// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Production ownership and dispatch for the std RPL stack.

// Dead until b7z9.16 wires the DAO TX scheduler (spec 09 14.2).
#[allow(dead_code)]
mod dao_tx_timing;
mod error;
mod provisioning;
mod receive;
pub(crate) mod root_sig;
mod runtime;
mod secure;
mod transmit;
pub(crate) mod util;

#[cfg(test)]
mod tests;

use std::collections::{HashSet, VecDeque};
use std::vec::Vec;

use lichen_hal::{NonVolatile, Radio};
use lichen_link::identity::PeerIdentity;
use lichen_link::link_layer::PeerAuthState;
use lichen_rpl::root_seq_cache::RootSeqCache;

mod dao_tx_sched;
use dao_tx_sched::{DaoTxAdvance, DaoTxPhase, DaoTxScheduler};
use lichen_rpl::routing::{DaoAdmissionState, DaoTxState};

use crate::announce::AnnounceProcessor;
use crate::node::{DaoHandlingOutcome, RplEvent, RplNode};
use crate::routing::DaoRxState;
use crate::routing::RplMaintenanceOutcome;
use crate::secure::SecureStack;
use crate::stack::ReceivedIpv6;

pub use self::error::{
    DaoAdmissionError, DaoSendError, RplControlError, RplReceiveError, RplRuntimeReceiveError,
    RplRuntimeTrickleError, RplStackOpenError, RplStackProvisionError,
};
pub use self::util::{survey_routing_headers, RoutingHeaderSurvey, SourceRouteView};

/// Outcome of Trickle transmit completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RplTrickleTransmitOutcome {
    Sent,
    Suppressed,
}

/// Result of one receive cycle in the runtime-integrated loop.
#[derive(Debug)]
pub struct RplRuntimeReceiveOutcome {
    pub now_ms: u64,
    pub maintenance: Option<RplMaintenanceOutcome>,
    pub received: Option<RplReceiveOutcome>,
    pub generation: u64,
}

/// Result of one authenticated packet processed by the production owner.
#[derive(Debug)]
pub enum RplReceiveOutcome {
    /// Authenticated IPv6 addressed to this node. CoAP candidates have already
    /// passed fail-closed OSCORE framing validation and can be classified with
    /// [`RplStack::secure_datagram`].
    DeliveredIpv6(ReceivedIpv6),
    AnnouncementAccepted {
        peer: PeerIdentity,
        should_relay: bool,
        relayed: bool,
    },
    AnnouncementRejected(crate::announce::AnnounceRejectReason),
    Rpl(RplEvent),
    RplRejected,
    Dao(DaoHandlingOutcome),
    DaoOriginNotAdmitted,
    Forwarded {
        /// Link-local IPv6 address corresponding to the selected L2 next hop.
        next_hop: [u8; 16],
    },
}

/// Result of admitting a frame at a border-router transport boundary.
///
/// Values of this type are produced only after the complete link signature,
/// signer-identity, destination, and replay checks have succeeded.  The
/// border router may forward an admitted non-RPL IPv6 packet upstream; RPL
/// control never escapes as an untyped byte slice and is processed by this
/// stack while the authenticated link-frame capability is still available.
#[derive(Debug)]
pub enum RplBorderIngressOutcome {
    Ipv6(ReceivedIpv6),
    Control(RplReceiveOutcome),
}

enum RplRole {
    Leaf(DaoTxState),
    Root(DaoRxState),
}

pub(crate) struct RoutePlan {
    next_hop: [u8; 8],
    source_route: Vec<[u8; 16]>,
}

/// Single production owner for RPL routing, authenticated links, and OSCORE CoAP.
///
/// Construct a public [`SecureStack`] first and move it into one of the leaf or
/// root constructors. This prevents competing radio receive loops and keeps the
/// plaintext base stack inaccessible to downstream code.
pub struct RplStack<R: Radio, S: NonVolatile> {
    stack: SecureStack<R>,
    pub(crate) rpl: RplNode,
    announces: AnnounceProcessor,
    storage: S,
    role: RplRole,
    local_rpl_addr: [u8; 16],
    local_control_addr: [u8; 16],
    bootstrap_peers: VecDeque<[u8; 8]>,
    dao_admissions: Option<DaoAdmissionState>,
    root_seqs: RootSeqCache,
    /// Durable generation handle for `root_seqs` (spec 06 §8.10.1 anti-replay
    /// survives reboot; worker6-eebl). Every admitted high-water mark is
    /// persisted BEFORE the in-memory cache is updated.
    root_seq_store: lichen_hal::storage::RedundantValue,
    /// DAO TX scheduler state (b7z9.16.1(b) wires the TX consumer).
    dao_tx_sched: DaoTxScheduler,
    wall_clock_unix: Option<fn() -> u64>,
    routing_now_ms: u64,
    generation: u64,
    direct_neighbors: HashSet<[u8; 8]>,
}

impl<R: Radio, S: NonVolatile> RplStack<R, S> {
    /// Install a link peer already authenticated by an external durable trust
    /// owner (for example, a gateway federation proof-of-possession exchange).
    pub fn install_verified_link_peer(&mut self, peer: PeerIdentity) {
        self.stack.add_peer(peer);
    }

    /// This node's key-derived IID (SHA-512 derivation; link-local identity).
    ///
    /// Distinct from the low half of the routable address: upstream
    /// `AddrForKey` bit-packs the inverted key and does not embed the IID
    /// (i72x.2).
    pub fn local_iid(&self) -> [u8; 8] {
        lichen_link::identity::iid_from_pubkey(&self.stack.local_public_key())
    }

    pub fn rpl_node(&self) -> &RplNode {
        &self.rpl
    }

    /// Update the root DIO Grounded bit from the owned upstream runtime state.
    #[must_use]
    pub fn set_ygg_reachable(&mut self, reachable: bool) -> bool {
        self.rpl.set_ygg_reachable(reachable)
    }

    #[cfg(feature = "raw-rpl-test-api")]
    pub fn rpl_node_mut(&mut self) -> &mut RplNode {
        &mut self.rpl
    }

    /// Current generation of this stack instance. RplRuntime bindings are tied to
    /// this value; reprovision or reset increments it to invalidate stale runtimes.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Install a Unix-seconds wall clock for root-signature expiry checks.
    ///
    /// Receiver side: without a clock the expiry check is unassessable; an
    /// otherwise-valid signed DIO degrades to `DioRootSigOutcome::Baseline`
    /// (treat as unsigned) exactly as it does for an elapsed expiry — spec
    /// 06 §8.10.1 "expired -> treat as unsigned" applied to the unassessable
    /// case, never to trusting the signature (forged or tampered signatures
    /// still reject; see `verify_dio_root_signature`).
    ///
    /// Root producer side (feature `root-sig`): this clock also sets the
    /// expiry on transmitted root signatures; without it, root DIOs are
    /// sent unsigned (see `send_dio`).
    pub fn set_wall_clock_unix(&mut self, clock: fn() -> u64) {
        self.wall_clock_unix = Some(clock);
    }

    /// Receiver-side trust state: only record sequences from DIOs whose root
    /// signature has passed verification (see `RootSeqCache` caller contract).
    /// The root-signature receiver validation consumes this at the DIO path.
    /// Interim `dead_code` expectation: the receiver call site lands with the
    /// root-signature validation bead (b7z9.37.1); the expectation then stops
    /// being fulfilled and must be removed.
    #[allow(
        dead_code,
        reason = "root-signature receiver call site lands in b7z9.37.1"
    )]
    pub(crate) fn root_seqs_mut(&mut self) -> &mut RootSeqCache {
        &mut self.root_seqs
    }

    /// Advance the DAO TX scheduler and detect the join transition
    /// (spec 09 14.2). On the first advance with the node joined and the
    /// scheduler idle, the initial DAO is scheduled 0-2 s out (R-09-017).
    /// Returns the scheduler outcome for the TX path.
    pub(crate) fn dao_tx_advance(&mut self, now_ms: u64) -> DaoTxAdvance {
        let joined = self.rpl.router.is_joined();
        if !joined {
            self.dao_tx_sched = DaoTxScheduler::new();
            return DaoTxAdvance::Idle;
        }
        if matches!(self.dao_tx_sched.phase(), DaoTxPhase::Idle) {
            // Join transition: schedule the initial DAO with a hash-free
            // 0-2 s offset derived from the current time slice (the node
            // has no RNG; the low bits of now_ms vary across nodes).
            let random_word = (now_ms as u32) ^ u32::from(self.rpl.router.dodag_id()[15]);
            self.dao_tx_sched.schedule_initial(now_ms, random_word);
        }
        self.dao_tx_sched.advance(now_ms)
    }

    /// Cached highest accepted `root_seq` for the key, if observed.
    #[must_use]
    pub fn root_seq_cached(&self, dodag_id: [u8; 16], instance: u8) -> Option<u64> {
        self.root_seqs.cached(dodag_id, instance)
    }

    pub(crate) fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn announces(&self) -> &AnnounceProcessor {
        &self.announces
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Get the local link-layer IID (SHA-512 of the local public key).
    ///
    /// Same identity plane as peer IIDs derived via `iid_from_pubkey_bytes`;
    /// use this wherever the node's own IID is compared against peer IIDs.
    pub fn local_iid(&self) -> [u8; 8] {
        self.stack.local_iid()
    }

    pub(crate) fn route_for(
        &mut self,
        destination: [u8; 16],
        now_ms: u64,
        from_parent: bool,
    ) -> Option<RoutePlan> {
        let now_ms = self.routing_now_ms.max(now_ms);
        self.routing_now_ms = now_ms;
        if destination[0] == 0xfe && destination[1] & 0xc0 == 0x80 {
            let iid: [u8; 8] = destination[8..].try_into().unwrap();
            let state = self.stack.link().peer_auth_state(&iid);
            if state == PeerAuthState::Unknown
                || (state == PeerAuthState::Authenticated && !self.direct_neighbors.contains(&iid))
            {
                return None;
            }
            return util::l2_destination(destination, self.stack.link_ref()).map(|next_hop| {
                RoutePlan {
                    next_hop,
                    source_route: Vec::new(),
                }
            });
        }
        if self.rpl.router.is_root() {
            if let Some(path) = self
                .rpl
                .router
                .lookup_route_at(core::net::Ipv6Addr::from(destination), now_ms)
            {
                let source_route: Vec<[u8; 16]> =
                    path.iter().map(core::net::Ipv6Addr::octets).collect();
                if source_route.last() != Some(&destination) {
                    return None;
                }
                // The first hop is a routable /128; its L2 EUI-64 is not
                // derivable from the address (i72x.2) — resolve through the
                // authenticated peer table, failing closed (no route).
                let first = *source_route.first()?;
                let mut next_hop = self.stack.link().peer_iid_for_routable_addr(&first)?;
                next_hop[0] ^= 0x02;
                return Some(RoutePlan {
                    next_hop,
                    source_route,
                // The first hop is this node's direct neighbor, but post-AddrForKey
                // it is a routable 02xx address with no embedded IID, so the L2
                // destination resolves through the authenticated peer table.
                return source_route.first().copied().and_then(|first| {
                    Some(RoutePlan {
                        next_hop: util::l2_destination(first, self.stack.link_ref())?,
                        source_route,
                    })
                });
            }
        }
        if let Some(entry) = self
            .announces
            .gradient_table_mut()
            .lookup(&destination, now_ms as u32)
        {
            return util::l2_destination(entry.next_hop, self.stack.link_ref()).map(|next_hop| {
                RoutePlan {
                    next_hop,
                    source_route: Vec::new(),
                }
            });
        }
        if from_parent {
            return None;
        }
        self.rpl
            .preferred_parent()
            .and_then(|parent| util::l2_destination(parent, self.stack.link_ref()))
            .map(|next_hop| RoutePlan {
                next_hop,
                source_route: Vec::new(),
            })
    }
}

#[cfg(test)]
impl<R: Radio> RplStack<R, lichen_hal::storage::mem::MemStorage> {
    fn fail_next_storage_write(&mut self) {
        self.storage.fail_next_write();
    }
}
