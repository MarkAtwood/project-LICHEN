// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Production ownership and dispatch for the std RPL stack.

mod error;
mod provisioning;
mod receive;
mod root_sig;
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
    /// Without a wall clock, root-signature expiry cannot be evaluated; the
    /// receiver then treats every well-formed signature as unexpired (a
    /// documented limitation — spec 06 §8.10.1 "expired -> treat as unsigned"
    /// needs a real clock to distinguish).
    pub fn set_wall_clock_unix(&mut self, clock: fn() -> u64) {
        self.wall_clock_unix = Some(clock);
    }

    /// Receiver-side trust state: only record sequences from DIOs whose root
    /// signature has passed verification (see `RootSeqCache` caller contract).
    /// The root-signature receiver validation consumes this at the DIO path.
    /// Interim `dead_code` expectation: the receiver call site lands with the
    /// root-signature validation bead (b7z9.37.1); the expectation then stops
    /// being fulfilled and must be removed.
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
            return Some(RoutePlan {
                next_hop: util::ipv6_eui64(destination),
                source_route: Vec::new(),
            });
        }
        if self.rpl.router.is_root() {
            if let Some(path) = self.rpl.router.lookup_route_at(&destination, now_ms) {
                let source_route = path.to_vec();
                if source_route.last() != Some(&destination) {
                    return None;
                }
                return source_route.first().copied().map(|first| RoutePlan {
                    next_hop: util::ipv6_eui64(first),
                    source_route,
                });
            }
        }
        if let Some(entry) = self
            .announces
            .gradient_table_mut()
            .lookup(&destination, now_ms as u32)
        {
            return Some(RoutePlan {
                next_hop: util::ipv6_eui64(entry.next_hop),
                source_route: Vec::new(),
            });
        }
        if from_parent {
            return None;
        }
        self.rpl.preferred_parent().map(|parent| RoutePlan {
            next_hop: util::ipv6_eui64(parent),
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
