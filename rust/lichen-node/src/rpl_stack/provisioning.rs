// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Stack provisioning and constructor methods.

use std::collections::HashSet;
use std::collections::VecDeque;

use crate::rpl_stack::dao_tx_sched::DaoTxScheduler;
use lichen_hal::storage::open_redundant;
use lichen_hal::storage::provision_redundant;
use lichen_hal::storage::update_redundant;
use lichen_hal::storage::RedundantOpenError;
use lichen_hal::storage::RedundantValue;
use lichen_hal::NonVolatile;
use lichen_hal::Radio;
use lichen_link::identity::iid_from_pubkey;
use lichen_rpl::root_seq_cache::RootSeqCache;
use lichen_rpl::root_seq_cache::ROOT_SEQ_WIRE_LEN;
use lichen_rpl::routing::DaoAdmissionState;
use lichen_rpl::routing::DaoAdmissionUpdateError;
use lichen_rpl::routing::DaoPersistentOpenError;
use lichen_rpl::routing::DaoProvisionError;
use lichen_rpl::routing::DaoTxState;

use crate::announce::AnnounceProcessor;
use crate::node::Node;
use crate::node::RplNode;
use crate::routing::DaoRxState;
use crate::routing::Router;
use crate::secure::SecureStack;

use super::error::DaoAdmissionError;
use super::error::RplStackOpenError;
use super::error::RplStackProvisionError;
use super::RplRole;
use super::RplStack;

/// Durable keys and format tag for the root-seq anti-replay cache
/// (spec 06 §8.10.1). Provisional, unshipped scope-bound format; like the
/// DTX2/DRX2/DAD1 records there is intentionally no migration path.
pub(crate) const ROOT_SEQ_KEYS: [&str; 2] = ["rpl.rseq.a", "rpl.rseq.b"];
pub(crate) const ROOT_SEQ_MAGIC: [u8; 4] = *b"RSQ1";
/// Slot record scratch size: payload plus the redundant-slot header/trailer
/// (lichen_hal::storage SLOT_HEADER_LEN + SLOT_TRAILER_LEN).
pub(crate) const ROOT_SEQ_RECORD_LEN: usize = ROOT_SEQ_WIRE_LEN + 24;

/// Load the persisted root-seq high-water cache.
///
/// Missing state means a fresh node (empty cache, no slot handle). Any
/// present-but-unreadable or corrupt record fails closed by propagating the
/// error, mirroring the DAO RX open path: durable anti-replay state must
/// never be silently discarded. A record left by a previous provisioning of
/// the same storage still loads — its high-water marks are keyed by
/// `(dodag_id, instance)` and remain valid anti-replay state.
pub(crate) fn open_root_seq_state<S: NonVolatile>(
    storage: &S,
) -> Result<(RootSeqCache, Option<RedundantValue>), RedundantOpenError<S::Error>> {
    let mut slot_a = [0u8; ROOT_SEQ_RECORD_LEN];
    let mut slot_b = [0u8; ROOT_SEQ_RECORD_LEN];
    let mut payload = [0u8; ROOT_SEQ_WIRE_LEN];
    let current = match open_redundant(
        storage,
        ROOT_SEQ_KEYS,
        ROOT_SEQ_MAGIC,
        &mut slot_a,
        &mut slot_b,
        &mut payload,
    ) {
        Ok(current) => current,
        Err(RedundantOpenError::Missing) => return Ok((RootSeqCache::default(), None)),
        Err(error) => return Err(error),
    };
    let cache = RootSeqCache::decode(&payload[..current.len]).ok_or(RedundantOpenError::Corrupt)?;
    Ok((cache, Some(current)))
}

impl<R: Radio, S: NonVolatile> RplStack<R, S> {
    /// Persist a staged root-seq cache, then commit it in memory.
    ///
    /// Ordering mirrors the DAO RX path (`update_redundant` before `*self =
    /// proposed`): the durable record advances BEFORE the in-memory cache,
    /// so a failed write leaves both unchanged and the caller can degrade
    /// without having extended trusted replay state. `Ok(())` guarantees the
    /// staged cache is both durable and live; `Err(())` guarantees neither
    /// advanced.
    pub(crate) fn commit_root_seqs(&mut self, staged: RootSeqCache) -> Result<(), ()> {
        let mut payload = [0u8; ROOT_SEQ_WIRE_LEN];
        let len = staged.encode(&mut payload).ok_or(())?;
        let mut record = [0u8; ROOT_SEQ_RECORD_LEN];
        let next = match self.root_seq_store {
            Some(current) => update_redundant(
                &mut self.storage,
                ROOT_SEQ_KEYS,
                ROOT_SEQ_MAGIC,
                current,
                &payload[..len],
                &mut record,
            )
            .map_err(|_| ())?,
            None => {
                provision_redundant(
                    &mut self.storage,
                    ROOT_SEQ_KEYS,
                    ROOT_SEQ_MAGIC,
                    &payload[..len],
                    &mut record,
                )
                .map_err(|_| ())?;
                RedundantValue {
                    generation: 1,
                    slot: 0,
                    len,
                }
            }
        };
        self.root_seq_store = Some(next);
        self.root_seqs = staged;
        Ok(())
    }

    pub fn provision_leaf<T: Into<SecureStack<R>>>(
        stack: T,
        local_rpl_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        mut storage: S,
    ) -> Result<Self, RplStackProvisionError<S::Error>> {
        let stack = stack.into();
        validate_origin(&stack, local_rpl_addr)
            .map_err(|()| RplStackProvisionError::InvalidOrigin)?;
        let control_addr = canonical_link_local(&stack);
        let key = stack.local_public_key();
        let tx = DaoTxState::provision(
            &mut storage,
            key,
            local_rpl_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )
        .map_err(RplStackProvisionError::Dao)?;
        let (root_seqs, root_seq_store) =
            open_root_seq_state(&storage).map_err(RplStackProvisionError::RootSeq)?;
        let rpl = RplNode {
            node: Node::new(stack.node_id()),
            router: Router::new(local_rpl_addr, dodag_id),
        };
        Ok(Self {
            stack,
            rpl,
            announces,
            storage,
            role: RplRole::Leaf(tx),
            local_rpl_addr,
            local_control_addr: control_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: None,
            root_seqs,
            root_seq_store,
            dao_tx_sched: DaoTxScheduler::new(),
            wall_clock_unix: None,
            routing_now_ms: 0,
            generation: 1,
            direct_neighbors: HashSet::new(),
        })
    }

    pub fn open_leaf<T: Into<SecureStack<R>>>(
        stack: T,
        local_rpl_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        storage: S,
    ) -> Result<Self, RplStackOpenError<S::Error>> {
        let stack = stack.into();
        validate_origin(&stack, local_rpl_addr).map_err(|()| RplStackOpenError::InvalidOrigin)?;
        let control_addr = canonical_link_local(&stack);
        let key = stack.local_public_key();
        let tx = DaoTxState::open(
            &storage,
            key,
            local_rpl_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )
        .map_err(RplStackOpenError::Dao)?;
        let (root_seqs, root_seq_store) =
            open_root_seq_state(&storage).map_err(RplStackOpenError::RootSeq)?;
        let rpl = RplNode {
            node: Node::new(stack.node_id()),
            router: Router::new(local_rpl_addr, dodag_id),
        };
        Ok(Self {
            stack,
            rpl,
            announces,
            storage,
            role: RplRole::Leaf(tx),
            local_rpl_addr,
            local_control_addr: control_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: None,
            root_seqs,
            root_seq_store,
            dao_tx_sched: DaoTxScheduler::new(),
            wall_clock_unix: None,
            routing_now_ms: 0,
            generation: 1,
            direct_neighbors: HashSet::new(),
        })
    }

    pub fn provision_root<T: Into<SecureStack<R>>>(
        stack: T,
        root_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        mut storage: S,
    ) -> Result<Self, RplStackProvisionError<S::Error>> {
        let stack = stack.into();
        validate_origin(&stack, root_addr).map_err(|()| RplStackProvisionError::InvalidOrigin)?;
        let control_addr = canonical_link_local(&stack);
        if root_addr != dodag_id {
            return Err(RplStackProvisionError::RootAddressMismatch);
        }
        let (router, rx, admissions) = provision_or_resume_root_state(
            &mut storage,
            root_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )?;
        let (root_seqs, root_seq_store) =
            open_root_seq_state(&storage).map_err(RplStackProvisionError::RootSeq)?;
        Ok(Self {
            rpl: RplNode {
                node: Node::new(stack.node_id()),
                router,
            },
            stack,
            announces,
            storage,
            role: RplRole::Root(rx),
            local_rpl_addr: root_addr,
            local_control_addr: control_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: Some(admissions),
            root_seqs,
            root_seq_store,
            dao_tx_sched: DaoTxScheduler::new(),
            wall_clock_unix: None,
            routing_now_ms: 0,
            generation: 1,
            direct_neighbors: HashSet::new(),
        })
    }

    pub fn open_root<T: Into<SecureStack<R>>>(
        stack: T,
        root_addr: [u8; 16],
        dodag_id: [u8; 16],
        announces: AnnounceProcessor,
        storage: S,
    ) -> Result<Self, RplStackOpenError<S::Error>> {
        let stack = stack.into();
        validate_origin(&stack, root_addr).map_err(|()| RplStackOpenError::InvalidOrigin)?;
        let control_addr = canonical_link_local(&stack);
        if root_addr != dodag_id {
            return Err(RplStackOpenError::RootAddressMismatch);
        }
        let (router, rx) =
            Router::open_root(&storage, root_addr).map_err(RplStackOpenError::Dao)?;
        let admissions = DaoAdmissionState::open(
            &storage,
            root_addr,
            lichen_core::constants::RPL_INSTANCE_ID,
            dodag_id,
        )
        .map_err(RplStackOpenError::Admission)?;
        if router
            .dao_manager
            .origin_high_water()
            .iter()
            .any(|hw| !admissions.contains(&hw.public_key))
        {
            return Err(RplStackOpenError::AdmissionInconsistent);
        }
        let (root_seqs, root_seq_store) =
            open_root_seq_state(&storage).map_err(RplStackOpenError::RootSeq)?;
        Ok(Self {
            rpl: RplNode {
                node: Node::new(stack.node_id()),
                router,
            },
            stack,
            announces,
            storage,
            role: RplRole::Root(rx),
            local_rpl_addr: root_addr,
            local_control_addr: control_addr,
            bootstrap_peers: VecDeque::new(),
            dao_admissions: Some(admissions),
            root_seqs,
            root_seq_store,
            dao_tx_sched: DaoTxScheduler::new(),
            wall_clock_unix: None,
            routing_now_ms: 0,
            generation: 1,
            direct_neighbors: HashSet::new(),
        })
    }

    /// Admit the currently pinned Announce identity to create root DAO state.
    ///
    /// Admissions are bounded by durable replay capacity and cannot be retired
    /// through this API. Origins already represented in persisted high-water
    /// state are restored as admitted by [`Self::open_root`].
    pub fn admit_dao_origin(&mut self, iid: [u8; 8]) -> Result<(), DaoAdmissionError<S::Error>> {
        if !matches!(self.role, RplRole::Root(_)) {
            return Err(DaoAdmissionError::NotRoot);
        }
        let key = self
            .announces
            .pinned_pubkey_for(&iid)
            .ok_or(DaoAdmissionError::IdentityNotPinned)?;
        let admissions = self
            .dao_admissions
            .as_mut()
            .ok_or(DaoAdmissionError::NotRoot)?;
        admissions
            .admit(&mut self.storage, *key.as_bytes())
            .map_err(|error| match error {
                DaoAdmissionUpdateError::Persistence(error) => {
                    DaoAdmissionError::Persistence(error)
                }
                DaoAdmissionUpdateError::Stale => DaoAdmissionError::Stale,
                DaoAdmissionUpdateError::Exhausted => DaoAdmissionError::Exhausted,
                DaoAdmissionUpdateError::Corrupt => DaoAdmissionError::Corrupt,
                DaoAdmissionUpdateError::Capacity => DaoAdmissionError::Capacity,
            })
    }
}

pub(crate) fn validate_origin<R: Radio>(
    stack: &SecureStack<R>,
    origin: [u8; 16],
) -> Result<(), ()> {
    let expected = lichen_link::ygg_addr_from_pubkey(stack.local_public_key().as_bytes());
    (origin == expected).then_some(()).ok_or(())
}

fn canonical_link_local<R: Radio>(stack: &SecureStack<R>) -> [u8; 16] {
    let mut address = [0u8; 16];
    address[..8].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    address[8..].copy_from_slice(&iid_from_pubkey(&stack.local_public_key()));
    address
}

pub(crate) fn provision_or_resume_root_state<S: NonVolatile>(
    storage: &mut S,
    root_addr: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
) -> Result<(Router, DaoRxState, DaoAdmissionState), RplStackProvisionError<S::Error>> {
    let admissions = match DaoAdmissionState::open(storage, root_addr, rpl_instance_id, dodag_id) {
        Ok(state) => Some(state),
        Err(DaoPersistentOpenError::Missing) => None,
        Err(error) => {
            return Err(RplStackProvisionError::Admission(DaoProvisionError::Open(
                error,
            )))
        }
    };
    let replay = match Router::open_root(storage, root_addr) {
        Ok(state) => Some(state),
        Err(DaoPersistentOpenError::Missing) => None,
        Err(error) => return Err(RplStackProvisionError::Dao(DaoProvisionError::Open(error))),
    };

    if admissions.as_ref().is_some_and(|state| !state.is_empty())
        || replay
            .as_ref()
            .is_some_and(|(router, _)| !router.dao_manager.origin_high_water().is_empty())
    {
        return Err(RplStackProvisionError::ExistingNonEmpty);
    }

    let admissions = match admissions {
        Some(state) => state,
        None => DaoAdmissionState::provision(storage, root_addr, rpl_instance_id, dodag_id)
            .map_err(RplStackProvisionError::Admission)?,
    };
    let (router, rx) = match replay {
        Some(state) => state,
        None => Router::provision_root(storage, root_addr).map_err(RplStackProvisionError::Dao)?,
    };
    Ok((router, rx, admissions))
}
