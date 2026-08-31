// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Anti-replay cache for root DIO signature sequence numbers.
//!
//! Spec 06-security §8.10.1: the receiver caches the highest accepted
//! `root_seq` keyed by `(dodag_id, instance)` and MUST reject any
//! candidate that does not strictly exceed it (L668, L687). A post-wrap
//! counter appears as a lower value, so strict increase also enforces the
//! MUST-NOT-WRAP rule without wrap arithmetic. Mirrors the Python oracle
//! `lichen.timing.dao.is_valid_dao_sequence` / crypto
//! `verify_root_dio_signature(cached_root_seq=...)`.
//!
//! Storage is a fixed-capacity table (no allocation): a node participates
//! in a handful of `(dodag_id, instance)` pairs at most. A full table
//! rejects new keys fail closed; the cached high-water marks of known keys
//! remain intact.
//!
//! # Caller contract
//!
//! [`Self::accept`] MUST only be called for a DIO whose root signature has
//! already passed verification (`verify_root_dio_signature` semantics):
//! the sequence high-water mark is trust state, and admitting attacker-
//! claimed `(dodag_id, instance)` keys before verification would let an
//! unauthenticated peer pin the table. With that contract honored, a full
//! table degrades to "cannot learn new DODAGs" — never to replay.

/// Maximum tracked `(dodag_id, instance)` keys.
pub const MAX_ROOT_SEQ_KEYS: usize = 16;

/// Reject reason for a `root_seq` that failed the strictly-increasing rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSeqReject {
    /// Equal to the cached value: replay of the last accepted DIO.
    Replay,
    /// Lower than the cached value: stale replay or post-wrap counter.
    Regression,
    /// Table full and the key is not yet tracked: fail closed rather than
    /// evict a live high-water mark.
    Capacity,
}

/// Highest accepted `root_seq` per `(dodag_id, instance)`.
#[derive(Debug, Default)]
pub struct RootSeqCache {
    entries: [Option<([u8; 16], u8, u64)>; MAX_ROOT_SEQ_KEYS],
}

impl RootSeqCache {
    /// Accept `root_seq` for `(dodag_id, instance)` iff it strictly exceeds
    /// the cached value; first observations are accepted while the table has
    /// room.
    ///
    /// On rejection the cache is left untouched (fail closed, auditable via
    /// the returned reason). Only call after the DIO's root signature has
    /// been verified — see the module-level caller contract.
    pub fn accept(
        &mut self,
        dodag_id: [u8; 16],
        instance: u8,
        root_seq: u64,
    ) -> Result<(), RootSeqReject> {
        let existing = self.entries.iter_mut().find_map(|slot| match slot {
            Some((id, inst, _)) if *id == dodag_id && *inst == instance => Some(slot),
            _ => None,
        });
        if let Some(slot) = existing {
            let Some((_, _, cached)) = *slot else {
                unreachable!("matched key slot always holds a value");
            };
            if root_seq <= cached {
                return Err(if root_seq == cached {
                    RootSeqReject::Replay
                } else {
                    RootSeqReject::Regression
                });
            }
            *slot = Some((dodag_id, instance, root_seq));
            return Ok(());
        }
        let free = self.entries.iter_mut().find(|e| e.is_none());
        let Some(slot) = free else {
            return Err(RootSeqReject::Capacity);
        };
        slot.replace((dodag_id, instance, root_seq));
        Ok(())
    }

    /// Cached highest accepted `root_seq` for the key, if observed.
    #[must_use]
    pub fn cached(&self, dodag_id: [u8; 16], instance: u8) -> Option<u64> {
        self.entries
            .iter()
            .flatten()
            .find_map(|(id, inst, seq)| (id == &dodag_id && inst == &instance).then_some(*seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DODAG_A: [u8; 16] = [0x20; 16];
    const DODAG_B: [u8; 16] = [0x21; 16];

    #[test]
    fn first_observation_is_accepted_and_cached() {
        let mut cache = RootSeqCache::default();
        assert_eq!(cache.cached(DODAG_A, 0), None);
        assert_eq!(cache.accept(DODAG_A, 0, 7), Ok(()));
        assert_eq!(cache.cached(DODAG_A, 0), Some(7));
    }

    #[test]
    fn equal_seq_is_replay() {
        let mut cache = RootSeqCache::default();
        cache.accept(DODAG_A, 0, 7).unwrap();
        assert_eq!(cache.accept(DODAG_A, 0, 7), Err(RootSeqReject::Replay));
        assert_eq!(cache.cached(DODAG_A, 0), Some(7));
    }

    #[test]
    fn lower_seq_is_regression() {
        let mut cache = RootSeqCache::default();
        cache.accept(DODAG_A, 0, 9).unwrap();
        assert_eq!(cache.accept(DODAG_A, 0, 8), Err(RootSeqReject::Regression));
        assert_eq!(cache.cached(DODAG_A, 0), Some(9));
    }

    #[test]
    fn post_wrap_counter_is_rejected_not_wrapped() {
        // A u64 counter that wrapped past u64::MAX reappears as a low value;
        // the MUST-NOT-WRAP rule rejects it instead of accepting the jump.
        let mut cache = RootSeqCache::default();
        cache.accept(DODAG_A, 0, u64::MAX).unwrap();
        assert_eq!(cache.accept(DODAG_A, 0, 1), Err(RootSeqReject::Regression));
        assert_eq!(cache.cached(DODAG_A, 0), Some(u64::MAX));
    }

    #[test]
    fn keys_are_isolated_by_dodag_and_instance() {
        let mut cache = RootSeqCache::default();
        cache.accept(DODAG_A, 0, 5).unwrap();
        // Same seq under a different DODAG or instance is a first observation.
        assert_eq!(cache.accept(DODAG_B, 0, 5), Ok(()));
        assert_eq!(cache.accept(DODAG_A, 1, 5), Ok(()));
        // ...and each key tracks its own high-water mark.
        assert_eq!(cache.accept(DODAG_B, 0, 6), Ok(()));
        assert_eq!(cache.accept(DODAG_A, 0, 6), Ok(()));
        assert_eq!(cache.cached(DODAG_A, 1), Some(5));
        assert_eq!(cache.cached(DODAG_B, 0), Some(6));
    }

    #[test]
    fn rejection_leaves_cache_untouched() {
        let mut cache = RootSeqCache::default();
        cache.accept(DODAG_A, 0, 9).unwrap();
        let _ = cache.accept(DODAG_A, 0, 9);
        let _ = cache.accept(DODAG_A, 0, 3);
        assert_eq!(cache.cached(DODAG_A, 0), Some(9));
        assert_eq!(cache.accept(DODAG_A, 0, 10), Ok(()));
    }

    #[test]
    fn full_table_fails_closed_without_eviction() {
        let mut cache = RootSeqCache::default();
        for i in 0..MAX_ROOT_SEQ_KEYS as u8 {
            let mut dodag = DODAG_A;
            dodag[0] = i;
            cache.accept(dodag, 0, 1).unwrap();
        }
        let mut dodag = DODAG_A;
        dodag[0] = 0xFF;
        assert_eq!(cache.accept(dodag, 0, 1), Err(RootSeqReject::Capacity));
        // Known keys keep working at capacity.
        let mut dodag = DODAG_A;
        dodag[0] = 0;
        assert_eq!(cache.accept(dodag, 0, 2), Ok(()));
        assert_eq!(cache.cached(dodag, 0), Some(2));
    }
}
