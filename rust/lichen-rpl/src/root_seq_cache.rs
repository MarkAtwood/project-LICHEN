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
//! [`RootSeqCache::accept`] MUST only be called for a DIO whose root signature has
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
#[derive(Clone, Debug, Default)]
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

// ── Durable persistence (std) ────────────────────────────────────────────────
//
// RSQ1 is a provisional, unshipped format with no migration. Each entry
// carries its own `(dodag_id, instance)` key, so the record binds no node
// scope: the high-water marks describe the ROOT's sequence, which is valid
// anti-replay state for any local identity on any later provisioning. Slot
// integrity is the bare CRC-32 of `lichen_hal::storage` — corruption
// detection, not tamper resistance (see `crate::persistence` docs).

#[cfg(feature = "std")]
use lichen_hal::{
    storage::{
        open_redundant, provision_redundant, update_redundant, RedundantOpenError,
        RedundantProvisionError, RedundantUpdateError, RedundantValue,
    },
    NonVolatile,
};

#[cfg(feature = "std")]
pub(crate) const ROOT_SEQ_KEYS: [&str; 2] = ["rpl.rseq.a", "rpl.rseq.b"];
#[cfg(feature = "std")]
pub(crate) const ROOT_SEQ_MAGIC: [u8; 4] = *b"RSQ1";
#[cfg(feature = "std")]
const ROOT_SEQ_ENTRY_LEN: usize = 16 + 1 + 8;
#[cfg(feature = "std")]
const ROOT_SEQ_PAYLOAD_LEN: usize = 1 + MAX_ROOT_SEQ_KEYS * ROOT_SEQ_ENTRY_LEN;
#[cfg(feature = "std")]
const ROOT_SEQ_RECORD_LEN: usize = ROOT_SEQ_PAYLOAD_LEN + crate::persistence::SLOT_OVERHEAD;

/// Failure to resume durable root-seq state.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootSeqOpenError<E> {
    /// No record was ever persisted.
    Missing,
    /// Present but unparsable: fail closed, never silently reset (a wiped
    /// high-water mark would reopen the replay window).
    Corrupt,
    /// I/O failure.
    Storage(E),
}

#[cfg(feature = "std")]
impl RootSeqCache {
    /// Open the durable high-water state.
    pub fn open<S: NonVolatile>(
        storage: &S,
    ) -> Result<(Self, RedundantValue), RootSeqOpenError<S::Error>> {
        let mut slot_a = [0u8; ROOT_SEQ_RECORD_LEN];
        let mut slot_b = [0u8; ROOT_SEQ_RECORD_LEN];
        let mut payload = [0u8; ROOT_SEQ_PAYLOAD_LEN];
        let current = open_redundant(
            storage,
            ROOT_SEQ_KEYS,
            ROOT_SEQ_MAGIC,
            &mut slot_a,
            &mut slot_b,
            &mut payload,
        )
        .map_err(|error| match error {
            RedundantOpenError::Missing => RootSeqOpenError::Missing,
            RedundantOpenError::Corrupt | RedundantOpenError::BufferTooSmall => {
                RootSeqOpenError::Corrupt
            }
            RedundantOpenError::Storage(error) => RootSeqOpenError::Storage(error),
        })?;
        let cache = Self::decode(&payload[..current.len]).ok_or(RootSeqOpenError::Corrupt)?;
        Ok((cache, current))
    }

    /// Open the durable state, provisioning an empty record when absent.
    ///
    /// Covers fresh provisioning, reboot resume, and upgrade from a build
    /// that predates the record. Corrupt state fails closed.
    pub fn resume<S: NonVolatile>(
        storage: &mut S,
    ) -> Result<(Self, RedundantValue), RootSeqOpenError<S::Error>> {
        match Self::open(storage) {
            Ok(state) => Ok(state),
            Err(RootSeqOpenError::Missing) => {
                let (payload, len) = Self::default().encode();
                let mut record = [0u8; ROOT_SEQ_RECORD_LEN];
                provision_redundant(
                    storage,
                    ROOT_SEQ_KEYS,
                    ROOT_SEQ_MAGIC,
                    &payload[..len],
                    &mut record,
                )
                .map_err(|error| match error {
                    RedundantProvisionError::Exists => RootSeqOpenError::Corrupt,
                    RedundantProvisionError::Storage(error) => RootSeqOpenError::Storage(error),
                })?;
                Self::open(storage)
            }
            Err(error) => Err(error),
        }
    }

    /// Persist the cache as the next redundant generation.
    pub fn persist<S: NonVolatile>(
        &self,
        storage: &mut S,
        current: RedundantValue,
    ) -> Result<RedundantValue, RedundantUpdateError<S::Error>> {
        let (payload, len) = self.encode();
        let mut record = [0u8; ROOT_SEQ_RECORD_LEN];
        update_redundant(
            storage,
            ROOT_SEQ_KEYS,
            ROOT_SEQ_MAGIC,
            current,
            &payload[..len],
            &mut record,
        )
    }

    fn encode(&self) -> ([u8; ROOT_SEQ_PAYLOAD_LEN], usize) {
        let mut out = [0u8; ROOT_SEQ_PAYLOAD_LEN];
        let count = self.entries.iter().flatten().count();
        out[0] = count as u8;
        let mut offset = 1;
        for (dodag_id, instance, root_seq) in self.entries.iter().flatten() {
            out[offset..offset + 16].copy_from_slice(dodag_id);
            out[offset + 16] = *instance;
            out[offset + 17..offset + ROOT_SEQ_ENTRY_LEN].copy_from_slice(&root_seq.to_be_bytes());
            offset += ROOT_SEQ_ENTRY_LEN;
        }
        (out, offset)
    }

    /// Strict decode: exact length, bounded count, nonzero sequences, no
    /// duplicate keys — any deviation is corrupt, never partially accepted.
    fn decode(payload: &[u8]) -> Option<Self> {
        let count = usize::from(*payload.first()?);
        if count > MAX_ROOT_SEQ_KEYS || payload.len() != 1 + count * ROOT_SEQ_ENTRY_LEN {
            return None;
        }
        let mut cache = Self::default();
        for index in 0..count {
            let offset = 1 + index * ROOT_SEQ_ENTRY_LEN;
            let dodag_id: [u8; 16] = payload[offset..offset + 16].try_into().ok()?;
            let instance = payload[offset + 16];
            let root_seq = u64::from_be_bytes(
                payload[offset + 17..offset + ROOT_SEQ_ENTRY_LEN]
                    .try_into()
                    .ok()?,
            );
            if root_seq == 0 || cache.cached(dodag_id, instance).is_some() {
                return None;
            }
            cache.entries[index] = Some((dodag_id, instance, root_seq));
        }
        Some(cache)
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

#[cfg(all(test, feature = "std"))]
mod persistence_tests {
    use super::*;
    use lichen_hal::storage::mem::{MemStorage, MemStorageError};
    use lichen_hal::storage::{provision_redundant, RedundantUpdateError};

    const DODAG_A: [u8; 16] = [0x20; 16];
    const DODAG_B: [u8; 16] = [0x21; 16];

    #[test]
    fn resume_provisions_empty_record_then_roundtrips_across_reopen() {
        let mut storage = MemStorage::new();
        let (cache, current) = RootSeqCache::resume(&mut storage).unwrap();
        assert_eq!(cache.cached(DODAG_A, 0), None);

        // Accept + persist, then "reboot": a fresh resume on the same
        // storage restores the high-water marks.
        let mut cache = cache;
        cache.accept(DODAG_A, 0, 7).unwrap();
        cache.accept(DODAG_B, 1, 9).unwrap();
        let _current = cache.persist(&mut storage, current).unwrap();

        let (restored, current) = RootSeqCache::resume(&mut storage).unwrap();
        assert_eq!(restored.cached(DODAG_A, 0), Some(7));
        assert_eq!(restored.cached(DODAG_B, 1), Some(9));

        // A second persist advances the generation and both slots parse.
        let mut restored = restored;
        restored.accept(DODAG_A, 0, 8).unwrap();
        let current = restored.persist(&mut storage, current).unwrap();
        let (final_cache, _) = RootSeqCache::resume(&mut storage).unwrap();
        assert_eq!(final_cache.cached(DODAG_A, 0), Some(8));
        assert_eq!(final_cache.cached(DODAG_B, 1), Some(9));
        assert!(current.generation >= 3);
    }

    #[test]
    fn open_reports_missing_then_resume_fills_it() {
        let storage = MemStorage::new();
        assert_eq!(
            RootSeqCache::open(&storage).unwrap_err(),
            RootSeqOpenError::<MemStorageError>::Missing
        );
    }

    #[test]
    fn corrupt_both_slots_fail_closed() {
        let mut storage = MemStorage::new();
        storage.set_raw(ROOT_SEQ_KEYS[0], &[0xff; 64]);
        storage.set_raw(ROOT_SEQ_KEYS[1], &[0x00; 10]);
        assert_eq!(
            RootSeqCache::resume(&mut storage).unwrap_err(),
            RootSeqOpenError::<MemStorageError>::Corrupt
        );
    }

    #[test]
    fn wrong_magic_fails_closed() {
        // DTX2-framed bytes under the root-seq keys must never open.
        let mut storage = MemStorage::new();
        let mut record = [0u8; ROOT_SEQ_RECORD_LEN];
        provision_redundant(&mut storage, ROOT_SEQ_KEYS, *b"DTX2", &[0], &mut record).unwrap();
        assert_eq!(
            RootSeqCache::resume(&mut storage).unwrap_err(),
            RootSeqOpenError::<MemStorageError>::Corrupt
        );
    }

    #[test]
    fn malformed_payloads_fail_closed() {
        // Trailing garbage after a valid empty record.
        assert!(RootSeqCache::decode(&[0, 0xAA]).is_none());
        // Count beyond capacity.
        assert!(RootSeqCache::decode(&[17]).is_none());
        // Count/length mismatch.
        assert!(RootSeqCache::decode(&[1, 0xAA]).is_none());
        // Zero sequence is never valid state.
        let mut zero_seq = std::vec![1u8];
        zero_seq.extend_from_slice(&DODAG_A);
        zero_seq.push(0);
        zero_seq.extend_from_slice(&0u64.to_be_bytes());
        assert!(RootSeqCache::decode(&zero_seq).is_none());
        // Duplicate (dodag_id, instance) keys.
        let mut duplicate = std::vec![2u8];
        for _ in 0..2 {
            duplicate.extend_from_slice(&DODAG_A);
            duplicate.push(0);
            duplicate.extend_from_slice(&7u64.to_be_bytes());
        }
        assert!(RootSeqCache::decode(&duplicate).is_none());
        // A valid empty record decodes.
        assert!(RootSeqCache::decode(&[0]).is_some());
    }

    #[test]
    fn stale_handle_is_rejected() {
        let mut storage = MemStorage::new();
        let (mut cache, current) = RootSeqCache::resume(&mut storage).unwrap();
        cache.accept(DODAG_A, 0, 7).unwrap();
        let stale = current;
        let current = cache.persist(&mut storage, current).unwrap();
        // Replaying the superseded handle must not roll back the slot state.
        assert_eq!(
            cache.persist(&mut storage, stale).unwrap_err(),
            RedundantUpdateError::Stale
        );
        // The current handle still advances.
        cache.accept(DODAG_A, 0, 8).unwrap();
        cache.persist(&mut storage, current).unwrap();
        let (restored, _) = RootSeqCache::resume(&mut storage).unwrap();
        assert_eq!(restored.cached(DODAG_A, 0), Some(8));
    }
}
