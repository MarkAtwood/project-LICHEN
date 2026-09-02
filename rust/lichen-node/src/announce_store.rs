//! Durable, sealed trust state for Node Announce processing (std builds).
//!
//! Persists the exact TOFU key pin and per-origin Announce sequence floor so
//! both survive a Node restart. Mirrors the gateway's sealed sender-store
//! pattern ([`crate`] sibling `GatewayOscoreSenderStore`):
//!
//! - Each record is `pubkey(32) || seq(2)` plus a 48-byte Schnorr48 signature
//!   made with the node persistence key material over a transcript binding
//!   the record domain, the originator IID, and the state bytes.
//! - State and rollback floor live in separate storage roots. Every accept
//!   writes state first, then the floor, so a crash between the two writes
//!   leaves the floor lagging (healed forward on the next load) but never
//!   ahead (which fails closed). A non-crash floor-write failure evicts the
//!   cache entry for the IID, so the stale pre-accept state is neither
//!   served nor re-validated against while the floor lags.
//! - `load` fails closed when the state side is missing (trust is never
//!   rebuilt from a floor alone), when the state does not strictly advance
//!   its floor, or when a seal does not verify. Only `(None, None)`
//!   initializes fresh. A missing floor heals forward to the sealed state:
//!   the state record is unforgeable under the seal threat model, and a
//!   deleted floor cannot lower trust below it, so healing never weakens
//!   the pin or the sequence floor.
//! - `accept` refuses to replace an existing pin with a different pubkey
//!   (IID-collision trust replacement) or to lower/hold the sequence floor,
//!   including across cache eviction and restart. Eviction removes the
//!   in-memory cache entry only; durable floors are never deleted, so there
//!   is deliberately no removal API.
//!
//! Capacity policy: the [`AnnounceStoreError::Full`] gate for *new* pins
//! counts durable state records (recounted from the state directory at
//! open), never the volatile cache, so saturation cannot be reset by a
//! restart and an over-capacity legacy store cannot overflow further.
//! IIDs that already have a durable record are never capacity-gated. The
//! cache is an optimization: at capacity `load` returns the durable state
//! without caching it, and a new `accept` LRU-evicts the coldest cache
//! entry (durable records are unaffected).

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use lichen_hal::storage::fs::FileStorage;
#[cfg(feature = "std")]
use lichen_hal::NonVolatile;
#[cfg(feature = "std")]
use lichen_link::keys::Seed;
#[cfg(feature = "std")]
use lichen_link::schnorr::{derive_keypair, sign, verify, SIGNATURE_LENGTH};
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::format;
#[cfg(feature = "std")]
use std::path::Path;
#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use zeroize::Zeroizing;

#[cfg(feature = "std")]
use crate::announce::{seq_gt, MAX_TRACKED_ORIGINATORS};

/// Exact TOFU key pin plus the highest accepted origin Announce sequence.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceTrustState {
    pub pubkey: [u8; 32],
    pub seq: u16,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceStoreError {
    Io,
    Corrupt,
    Full,
}

#[cfg(feature = "std")]
const STATE_DOMAIN: &[u8] = b"LICHEN-NODE-ANNOUNCE-STATE-v1\0";
#[cfg(feature = "std")]
const FLOOR_DOMAIN: &[u8] = b"LICHEN-NODE-ANNOUNCE-FLOOR-v1\0";

/// `pubkey(32) || seq(2)`.
#[cfg(feature = "std")]
const STATE_BYTES: usize = 34;
#[cfg(feature = "std")]
const RECORD_BYTES: usize = STATE_BYTES + SIGNATURE_LENGTH;

/// Durable, sealed pin/floor store for Node Announce trust state.
///
/// The `Debug` impl is hand-written because `Zeroizing`'s own `Debug` is a
/// derived, transparent print; a derived impl here would emit the sealing
/// seed on any `{:?}` of the store.
#[cfg(feature = "std")]
impl std::fmt::Debug for AnnounceTrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnnounceTrustStore")
            .field("records", &self.records)
            .field("clock", &self.clock)
            .field("durable_count", &self.durable_count)
            .field("storage", &self.storage)
            .field("floor_storage", &self.floor_storage)
            .field("sealing_seed", &self.sealing_seed.is_some())
            .finish()
    }
}

/// Cached durable state plus its LRU stamp (larger = more recently used).
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CacheEntry {
    state: AnnounceTrustState,
    last_use: u64,
}

#[cfg(feature = "std")]
pub struct AnnounceTrustStore {
    /// Volatile read/write cache of durable records. An optimization only:
    /// entries may be absent (capacity) or evicted (LRU) at any time without
    /// changing what is authoritative.
    records: HashMap<[u8; 8], CacheEntry>,
    /// Monotonic source of LRU stamps.
    clock: u64,
    /// Number of durable state records this store owns. Recounted from the
    /// state directory at open and incremented only when a new record is
    /// durably committed; never derived from the volatile cache.
    durable_count: usize,
    storage: Option<FileStorage>,
    floor_storage: Option<FileStorage>,
    sealing_seed: Option<Zeroizing<[u8; 32]>>,
}

#[cfg(feature = "std")]
impl AnnounceTrustStore {
    /// Cache-only store; nothing is persisted.
    ///
    /// WARNING (bead vwiq): an ephemeral store provides NO durable pin or
    /// replay-floor protection - after every restart all pins vanish and
    /// IID-collision attackers can re-pin at will. Production callers MUST
    /// use [`AnnounceTrustStore::persistent`]. This constructor exists only
    /// for tests and explicitly opt-in simulations.
    #[doc(hidden)]
    pub fn ephemeral_unprotected() -> Self {
        Self {
            records: HashMap::new(),
            clock: 0,
            durable_count: 0,
            storage: None,
            floor_storage: None,
            sealing_seed: None,
        }
    }

    /// True when this store is backed by durable storage. Only durable stores
    /// are authoritative for admission: an ephemeral store is a mirror of the
    /// processor's in-memory tables and is never consulted.
    pub fn is_persistent(&self) -> bool {
        self.storage.is_some()
    }

    /// Open durable stores under `state_root` and `floor_root` (separate
    /// roots so a rollback snapshot cannot silently rewind both sides).
    ///
    /// The number of durable state records already on disk is recounted at
    /// open so the new-pin capacity gate survives restarts (a cache-only
    /// count would reopen admission after every restart and let an
    /// over-capacity store overflow without bound).
    pub fn persistent(
        state_root: &Path,
        floor_root: &Path,
        sealing_seed: &[u8; 32],
    ) -> Result<Self, AnnounceStoreError> {
        let state_dir = state_root.join("announce-trust");
        let storage = FileStorage::new(&state_dir).map_err(|_| AnnounceStoreError::Io)?;
        let floor_storage = FileStorage::new(floor_root.join("announce-trust"))
            .map_err(|_| AnnounceStoreError::Io)?;
        let durable_count = count_durable_state_records(&state_dir)?;
        Ok(Self {
            records: HashMap::new(),
            clock: 0,
            durable_count,
            storage: Some(storage),
            floor_storage: Some(floor_storage),
            sealing_seed: Some(Zeroizing::new(*sealing_seed)),
        })
    }

    fn key(iid: &[u8; 8], floor: bool) -> String {
        let suffix = if floor { "-floor" } else { "" };
        format!("announce-pin-{}{}", hex_iid(iid), suffix)
    }

    fn encode(state: AnnounceTrustState) -> [u8; STATE_BYTES] {
        let mut encoded = [0u8; STATE_BYTES];
        encoded[..32].copy_from_slice(&state.pubkey);
        encoded[32..].copy_from_slice(&state.seq.to_be_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<AnnounceTrustState, AnnounceStoreError> {
        if encoded.len() != STATE_BYTES {
            return Err(AnnounceStoreError::Corrupt);
        }
        Ok(AnnounceTrustState {
            pubkey: encoded[..32].try_into().expect("checked state length"),
            seq: u16::from_be_bytes(encoded[32..].try_into().expect("checked state length")),
        })
    }

    fn transcript(domain: &[u8], iid: &[u8; 8], state: &[u8; STATE_BYTES]) -> Vec<u8> {
        let mut transcript = Vec::with_capacity(domain.len() + iid.len() + state.len());
        transcript.extend_from_slice(domain);
        transcript.extend_from_slice(iid);
        transcript.extend_from_slice(state);
        transcript
    }

    fn read(
        &self,
        iid: &[u8; 8],
        floor: bool,
    ) -> Result<Option<AnnounceTrustState>, AnnounceStoreError> {
        let storage = if floor {
            self.floor_storage.as_ref()
        } else {
            self.storage.as_ref()
        };
        let Some(storage) = storage else {
            return Ok(None);
        };
        let mut encoded = [0u8; RECORD_BYTES];
        let Some(length) = storage
            .read(&Self::key(iid, floor), &mut encoded)
            .map_err(|_| AnnounceStoreError::Io)?
        else {
            return Ok(None);
        };
        if length != RECORD_BYTES {
            return Err(AnnounceStoreError::Corrupt);
        }
        let state_bytes: &[u8; STATE_BYTES] = encoded[..STATE_BYTES]
            .try_into()
            .expect("fixed state prefix");
        let signature: &[u8; SIGNATURE_LENGTH] = encoded[STATE_BYTES..]
            .try_into()
            .expect("fixed sealed signature suffix");
        let seed = self.sealing_seed.as_deref().ok_or(AnnounceStoreError::Io)?;
        let (_, public) = derive_keypair(&Seed::new(*seed));
        let domain = if floor { FLOOR_DOMAIN } else { STATE_DOMAIN };
        if !verify(
            &public,
            &Self::transcript(domain, iid, state_bytes),
            signature,
        ) {
            return Err(AnnounceStoreError::Corrupt);
        }
        Ok(Some(Self::decode(state_bytes)?))
    }

    fn write(
        &mut self,
        iid: &[u8; 8],
        floor: bool,
        state: AnnounceTrustState,
    ) -> Result<(), AnnounceStoreError> {
        let state_bytes = Self::encode(state);
        let seed = self.sealing_seed.as_deref().ok_or(AnnounceStoreError::Io)?;
        let (private, public) = derive_keypair(&Seed::new(*seed));
        let domain = if floor { FLOOR_DOMAIN } else { STATE_DOMAIN };
        let signature = sign(
            &private,
            &public,
            &Self::transcript(domain, iid, &state_bytes),
        );
        let mut encoded = [0u8; RECORD_BYTES];
        encoded[..STATE_BYTES].copy_from_slice(&state_bytes);
        encoded[STATE_BYTES..].copy_from_slice(&signature);
        let storage = if floor {
            self.floor_storage.as_mut()
        } else {
            self.storage.as_mut()
        };
        storage
            .ok_or(AnnounceStoreError::Io)?
            .write(&Self::key(iid, floor), &encoded)
            .map_err(|_| AnnounceStoreError::Io)
    }

    /// True when `current` regresses relative to the durable `floor`.
    ///
    /// Pins never change under TOFU (a key change is rejected, not adopted),
    /// so any pubkey difference means one side was rolled back or tampered.
    /// Sequence comparison reuses the processor's RFC 1982 serial arithmetic.
    fn precedes(current: AnnounceTrustState, floor: AnnounceTrustState) -> bool {
        current.pubkey != floor.pubkey
            || (!seq_gt(current.seq, floor.seq) && current.seq != floor.seq)
    }

    /// Load the trust state for `iid`, rebuilding the cache from storage.
    ///
    /// Fails closed on a missing state record, a regressed state, or an
    /// unverifiable record. A missing floor record heals forward to the
    /// sealed state (first-accept crash window or lost floor file) so the
    /// originator is not permanently bricked.
    ///
    /// At cache capacity the resolved durable state is returned without
    /// being cached: the cache is an optimization and must never make a
    /// durably-pinned origin unusable ([`AnnounceStoreError::Full`] is a
    /// new-pin admission outcome, never a load outcome).
    pub fn load(
        &mut self,
        iid: &[u8; 8],
    ) -> Result<Option<AnnounceTrustState>, AnnounceStoreError> {
        if let Some(entry) = self.records.get_mut(iid) {
            self.clock = self.clock.wrapping_add(1);
            entry.last_use = self.clock;
            return Ok(Some(entry.state));
        }
        if self.storage.is_none() {
            return Ok(None);
        }
        let state = self.read(iid, false)?;
        let floor = self.read(iid, true)?;
        let state = match (state, floor) {
            (None, None) => return Ok(None),
            (None, Some(_)) => return Err(AnnounceStoreError::Corrupt),
            (Some(state), None) => {
                // The sealed state is unforgeable and a missing floor cannot
                // lower trust below it: rebuild the floor from the state.
                self.write(iid, true, state)?;
                state
            }
            (Some(state), Some(floor)) if Self::precedes(state, floor) => {
                return Err(AnnounceStoreError::Corrupt)
            }
            (Some(state), Some(floor)) if state != floor => {
                self.write(iid, true, state)?;
                state
            }
            (Some(state), Some(_)) => state,
        };
        if self.records.len() < MAX_TRACKED_ORIGINATORS {
            self.remember(iid, state);
        }
        Ok(Some(state))
    }

    /// Read-only durable view for accept-time validation (bead 9gug): the
    /// sealed state and floor straight from storage, no cache, NO heal
    /// writes (those belong to load(); accept must not mutate state in its
    /// validation step - a detached floor window would otherwise fail
    /// before the state write commits). Returns the current trust state a
    /// new sequence must strictly advance, or None for a genuinely new pin.
    fn read_durable_current(
        &self,
        iid: &[u8; 8],
    ) -> Result<Option<AnnounceTrustState>, AnnounceStoreError> {
        let state = self.read(iid, false)?;
        let floor = self.read(iid, true)?;
        match (state, floor) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(AnnounceStoreError::Corrupt),
            // The sealed state is unforgeable and a missing floor cannot
            // lower trust below it: validate against the state alone.
            (Some(state), None) => Ok(Some(state)),
            (Some(state), Some(floor)) if Self::precedes(state, floor) => {
                Err(AnnounceStoreError::Corrupt)
            }
            // A lagging floor (crash window) validates against the sealed
            // state - the truth the floor will be healed to.
            (Some(state), Some(_)) => Ok(Some(state)),
        }
    }

    /// Cache `state` for `iid`, LRU-evicting the coldest entry when the
    /// cache is at capacity and `iid` is not already cached. Only the cache
    /// entry is removed; durable records are never deleted.
    fn remember(&mut self, iid: &[u8; 8], state: AnnounceTrustState) {
        if !self.records.contains_key(iid) && self.records.len() >= MAX_TRACKED_ORIGINATORS {
            if let Some((victim, _)) = self
                .records
                .iter()
                .min_by_key(|(_, entry)| entry.last_use)
                .map(|(iid, entry)| (*iid, entry.last_use))
            {
                self.records.remove(&victim);
            }
        }
        self.clock = self.clock.wrapping_add(1);
        self.records.insert(
            *iid,
            CacheEntry {
                state,
                last_use: self.clock,
            },
        );
    }

    /// Record an accepted Announce: pin the exact pubkey and advance the
    /// sequence floor. Refuses pin replacement and any sequence that does
    /// not strictly advance the current floor (wraparound-aware).
    ///
    /// The new-pin capacity gate counts durable state records, so it holds
    /// across restarts and cache eviction; an origin that already has a
    /// durable record is never capacity-gated.
    pub fn accept(
        &mut self,
        iid: &[u8; 8],
        next: AnnounceTrustState,
    ) -> Result<(), AnnounceStoreError> {
        // Durable-first validation (bead 9gug): a second store instance on
        // the same roots has an independent cache, so validating against the
        // cache would let a stale instance seal a regressed (state, floor)
        // pair with zero tamper evidence. Validate against the READ-ONLY
        // durable view instead (no heal writes here - load() owns those, and
        // accept must not mutate during validation). Ephemeral stores have
        // no durable state and stay cache-first.
        let existing = if self.storage.is_some() {
            self.read_durable_current(iid)?
        } else {
            self.load(iid)?
        };
        if let Some(current) = existing {
            if next.pubkey != current.pubkey {
                return Err(AnnounceStoreError::Corrupt);
            }
            if !seq_gt(next.seq, current.seq) {
                return Err(AnnounceStoreError::Corrupt);
            }
        } else if self.storage.is_some() {
            if self.durable_count >= MAX_TRACKED_ORIGINATORS {
                return Err(AnnounceStoreError::Full);
            }
        } else if self.records.len() >= MAX_TRACKED_ORIGINATORS {
            return Err(AnnounceStoreError::Full);
        }
        if self.storage.is_some() {
            self.write(iid, false, next)?;
            if existing.is_none() {
                // The state record is the durable identity: count it as soon
                // as it exists on disk, before the (healable) floor witness
                // write, so a failed floor write cannot undercount.
                self.durable_count += 1;
            }
            if let Err(error) = self.write(iid, true, next) {
                // The state record committed but the floor witness did not.
                // The cache (and any caller-held state) may still reflect the
                // pre-accept floor, and validating against it could overwrite
                // the newer sealed state with a replayed sequence. Evict so
                // the next load() rebuilds from the sealed state and heals
                // the lagging floor forward.
                self.records.remove(iid);
                return Err(error);
            }
        }
        self.remember(iid, next);
        Ok(())
    }
}

/// Count durable state records in `state_dir` (opened by
/// [`AnnounceTrustStore::persistent`]). Floor witnesses live under the
/// separate floor root and temp files are dot-prefixed, but both are
/// excluded by name for robustness. Fails closed on any I/O error so the
/// capacity gate never undercounts.
#[cfg(feature = "std")]
fn count_durable_state_records(state_dir: &Path) -> Result<usize, AnnounceStoreError> {
    let mut count = 0usize;
    for entry in std::fs::read_dir(state_dir).map_err(|_| AnnounceStoreError::Io)? {
        let entry = entry.map_err(|_| AnnounceStoreError::Io)?;
        if !entry
            .file_type()
            .map_err(|_| AnnounceStoreError::Io)?
            .is_file()
        {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("announce-pin-") && !name.ends_with("-floor") {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(feature = "std")]
fn hex_iid(iid: &[u8; 8]) -> String {
    let mut hex = String::with_capacity(16);
    for byte in iid {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble"));
    }
    hex
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_PATH: AtomicU64 = AtomicU64::new(1);

    /// Create a state directory that hardened FileStorage accepts (0700).
    fn private_test_dir(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn unique_roots(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let suffix = TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let state = std::env::temp_dir().join(format!(
            "lichen-node-announce-{name}-{}-{suffix}",
            std::process::id()
        ));
        let floor = state.with_extension("floors");
        private_test_dir(&state);
        private_test_dir(&floor);
        (state, floor)
    }

    /// Write a raw record file the way hardened FileStorage would (0600).
    fn write_record_raw(path: &std::path::Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn state(pubkey_byte: u8, seq: u16) -> AnnounceTrustState {
        AnnounceTrustState {
            pubkey: [pubkey_byte; 32],
            seq,
        }
    }

    fn record_path(root: &Path, iid: &[u8; 8], floor: bool) -> std::path::PathBuf {
        root.join("announce-trust")
            .join(AnnounceTrustStore::key(iid, floor))
    }

    #[test]
    fn store_survives_restart_and_enforces_durable_floor() {
        let (state_root, floor_root) = unique_roots("restart");
        let iid = [0x11; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x32; 32]).unwrap();
        store.accept(&iid, state(0xA1, 100)).unwrap();
        drop(store);

        let mut reopened =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x32; 32]).unwrap();
        assert_eq!(reopened.load(&iid), Ok(Some(state(0xA1, 100))));

        // The durable floor survived the restart: a stale or held sequence
        // is refused, and the pin is still bound to the exact pubkey.
        assert_eq!(
            reopened.accept(&iid, state(0xA1, 100)),
            Err(AnnounceStoreError::Corrupt)
        );
        assert_eq!(
            reopened.accept(&iid, state(0xA1, 50)),
            Err(AnnounceStoreError::Corrupt)
        );
        assert_eq!(
            reopened.accept(&iid, state(0xA2, 200)),
            Err(AnnounceStoreError::Corrupt)
        );
        assert_eq!(reopened.load(&iid), Ok(Some(state(0xA1, 100))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn store_rejects_tamper_and_wrong_sealing_seed() {
        let (state_root, floor_root) = unique_roots("tamper");
        let iid = [0x22; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x42; 32]).unwrap();
        store.accept(&iid, state(0xB1, 10)).unwrap();
        drop(store);

        let record = std::fs::read(record_path(&state_root, &iid, false)).unwrap();
        let mut tampered = record.clone();
        tampered[0] ^= 0x80; // flip a pubkey bit: must not re-pin a different key
        write_record_raw(&record_path(&state_root, &iid, false), &tampered);
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x42; 32]).unwrap();
        assert_eq!(store.load(&iid), Err(AnnounceStoreError::Corrupt));
        drop(store);

        // Restore the ORIGINAL sealed record before the foreign-seed check:
        // a tampered record fails signature verification for ANY seed, so
        // asserting on it proves nothing about seed binding. The restored
        // record verifies under seed 0x42 and must still fail under 0x43.
        write_record_raw(&record_path(&state_root, &iid, false), &record);

        // Sealing is bound to the node persistence key material.
        let mut foreign =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x43; 32]).unwrap();
        assert_eq!(foreign.load(&iid), Err(AnnounceStoreError::Corrupt));

        // And the restored record still verifies under the CORRECT seed -
        // proving the foreign failure is seed-specific, not a generally
        // unreadable record.
        let mut owner_again =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x42; 32]).unwrap();
        assert_eq!(owner_again.load(&iid), Ok(Some(state(0xB1, 10))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn store_seal_is_bound_to_the_iid_key_field() {
        let (state_root, floor_root) = unique_roots("iid-binding");
        let iid = [0x33; 8];
        let other_iid = [0x34; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x52; 32]).unwrap();
        store.accept(&iid, state(0xC1, 7)).unwrap();
        drop(store);

        // A record lifted from one IID does not verify for another.
        std::fs::copy(
            record_path(&state_root, &iid, false),
            record_path(&state_root, &other_iid, false),
        )
        .unwrap();
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x52; 32]).unwrap();
        assert_eq!(store.load(&other_iid), Err(AnnounceStoreError::Corrupt));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn store_fails_closed_when_exactly_one_side_is_present() {
        let (state_root, floor_root) = unique_roots("half-present");
        let iid = [0x44; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x62; 32]).unwrap();
        store.accept(&iid, state(0xD1, 12)).unwrap();
        let state_record = std::fs::read(record_path(&state_root, &iid, false)).unwrap();
        drop(store);

        // Removing the state side must fail closed. accept() must not heal
        // or recreate a half-present record either: trust is never rebuilt
        // from a half-record.
        std::fs::remove_file(record_path(&state_root, &iid, false)).unwrap();
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x62; 32]).unwrap();
        assert_eq!(store.load(&iid), Err(AnnounceStoreError::Corrupt));
        assert_eq!(
            store.accept(&iid, state(0xD1, 12)),
            Err(AnnounceStoreError::Corrupt)
        );
        drop(store);

        // Restore state, remove floor: the state is authoritative and
        // unforgeable, so load heals the floor forward instead of failing.
        write_record_raw(&record_path(&state_root, &iid, false), &state_record);
        std::fs::remove_file(record_path(&floor_root, &iid, true)).unwrap();
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x62; 32]).unwrap();
        assert_eq!(store.load(&iid), Ok(Some(state(0xD1, 12))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn store_heals_first_accept_crash_window_instead_of_bricking() {
        // Crash (or transient IO error) between the state and floor writes
        // of the FIRST-ever accept leaves (Some(state), None) on disk. The
        // originator must recover on the next load/accept, not stay bricked
        // behind Err(Corrupt) forever.
        let (state_root, floor_root) = unique_roots("first-accept-crash");
        let iid = [0xAB; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xC2; 32]).unwrap();
        store.accept(&iid, state(0x41, 1)).unwrap();
        drop(store);
        std::fs::remove_file(record_path(&floor_root, &iid, true)).unwrap();

        let mut reopened =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xC2; 32]).unwrap();
        assert_eq!(reopened.load(&iid), Ok(Some(state(0x41, 1))));
        // The rebuild must have durably rewritten the floor record itself,
        // not merely populated the cache.
        assert_eq!(
            reopened.read(&iid, true),
            Ok(Some(state(0x41, 1))),
            "rebuilt floor must be durably written"
        );
        // The healed floor is durably rewritten: a held sequence is refused.
        assert_eq!(
            reopened.accept(&iid, state(0x41, 1)),
            Err(AnnounceStoreError::Corrupt)
        );
        // And the originator can continue advancing from the healed state.
        assert!(reopened.accept(&iid, state(0x41, 2)).is_ok());
        drop(reopened);

        let mut final_check =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xC2; 32]).unwrap();
        assert_eq!(final_check.load(&iid), Ok(Some(state(0x41, 2))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn store_rejects_state_rollback_and_heals_floor_lag() {
        // A restored older state snapshot behind a newer durable floor
        // fails closed.
        let (state_root, floor_root) = unique_roots("rollback");
        let iid = [0x55; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x72; 32]).unwrap();
        store.accept(&iid, state(0xE1, 100)).unwrap();
        let older_state_record = std::fs::read(record_path(&state_root, &iid, false)).unwrap();
        store.accept(&iid, state(0xE1, 200)).unwrap();
        drop(store);

        write_record_raw(&record_path(&state_root, &iid, false), &older_state_record);
        let mut rolled_back =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x72; 32]).unwrap();
        assert_eq!(rolled_back.load(&iid), Err(AnnounceStoreError::Corrupt));

        // A lagging floor (crash between the two writes) heals forward.
        let (state_root, floor_root) = unique_roots("floor-lag");
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x82; 32]).unwrap();
        store.accept(&iid, state(0xE1, 100)).unwrap();
        let stale_floor_record = std::fs::read(record_path(&floor_root, &iid, true)).unwrap();
        store.accept(&iid, state(0xE1, 200)).unwrap();
        drop(store);

        write_record_raw(&record_path(&floor_root, &iid, true), &stale_floor_record);
        let mut healed =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x82; 32]).unwrap();
        assert_eq!(healed.load(&iid), Ok(Some(state(0xE1, 200))));
        // The heal must have durably rewritten the floor record itself, not
        // merely populated the cache: the sealed on-disk floor now holds the
        // healed sequence (re-arms rollback detection via precedes).
        assert_eq!(
            healed.read(&iid, true),
            Ok(Some(state(0xE1, 200))),
            "healed floor must be durably rewritten"
        );
        // The healed floor is durably rewritten: replay of seq 100 fails.
        drop(healed);
        let mut healed =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x82; 32]).unwrap();
        assert_eq!(
            healed.accept(&iid, state(0xE1, 100)),
            Err(AnnounceStoreError::Corrupt)
        );

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn second_store_instance_cannot_seal_regressed_floor() {
        // 9gug: a second AnnounceTrustStore on the same roots (stale systemd
        // unit beside a debug run) has an independent cache. Validation must
        // consult the DURABLE records, not that cache, or the second
        // instance seals a self-consistent regressed (state, floor) pair
        // with zero tamper evidence.
        let (state_root, floor_root) = unique_roots("second-instance");
        let iid = [0x7A; 8];
        let mut owner =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xD2; 32]).unwrap();
        owner.accept(&iid, state(0x61, 100)).unwrap();

        let mut stale_cache =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xD2; 32]).unwrap();
        assert_eq!(stale_cache.load(&iid), Ok(Some(state(0x61, 100))));

        owner.accept(&iid, state(0x61, 200)).unwrap();
        drop(owner);

        // The stale-cache instance must not seal (150,150): durable-first
        // validation reads 200 and refuses the regression.
        assert_eq!(
            stale_cache.accept(&iid, state(0x61, 150)),
            Err(AnnounceStoreError::Corrupt)
        );
        // B's cache legitimately still holds the stale 100 (the Corrupt
        // rejection does not evict), but that is now harmless: every future
        // accept re-validates durable-first, so the regression stays
        // blocked regardless of what the cache serves.
        assert_eq!(stale_cache.load(&iid), Ok(Some(state(0x61, 100))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn store_refuses_pin_replacement_for_same_iid() {
        let (state_root, floor_root) = unique_roots("pin-replacement");
        let iid = [0x66; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x92; 32]).unwrap();
        store.accept(&iid, state(0xF1, 5)).unwrap();
        // An IID collision presenting a different key must never re-pin,
        // not even in the cache, and must leave durable state untouched.
        assert_eq!(
            store.accept(
                &iid,
                AnnounceTrustState {
                    pubkey: [0xF2; 32],
                    seq: 6000,
                }
            ),
            Err(AnnounceStoreError::Corrupt)
        );
        assert_eq!(store.load(&iid), Ok(Some(state(0xF1, 5))));
        drop(store);

        let mut reopened =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0x92; 32]).unwrap();
        assert_eq!(reopened.load(&iid), Ok(Some(state(0xF1, 5))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn store_sequence_floor_advances_with_wraparound() {
        let (state_root, floor_root) = unique_roots("wraparound");
        let iid = [0x77; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xA2; 32]).unwrap();
        store.accept(&iid, state(0x11, 65534)).unwrap();
        // 5 is newer than 65534 under RFC 1982 serial arithmetic.
        store.accept(&iid, state(0x11, 5)).unwrap();
        assert_eq!(store.load(&iid), Ok(Some(state(0x11, 5))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn store_capacity_is_bounded() {
        let mut store = AnnounceTrustStore::ephemeral_unprotected();
        for i in 0..MAX_TRACKED_ORIGINATORS {
            let mut iid = [0u8; 8];
            iid[0] = i as u8;
            store
                .accept(&iid, state((i % 251) as u8 + 1, i as u16))
                .unwrap();
        }
        assert_eq!(
            store.accept(&[0xFF; 8], state(1, 1)),
            Err(AnnounceStoreError::Full)
        );
    }

    #[test]
    fn durable_capacity_gate_counts_durable_records_not_cache() {
        let (state_root, floor_root) = unique_roots("durable-gate");
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xD2; 32]).unwrap();
        for i in 0..MAX_TRACKED_ORIGINATORS {
            let mut iid = [0u8; 8];
            iid[0] = i as u8;
            store
                .accept(&iid, state(i as u8 + 1, 100 + i as u16))
                .unwrap();
        }
        // At capacity a brand-new pin is refused.
        assert_eq!(
            store.accept(&[0xEE; 8], state(1, 1)),
            Err(AnnounceStoreError::Full)
        );
        drop(store);

        // Restart with an EMPTY cache: the gate must still hold. Counting
        // the cache would reopen admission and overflow the durable store.
        let mut reopened =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xD2; 32]).unwrap();
        assert_eq!(
            reopened.accept(&[0xEF; 8], state(1, 2)),
            Err(AnnounceStoreError::Full)
        );

        // An origin with a durable record is never capacity-gated.
        let first = [0u8; 8];
        assert!(reopened.accept(&first, state(1, 101)).is_ok());
        assert_eq!(reopened.load(&first), Ok(Some(state(1, 101))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn load_survives_full_cache_and_accept_lru_evicts() {
        let (state_root, floor_root) = unique_roots("full-cache");
        let over = MAX_TRACKED_ORIGINATORS + 2;

        // Seed an over-capacity durable store directly through the sealed
        // record writer: the only way this state arises is the old
        // cache-counted gate (or an operator capacity downgrade), and the
        // store must still serve every durably-pinned origin.
        {
            let mut store =
                AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xE2; 32]).unwrap();
            for i in 0..over {
                let mut iid = [0u8; 8];
                iid[0] = i as u8;
                let seeded = state(i as u8 + 1, 7);
                store.write(&iid, false, seeded).unwrap();
                store.write(&iid, true, seeded).unwrap();
            }
        }

        let mut reopened =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xE2; 32]).unwrap();
        // The open-time recount sees all over-capacity records: no new pins.
        assert_eq!(
            reopened.accept(&[0xFF; 8], state(9, 9)),
            Err(AnnounceStoreError::Full)
        );

        // The first MAX loads fill the cache; the remainder must still load
        // (cache-skip path) instead of failing with Full.
        for i in 0..over {
            let mut iid = [0u8; 8];
            iid[0] = i as u8;
            assert_eq!(
                reopened.load(&iid),
                Ok(Some(state(i as u8 + 1, 7))),
                "durably-pinned origin {i} must survive a full cache"
            );
        }

        // Over-capacity origins keep advancing: the accept's cache insert
        // LRU-evicts a cache entry rather than failing with Full, and the
        // evicted origin still resolves from its durable record.
        let mut evict_candidate = [0u8; 8];
        evict_candidate[0] = (over - 1) as u8;
        assert!(reopened
            .accept(&evict_candidate, state(over as u8, 8))
            .is_ok());
        assert_eq!(
            reopened.load(&evict_candidate),
            Ok(Some(state(over as u8, 8)))
        );
        assert_eq!(reopened.load(&[0u8; 8]), Ok(Some(state(1, 7))));

        // And the advanced floor is durable across another restart.
        drop(reopened);
        let mut final_check =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xE2; 32]).unwrap();
        assert_eq!(
            final_check.load(&evict_candidate),
            Ok(Some(state(over as u8, 8)))
        );
        assert_eq!(final_check.load(&[0u8; 8]), Ok(Some(state(1, 7))));
        assert_eq!(
            final_check.accept(&[0xF1; 8], state(1, 1)),
            Err(AnnounceStoreError::Full)
        );

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn failed_floor_write_evicts_stale_cache_and_load_rebuilds() {
        // Non-fatal floor-write failure after the state commit (ENOSPC/EIO on
        // the floor root): the accept must not leave the pre-accept state in
        // the cache, or a replayed intermediate sequence would pass the
        // stale-cache check and regress the newer sealed state.
        let (state_root, floor_root) = unique_roots("floor-write-fail");
        let iid = [0x9B; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xF2; 32]).unwrap();
        store.accept(&iid, state(0x71, 100)).unwrap();

        // Detaching the floor storage makes exactly the floor write fail
        // (Err(Io)) after the state write committed.
        let floor_storage = store.floor_storage.take();
        assert_eq!(
            store.accept(&iid, state(0x71, 200)),
            Err(AnnounceStoreError::Io)
        );

        // The state record committed: the durable record on disk holds 200.
        let raw = std::fs::read(record_path(&state_root, &iid, false)).unwrap();
        let durable_seq = u16::from_be_bytes([raw[32], raw[33]]);
        assert_eq!(durable_seq, 200);

        // Restore the floor and rebuild in the SAME store instance: the
        // durable state (200) must be served, not the stale cached 100, and
        // the lagging floor heals forward to the sealed state.
        store.floor_storage = floor_storage;
        assert_eq!(store.load(&iid), Ok(Some(state(0x71, 200))));
        // The heal must have durably rewritten the floor record itself, not
        // merely populated the cache.
        assert_eq!(
            store.read(&iid, true),
            Ok(Some(state(0x71, 200))),
            "healed floor must be durably rewritten"
        );

        // The healed floor rejects the intermediate replay that a stale
        // cache would have accepted, and the floor keeps advancing.
        assert_eq!(
            store.accept(&iid, state(0x71, 150)),
            Err(AnnounceStoreError::Corrupt)
        );
        assert!(store.accept(&iid, state(0x71, 201)).is_ok());
        drop(store);

        // The advanced state is durable across a restart.
        let mut final_check =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xF2; 32]).unwrap();
        assert_eq!(final_check.load(&iid), Ok(Some(state(0x71, 201))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn ephemeral_store_roundtrip() {
        let iid = [0x88; 8];
        let mut store = AnnounceTrustStore::ephemeral_unprotected();
        assert_eq!(store.load(&iid), Ok(None));
        store.accept(&iid, state(0x21, 9)).unwrap();
        assert_eq!(store.load(&iid), Ok(Some(state(0x21, 9))));
        assert_eq!(
            store.accept(&iid, state(0x21, 8)),
            Err(AnnounceStoreError::Corrupt)
        );
    }

    #[test]
    fn debug_output_never_contains_the_sealing_seed() {
        let (state_root, floor_root) = unique_roots("debug-redacted");
        let seed = [0x37; 32];
        let mut store = AnnounceTrustStore::persistent(&state_root, &floor_root, &seed).unwrap();
        store.accept(&[0x99; 8], state(0x31, 1)).unwrap();
        let rendered = format!("{store:?}");
        assert!(rendered.contains("sealing_seed"), "{rendered}");
        // The seed must appear neither raw (byte-wise window) nor as any
        // run of its own hex nibbles.
        for window in seed.windows(4) {
            assert!(
                !rendered.as_bytes().windows(4).any(|w| w == window),
                "debug output leaked seed bytes: {rendered}"
            );
        }
        assert!(!rendered.contains("37373737"), "{rendered}");
        drop(store);
        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }

    #[test]
    fn persistent_open_fails_when_root_is_a_file() {
        let suffix = TEST_PATH.fetch_add(1, Ordering::Relaxed);
        let blocker = std::env::temp_dir().join(format!(
            "lichen-node-announce-blocked-{}-{suffix}",
            std::process::id()
        ));
        std::fs::write(&blocker, b"not a directory").unwrap();
        assert!(matches!(
            AnnounceTrustStore::persistent(&blocker, &blocker, &[0xB2; 32]),
            Err(AnnounceStoreError::Io)
        ));
        std::fs::remove_file(blocker).unwrap();
    }
    #[test]
    fn store_floor_outlives_cache_eviction() {
        // Eviction interaction: the in-memory admission cache may evict a
        // pinned originator under capacity pressure, but the durable pin and
        // floor outlive that eviction. After the cache entry is gone (store
        // handle dropped and reopened), the evicted originator can neither
        // replay an older sequence nor re-pin the IID with a different key.
        let (state_root, floor_root) = unique_roots("floor-outlives-eviction");
        let iid = [0x8A; 8];
        let mut store =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xB2; 32]).unwrap();
        store.accept(&iid, state(0x21, 100)).unwrap();
        // Eviction: drop the handle; durable state must be untouched.
        drop(store);

        let mut reopened =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xB2; 32]).unwrap();
        // Replay of the evicted originator's older announcement is refused.
        assert_eq!(
            reopened.accept(&iid, state(0x21, 99)),
            Err(AnnounceStoreError::Corrupt)
        );
        // A different key claiming the evicted IID must not re-pin.
        assert_eq!(
            reopened.accept(
                &iid,
                AnnounceTrustState {
                    pubkey: [0x22; 32],
                    seq: 101,
                }
            ),
            Err(AnnounceStoreError::Corrupt)
        );
        // The floor still advances for the pinned key.
        reopened.accept(&iid, state(0x21, 101)).unwrap();
        drop(reopened);

        // And the advanced floor survives another restart.
        let mut reopened =
            AnnounceTrustStore::persistent(&state_root, &floor_root, &[0xB2; 32]).unwrap();
        assert_eq!(reopened.load(&iid), Ok(Some(state(0x21, 101))));

        std::fs::remove_dir_all(state_root).unwrap();
        std::fs::remove_dir_all(floor_root).unwrap();
    }
}
