//! Persistent identity storage using NonVolatile trait.
//!
//! Stores:
//! - Identity seed (32 bytes) → derives keypair on load
//! - Peer table (pubkeys for signature verification)
//! - Link layer sequence numbers (for replay protection continuity)

use crate::NonVolatile;
use lichen_link::{PublicKey, Seed};

const SLOT_VERSION: u8 = 1;
const SLOT_HEADER_LEN: usize = 20;
const SLOT_TRAILER_LEN: usize = 4;

/// Parsed slot info: (generation, payload_len) if valid, plus whether any data was present.
type ParsedSlot = (Option<(u64, usize)>, bool);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedundantOpenError<E> {
    Missing,
    Corrupt,
    BufferTooSmall,
    Storage(E),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedundantValue {
    pub generation: u64,
    pub slot: usize,
    pub len: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RedundantProvisionError<E> {
    Exists,
    Storage(E),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RedundantUpdateError<E> {
    Storage(E),
    Stale,
    Exhausted,
    Corrupt,
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn parse_slot<'a>(raw: &'a [u8], magic: &[u8; 4]) -> Option<(u64, &'a [u8])> {
    if raw.len() < SLOT_HEADER_LEN + SLOT_TRAILER_LEN
        || &raw[..4] != magic
        || raw[4] != SLOT_VERSION
        || raw[5..8] != [0; 3]
    {
        return None;
    }
    let generation = u64::from_be_bytes(raw[8..16].try_into().ok()?);
    let payload_len = u32::from_be_bytes(raw[16..20].try_into().ok()?) as usize;
    let checksum_at = SLOT_HEADER_LEN.checked_add(payload_len)?;
    if generation == 0 || checksum_at.checked_add(SLOT_TRAILER_LEN)? != raw.len() {
        return None;
    }
    let expected = u32::from_be_bytes(raw[checksum_at..].try_into().ok()?);
    (crc32(&raw[..checksum_at]) == expected)
        .then_some((generation, &raw[SLOT_HEADER_LEN..checksum_at]))
}

fn read_raw<'a, S: NonVolatile>(
    storage: &S,
    key: &str,
    buf: &'a mut [u8],
) -> Result<Option<&'a [u8]>, RedundantOpenError<S::Error>> {
    let Some(len) = storage
        .read(key, buf)
        .map_err(RedundantOpenError::Storage)?
    else {
        return Ok(None);
    };
    if len > buf.len() {
        return Err(RedundantOpenError::BufferTooSmall);
    }
    Ok(Some(&buf[..len]))
}

fn read_parsed_update<S: NonVolatile>(
    storage: &S,
    key: &str,
    buf: &mut [u8],
    magic: [u8; 4],
) -> Result<ParsedSlot, RedundantUpdateError<S::Error>> {
    let raw = read_raw(storage, key, buf).map_err(|error| match error {
        RedundantOpenError::Storage(error) => RedundantUpdateError::Storage(error),
        _ => RedundantUpdateError::Corrupt,
    })?;
    let present = raw.is_some();
    let parsed = raw
        .and_then(|raw| parse_slot(raw, &magic))
        .map(|(generation, payload)| (generation, payload.len()));
    Ok((parsed, present))
}

/// Open the newest valid value from two alternating slots.
pub fn open_redundant<S: NonVolatile>(
    storage: &S,
    keys: [&str; 2],
    magic: [u8; 4],
    slot_a: &mut [u8],
    slot_b: &mut [u8],
    out: &mut [u8],
) -> Result<RedundantValue, RedundantOpenError<S::Error>> {
    let raw_a = read_raw(storage, keys[0], slot_a)?;
    let raw_b = read_raw(storage, keys[1], slot_b)?;
    let parsed_a = raw_a.and_then(|raw| parse_slot(raw, &magic));
    let parsed_b = raw_b.and_then(|raw| parse_slot(raw, &magic));
    let (generation, slot, payload) = match (parsed_a, parsed_b) {
        (Some(a), Some(b)) if b.0 > a.0 => (b.0, 1, b.1),
        (Some(a), _) => (a.0, 0, a.1),
        (None, Some(b)) => (b.0, 1, b.1),
        (None, None) if raw_a.is_none() && raw_b.is_none() => {
            return Err(RedundantOpenError::Missing)
        }
        (None, None) => return Err(RedundantOpenError::Corrupt),
    };
    if payload.len() > out.len() {
        return Err(RedundantOpenError::BufferTooSmall);
    }
    out[..payload.len()].copy_from_slice(payload);
    Ok(RedundantValue {
        generation,
        slot,
        len: payload.len(),
    })
}

fn encode_slot(magic: [u8; 4], generation: u64, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let len = SLOT_HEADER_LEN
        .checked_add(payload.len())?
        .checked_add(SLOT_TRAILER_LEN)?;
    if generation == 0 || payload.len() > u32::MAX as usize || out.len() < len {
        return None;
    }
    out[..4].copy_from_slice(&magic);
    out[4] = SLOT_VERSION;
    out[5..8].fill(0);
    out[8..16].copy_from_slice(&generation.to_be_bytes());
    out[16..20].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[20..20 + payload.len()].copy_from_slice(payload);
    let checksum_at = 20 + payload.len();
    let checksum = crc32(&out[..checksum_at]);
    out[checksum_at..len].copy_from_slice(&checksum.to_be_bytes());
    Some(len)
}

/// Provision an absent two-slot value. Existing or corrupt state is not overwritten.
pub fn provision_redundant<S: NonVolatile>(
    storage: &mut S,
    keys: [&str; 2],
    magic: [u8; 4],
    payload: &[u8],
    record: &mut [u8],
) -> Result<(), RedundantProvisionError<S::Error>> {
    let mut present = [0u8; 1];
    let a = storage
        .read(keys[0], &mut present)
        .map_err(RedundantProvisionError::Storage)?;
    let b = storage
        .read(keys[1], &mut present)
        .map_err(RedundantProvisionError::Storage)?;
    if a.is_some() || b.is_some() {
        return Err(RedundantProvisionError::Exists);
    }
    let len = encode_slot(magic, 1, payload, record).expect("record buffer sized by caller");
    storage
        .write(keys[0], &record[..len])
        .map_err(RedundantProvisionError::Storage)
}

/// Persist the next generation to the slot opposite `current.slot`.
pub fn update_redundant<S: NonVolatile>(
    storage: &mut S,
    keys: [&str; 2],
    magic: [u8; 4],
    current: RedundantValue,
    payload: &[u8],
    record: &mut [u8],
) -> Result<RedundantValue, RedundantUpdateError<S::Error>> {
    let (parsed_a, a_present) = read_parsed_update(storage, keys[0], record, magic)?;
    let (parsed_b, b_present) = read_parsed_update(storage, keys[1], record, magic)?;
    let latest = match (parsed_a, parsed_b) {
        (Some(a), Some(b)) if b.0 > a.0 => RedundantValue {
            generation: b.0,
            slot: 1,
            len: b.1,
        },
        (Some(a), _) => RedundantValue {
            generation: a.0,
            slot: 0,
            len: a.1,
        },
        (None, Some(b)) => RedundantValue {
            generation: b.0,
            slot: 1,
            len: b.1,
        },
        (None, None) if !a_present && !b_present => return Err(RedundantUpdateError::Stale),
        (None, None) => return Err(RedundantUpdateError::Corrupt),
    };
    if latest.generation != current.generation || latest.slot != current.slot {
        return Err(RedundantUpdateError::Stale);
    }
    let generation = current
        .generation
        .checked_add(1)
        .ok_or(RedundantUpdateError::Exhausted)?;
    let len =
        encode_slot(magic, generation, payload, record).expect("record buffer sized by caller");
    let slot = 1 - current.slot;
    storage
        .write(keys[slot], &record[..len])
        .map_err(RedundantUpdateError::Storage)?;
    Ok(RedundantValue {
        generation,
        slot,
        len: payload.len(),
    })
}

/// Storage key constants for persistent identity and link state.
///
/// # Design Rationale
///
/// Keys are defined as constants rather than inline strings to:
/// - **Prevent typos**: A misspelled constant is a compile error; a misspelled
///   string silently reads/writes the wrong slot.
/// - **Enable refactoring**: Renaming a key updates all usages automatically.
/// - **Support grep/IDE navigation**: Constants are discoverable; magic strings
///   scattered across call sites are not.
///
/// # Naming Convention
///
/// Keys use a `namespace.field` format with short names (8 chars max) to
/// minimize flash wear and storage overhead on embedded targets. The prefixes
/// group related data:
/// - `id.*` — node identity (seed, replay-protection state)
/// - `peers.*` — peer public keys
/// - `peer.N` — individual peer entries (see [`peer_key`])
pub mod keys {
    /// 32-byte Ed25519 seed that derives the node's keypair.
    pub const IDENTITY_SEED: &str = "id.seed";
    /// Link-layer epoch counter (1 byte) for replay protection.
    pub const EPOCH: &str = "id.epoch";
    /// Link-layer sequence number (2 bytes, big-endian) for replay protection.
    pub const SEQNUM: &str = "id.seq";
    /// Number of persisted peers (1 byte).
    pub const PEER_COUNT: &str = "peers.n";
}

/// Maximum number of peers to persist.
pub const MAX_PEERS: usize = 16;

/// Get peer key name for index.
pub fn peer_key(index: usize) -> heapless::String<16> {
    let mut s = heapless::String::new();
    core::fmt::write(&mut s, format_args!("peer.{}", index))
        .expect("peer key always fits in 16 bytes");
    s
}

/// Load identity seed from storage.
///
/// Returns `Some(seed)` if found and valid, `None` otherwise.
pub fn load_seed<S: NonVolatile>(storage: &S) -> Result<Option<Seed>, S::Error> {
    let mut buf = [0u8; 32];
    let Some(n) = storage.read(keys::IDENTITY_SEED, &mut buf)? else {
        return Ok(None);
    };
    Ok(if n == 32 { Some(Seed::new(buf)) } else { None })
}

/// Save identity seed to storage.
pub fn save_seed<S: NonVolatile>(storage: &mut S, seed: &Seed) -> Result<(), S::Error> {
    storage.write(keys::IDENTITY_SEED, seed.as_bytes())
}

/// Load link layer epoch from storage.
pub fn load_epoch<S: NonVolatile>(storage: &S) -> Result<Option<u8>, S::Error> {
    let mut buf = [0u8; 1];
    let Some(n) = storage.read(keys::EPOCH, &mut buf)? else {
        return Ok(None);
    };
    Ok(if n == 1 { Some(buf[0]) } else { None })
}

/// Save link layer epoch to storage.
pub fn save_epoch<S: NonVolatile>(storage: &mut S, epoch: u8) -> Result<(), S::Error> {
    storage.write(keys::EPOCH, &[epoch])
}

/// Load link layer sequence number from storage.
pub fn load_seqnum<S: NonVolatile>(storage: &S) -> Result<Option<u16>, S::Error> {
    let mut buf = [0u8; 2];
    let Some(n) = storage.read(keys::SEQNUM, &mut buf)? else {
        return Ok(None);
    };
    Ok(if n == 2 {
        Some(u16::from_be_bytes(buf))
    } else {
        None
    })
}

/// Save link layer sequence number to storage.
pub fn save_seqnum<S: NonVolatile>(storage: &mut S, seqnum: u16) -> Result<(), S::Error> {
    storage.write(keys::SEQNUM, &seqnum.to_be_bytes())
}

/// Load peer count from storage.
pub fn load_peer_count<S: NonVolatile>(storage: &S) -> Result<usize, S::Error> {
    let mut buf = [0u8; 1];
    Ok(storage.read(keys::PEER_COUNT, &mut buf)?.map_or(0, |n| {
        if n == 1 {
            buf[0] as usize
        } else {
            0
        }
    }))
}

/// Load a peer pubkey from storage.
pub fn load_peer<S: NonVolatile>(storage: &S, index: usize) -> Result<Option<PublicKey>, S::Error> {
    if index >= MAX_PEERS {
        return Ok(None);
    }
    let key = peer_key(index);
    let mut buf = [0u8; 32];
    let Some(n) = storage.read(&key, &mut buf)? else {
        return Ok(None);
    };
    Ok(if n == 32 {
        Some(PublicKey::new(buf))
    } else {
        None
    })
}

/// Save peer table to storage.
///
/// Overwrites existing peers. Pass a slice of pubkeys.
///
/// SECURITY: Writes entries before count to ensure crash safety - the count
/// only reflects successfully written entries.
pub fn save_peers<S: NonVolatile>(storage: &mut S, peers: &[PublicKey]) -> Result<(), S::Error> {
    let count = peers.len().min(MAX_PEERS);
    for (i, pubkey) in peers.iter().take(count).enumerate() {
        let key = peer_key(i);
        storage.write(&key, pubkey.as_bytes())?;
    }
    // Write count LAST so it only reflects successfully written entries
    storage.write(keys::PEER_COUNT, &[count as u8])?;
    Ok(())
}

/// In-memory NonVolatile implementation for testing.
#[cfg(any(test, feature = "std"))]
pub mod mem {
    extern crate std;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::string::String;
    use std::vec::Vec;

    use crate::NonVolatile;

    /// In-memory storage for testing.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MemStorageError;

    #[derive(Debug, Default, Clone)]
    pub struct MemStorage {
        data: HashMap<String, Vec<u8>>,
        fail_after_writes: Option<usize>,
        fail_next_read: Cell<bool>,
    }

    impl MemStorage {
        pub fn new() -> Self {
            Self::default()
        }

        /// Simulate reboot by clearing volatile state but keeping persisted data.
        ///
        /// No-op: MemStorage is always persistent, so "reboot" changes nothing.
        /// Call this in tests to verify data survives simulated reboots.
        pub fn clear_volatile(&mut self) {}

        pub fn fail_next_write(&mut self) {
            self.fail_after_writes = Some(0);
        }

        pub fn fail_next_read(&self) {
            self.fail_next_read.set(true);
        }

        pub fn fail_after_writes(&mut self, successful_writes: usize) {
            self.fail_after_writes = Some(successful_writes);
        }

        pub fn set_raw(&mut self, key: &str, value: &[u8]) {
            self.data.insert(key.into(), value.to_vec());
        }

        pub fn raw(&self, key: &str) -> Option<&[u8]> {
            self.data.get(key).map(Vec::as_slice)
        }
    }

    impl NonVolatile for MemStorage {
        type Error = MemStorageError;

        fn read(&self, key: &str, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            if self.fail_next_read.replace(false) {
                return Err(MemStorageError);
            }
            let Some(data) = self.data.get(key) else {
                return Ok(None);
            };
            let stored = data.len();
            let n = stored.min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok(Some(stored))
        }

        fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error> {
            if let Some(remaining) = self.fail_after_writes.as_mut() {
                if *remaining == 0 {
                    self.fail_after_writes = None;
                    return Err(MemStorageError);
                }
                *remaining -= 1;
            }
            self.data.insert(key.into(), data.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &str) -> bool {
            self.data.remove(key).is_some()
        }
    }
}

#[cfg(feature = "std")]
pub mod fs {
    //! File-backed [`NonVolatile`] with a private security-state policy.
    //!
    //! [`FileStorage`] holds identity seeds, replay-protection state, and
    //! sealed records, so it applies fail-closed Unix semantics instead of
    //! process umask defaults:
    //!
    //! - The state directory is created owner-only (0700). A pre-existing
    //!   directory must already be a real, owner-only directory, or opening
    //!   fails.
    //! - Writes go through a uniquely named 0600 temp file opened with
    //!   exclusive-create semantics (which refuses a pre-planted file or
    //!   symlink at a guessed path), fsynced, verified, then atomically
    //!   renamed into place.
    //! - Reads verify the open file is a regular 0600 file owned by the
    //!   effective user (Linux) and that the path still resolves to the same
    //!   inode, refusing symlinks and group/world-readable files.

    extern crate std;
    use crate::NonVolatile;
    use std::fs;
    use std::io::{self, Read, Write};
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug)]
    pub struct FileStorage {
        dir: PathBuf,
    }

    impl FileStorage {
        pub fn new<P: AsRef<Path>>(p: P) -> io::Result<Self> {
            let d = p.as_ref().to_path_buf();
            match fs::symlink_metadata(&d) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    create_private_dir(&d)?;
                }
                Err(error) => return Err(error),
            }
            verify_private_dir(&d)?;
            Ok(Self { dir: d })
        }
        fn key_path(&self, k: &str) -> PathBuf {
            self.dir.join(k)
        }
        /// Uniquely named temp path; exclusive-create opening refuses any
        /// pre-planted file or symlink at a guessed name.
        fn temp_path(&self, k: &str) -> PathBuf {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            self.dir
                .join(format!(".{}.{}-{}.tmp", k, std::process::id(), n))
        }
    }

    impl NonVolatile for FileStorage {
        type Error = io::Error;
        fn read(&self, key: &str, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            let p = self.key_path(key);
            let mut file = match fs::File::open(&p) {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            };
            verify_private_file(&p, &file.metadata()?, "security state")?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            let stored = data.len();
            let n = stored.min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok(Some(stored))
        }
        fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error> {
            let final_path = self.key_path(key);
            let temp_path = self.temp_path(key);
            let result = (|| -> io::Result<()> {
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                options.mode(0o600);
                let mut file = options.open(&temp_path)?;
                #[cfg(unix)]
                fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
                file.write_all(data)?;
                file.sync_all()?;
                verify_private_file(&temp_path, &file.metadata()?, "security state")?;
                fs::rename(&temp_path, &final_path)?;
                sync_dir(&self.dir);
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temp_path);
            }
            result
        }
        fn delete(&mut self, key: &str) -> bool {
            let p = self.key_path(key);
            fs::remove_file(p).is_ok()
        }
    }

    fn sync_dir(path: &Path) {
        let _ = fs::File::open(path).and_then(|d| d.sync_all());
    }

    fn create_private_dir(path: &Path) -> io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        if let Err(error) = builder.create(path) {
            // A concurrent creator is acceptable; verification below decides
            // whether the existing directory is trustworthy.
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn private_state_error(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message.into())
    }

    /// Fail closed unless `path` is a real, owner-only directory.
    fn verify_private_dir(path: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir() {
            return Err(private_state_error(
                "state directory must be a real directory, not a link or special file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o7777 != 0o700 {
                return Err(private_state_error("state directory must have mode 0700"));
            }
        }
        verify_effective_owner(&metadata, "state directory")
    }

    /// Fail closed unless `path` still resolves to the already-open regular
    /// 0600 file described by `metadata` (no symlink swap, no mode drift).
    fn verify_private_file(path: &Path, metadata: &fs::Metadata, label: &str) -> io::Result<()> {
        if !metadata.file_type().is_file() {
            return Err(private_state_error(format!(
                "{label} is not a regular file"
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let path_metadata = fs::symlink_metadata(path)?;
            if path_metadata.file_type().is_symlink()
                || path_metadata.dev() != metadata.dev()
                || path_metadata.ino() != metadata.ino()
            {
                return Err(private_state_error(format!(
                    "{label} path changed or is a symbolic link"
                )));
            }
            if metadata.permissions().mode() & 0o7777 != 0o600 {
                return Err(private_state_error(format!("{label} must have mode 0600")));
            }
        }
        verify_effective_owner(metadata, label)
    }

    #[cfg(target_os = "linux")]
    fn verify_effective_owner(metadata: &fs::Metadata, label: &str) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let effective_uid = fs::metadata("/proc/self")?.uid();
        if metadata.uid() != effective_uid {
            return Err(private_state_error(format!(
                "{label} is not owned by the effective user"
            )));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn verify_effective_owner(_metadata: &fs::Metadata, _label: &str) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use super::fs::FileStorage;
    use super::*;
    use mem::MemStorage;
    #[cfg(feature = "std")]
    use std::fs;
    #[cfg(feature = "std")]
    use std::io;

    #[test]
    fn seed_round_trip() {
        let mut storage = MemStorage::new();
        let seed = Seed::new([0xABu8; 32]);

        assert_eq!(load_seed(&storage).unwrap(), None);
        save_seed(&mut storage, &seed).unwrap();
        assert_eq!(load_seed(&storage).unwrap(), Some(seed));
    }

    #[test]
    fn epoch_seqnum_round_trip() {
        let mut storage = MemStorage::new();

        assert_eq!(load_epoch(&storage).unwrap(), None);
        assert_eq!(load_seqnum(&storage).unwrap(), None);

        save_epoch(&mut storage, 5).unwrap();
        save_seqnum(&mut storage, 12345).unwrap();

        assert_eq!(load_epoch(&storage).unwrap(), Some(5));
        assert_eq!(load_seqnum(&storage).unwrap(), Some(12345));
    }

    #[test]
    fn peers_round_trip() {
        let mut storage = MemStorage::new();
        let peers = [
            PublicKey::new([0x01u8; 32]),
            PublicKey::new([0x02u8; 32]),
            PublicKey::new([0x03u8; 32]),
        ];

        assert_eq!(load_peer_count(&storage).unwrap(), 0);
        save_peers(&mut storage, &peers).unwrap();

        assert_eq!(load_peer_count(&storage).unwrap(), 3);
        assert_eq!(
            load_peer(&storage, 0).unwrap(),
            Some(PublicKey::new([0x01u8; 32]))
        );
        assert_eq!(
            load_peer(&storage, 1).unwrap(),
            Some(PublicKey::new([0x02u8; 32]))
        );
        assert_eq!(
            load_peer(&storage, 2).unwrap(),
            Some(PublicKey::new([0x03u8; 32]))
        );
        assert_eq!(load_peer(&storage, 3).unwrap(), None);
    }

    #[test]
    fn seed_survives_simulated_reboot() {
        let mut storage = MemStorage::new();
        let seed = Seed::new([0xDEu8; 32]);
        save_seed(&mut storage, &seed).unwrap();

        storage.clear_volatile();
        assert_eq!(load_seed(&storage).unwrap(), Some(seed));
    }

    #[test]
    fn redundant_slots_survive_corrupt_newest_and_reject_torn_only_slot() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut record = [0u8; 64];
        provision_redundant(&mut storage, keys, *b"TEST", b"old", &mut record).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        let first = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        update_redundant(&mut storage, keys, *b"TEST", first, b"new", &mut record).unwrap();
        storage.set_raw(keys[1], b"torn");
        let loaded = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        assert_eq!(&out[..loaded.len], b"old");

        storage.delete(keys[0]);
        assert_eq!(
            open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out),
            Err(RedundantOpenError::Corrupt)
        );
    }

    #[test]
    fn acknowledged_write_is_atomic_or_old_value_remains() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut record = [0u8; 64];
        provision_redundant(&mut storage, keys, *b"TEST", b"old", &mut record).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        let first = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        storage.fail_next_write();
        assert!(
            update_redundant(&mut storage, keys, *b"TEST", first, b"new", &mut record).is_err()
        );
        let loaded = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        assert_eq!(&out[..loaded.len], b"old");
    }

    #[test]
    fn redundant_open_rejects_reported_length_larger_than_buffer() {
        let mut storage = MemStorage::new();
        storage.set_raw("test.a", &[0u8; 65]);
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        assert_eq!(
            open_redundant(
                &storage,
                ["test.a", "test.b"],
                *b"TEST",
                &mut a,
                &mut b,
                &mut out,
            ),
            Err(RedundantOpenError::BufferTooSmall)
        );
    }

    #[test]
    fn redundant_update_rejects_stale_handle() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut record = [0u8; 64];
        provision_redundant(&mut storage, keys, *b"TEST", b"old", &mut record).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        let first = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        let stale = first;
        update_redundant(&mut storage, keys, *b"TEST", first, b"new", &mut record).unwrap();
        assert_eq!(
            update_redundant(&mut storage, keys, *b"TEST", stale, b"lost", &mut record),
            Err(RedundantUpdateError::Stale)
        );
    }

    #[test]
    fn redundant_read_failures_are_not_treated_as_missing() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        storage.fail_next_read();
        assert_eq!(
            open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out),
            Err(RedundantOpenError::Storage(mem::MemStorageError))
        );

        let mut record = [0u8; 64];
        storage.fail_next_read();
        assert_eq!(
            provision_redundant(&mut storage, keys, *b"TEST", b"new", &mut record),
            Err(RedundantProvisionError::Storage(mem::MemStorageError))
        );
        assert!(storage.raw(keys[0]).is_none());
        assert!(storage.raw(keys[1]).is_none());
    }

    #[test]
    fn equal_max_generation_slots_are_exhausted_without_write() {
        let mut storage = MemStorage::new();
        let keys = ["test.a", "test.b"];
        let mut record = [0u8; 64];
        let len = encode_slot(*b"TEST", u64::MAX, b"old", &mut record).unwrap();
        storage.set_raw(keys[0], &record[..len]);
        storage.set_raw(keys[1], &record[..len]);
        let before_a = storage.raw(keys[0]).unwrap().to_vec();
        let before_b = storage.raw(keys[1]).unwrap().to_vec();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut out = [0u8; 16];
        let current = open_redundant(&storage, keys, *b"TEST", &mut a, &mut b, &mut out).unwrap();
        assert_eq!(current.generation, u64::MAX);
        assert_eq!(current.slot, 0);
        assert_eq!(
            update_redundant(&mut storage, keys, *b"TEST", current, b"new", &mut record,),
            Err(RedundantUpdateError::Exhausted)
        );
        assert_eq!(storage.raw(keys[0]), Some(before_a.as_slice()));
        assert_eq!(storage.raw(keys[1]), Some(before_b.as_slice()));
    }

    #[cfg(feature = "std")]
    fn unique_fs_dir(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "lichen-hal-fs-{}-{}-{}",
            label,
            std::process::id(),
            n
        ))
    }

    #[cfg(all(unix, feature = "std"))]
    fn make_private_dir(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    #[cfg(feature = "std")]
    fn file_storage_durable_and_preserves_on_failure() {
        let d = unique_fs_dir("durable");
        let mut s = FileStorage::new(&d).unwrap();
        let seed = Seed::new([0x22u8; 32]);
        save_seed(&mut s, &seed).unwrap();
        assert_eq!(load_seed(&s).unwrap(), Some(seed.clone()));
        let s2 = FileStorage::new(&d).unwrap();
        assert_eq!(load_seed(&s2).unwrap(), Some(seed));
        save_epoch(&mut s, 42).unwrap();
        assert_eq!(load_epoch(&s).unwrap(), Some(42));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    #[cfg(feature = "std")]
    fn file_storage_creates_owner_only_dir_and_private_files() {
        use std::os::unix::fs::PermissionsExt;

        let d = unique_fs_dir("private");
        let mut s = FileStorage::new(&d).unwrap();
        assert_eq!(
            fs::metadata(&d).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        let seed = Seed::new([0x33u8; 32]);
        save_seed(&mut s, &seed).unwrap();
        let seed_path = d.join(keys::IDENTITY_SEED);
        assert_eq!(
            fs::metadata(&seed_path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        save_seed(&mut s, &Seed::new([0x34u8; 32])).unwrap();
        assert_eq!(
            fs::metadata(&seed_path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        let leftovers = fs::read_dir(&d)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.starts_with('.') && name.ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0, "temp files leaked");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    #[cfg(feature = "std")]
    fn file_storage_rejects_world_readable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let d = unique_fs_dir("open-dir");
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(FileStorage::new(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    #[cfg(feature = "std")]
    fn file_storage_rejects_symlinked_directory() {
        use std::os::unix::fs::symlink;

        let real = unique_fs_dir("real-dir");
        make_private_dir(&real);
        let link = unique_fs_dir("linked-dir");
        let _ = fs::remove_file(&link);
        symlink(&real, &link).unwrap();
        assert!(FileStorage::new(&link).is_err());
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
    }

    #[cfg(unix)]
    #[test]
    #[cfg(feature = "std")]
    fn file_storage_requires_existing_parent() {
        let d = unique_fs_dir("orphan").join("child");
        assert!(FileStorage::new(&d).is_err());
    }

    #[cfg(unix)]
    #[test]
    #[cfg(feature = "std")]
    fn file_storage_read_fails_closed_on_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let d = unique_fs_dir("loose-file");
        let mut s = FileStorage::new(&d).unwrap();
        let seed = Seed::new([0x44u8; 32]);
        save_seed(&mut s, &seed).unwrap();
        let seed_path = d.join(keys::IDENTITY_SEED);
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_seed(&s).unwrap_err().kind() == io::ErrorKind::PermissionDenied);
        // Overwriting heals the file: the insecure path is replaced, never read.
        let replacement = Seed::new([0x45u8; 32]);
        save_seed(&mut s, &replacement).unwrap();
        assert_eq!(load_seed(&s).unwrap(), Some(replacement));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    #[cfg(feature = "std")]
    fn file_storage_read_rejects_symlinked_key() {
        use std::os::unix::fs::symlink;

        let d = unique_fs_dir("link-key");
        let mut s = FileStorage::new(&d).unwrap();
        let target = d.join("attacker-control");
        fs::write(&target, [0x5au8; 32]).unwrap();
        let seed_path = d.join(keys::IDENTITY_SEED);
        symlink(&target, &seed_path).unwrap();
        let mut buf = [0u8; 32];
        assert!(s.read(keys::IDENTITY_SEED, &mut buf).is_err());
        assert_eq!(fs::read(&target).unwrap(), [0x5au8; 32]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    #[cfg(feature = "std")]
    fn file_storage_write_replaces_symlinked_key_without_following() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let d = unique_fs_dir("link-swap");
        let mut s = FileStorage::new(&d).unwrap();
        let target = d.join("attacker-control");
        fs::write(&target, [0xaau8; 32]).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let seed_path = d.join(keys::IDENTITY_SEED);
        symlink(&target, &seed_path).unwrap();
        let seed = Seed::new([0x46u8; 32]);
        save_seed(&mut s, &seed).unwrap();
        assert_eq!(load_seed(&s).unwrap(), Some(seed));
        let metadata = fs::symlink_metadata(&seed_path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(fs::read(&target).unwrap(), [0xaau8; 32]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
