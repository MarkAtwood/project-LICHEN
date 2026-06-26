//! Persistent identity storage using NonVolatile trait.
//!
//! Stores:
//! - Identity seed (32 bytes) → derives keypair on load
//! - Peer table (pubkeys for signature verification)
//! - Link layer sequence numbers (for replay protection continuity)

use crate::NonVolatile;

/// Key names for persistent storage.
pub mod keys {
    pub const IDENTITY_SEED: &str = "id.seed";
    pub const EPOCH: &str = "id.epoch";
    pub const SEQNUM: &str = "id.seq";
    pub const PEER_COUNT: &str = "peers.n";
}

/// Maximum number of peers to persist.
pub const MAX_PEERS: usize = 16;

/// Get peer key name for index.
pub fn peer_key(index: usize) -> heapless::String<16> {
    let mut s = heapless::String::new();
    core::fmt::write(&mut s, format_args!("peer.{}", index)).ok();
    s
}

/// Load identity seed from storage.
///
/// Returns `Some(seed)` if found and valid, `None` otherwise.
pub fn load_seed<S: NonVolatile>(storage: &S) -> Option<[u8; 32]> {
    let mut buf = [0u8; 32];
    let n = storage.read(keys::IDENTITY_SEED, &mut buf)?;
    if n == 32 {
        Some(buf)
    } else {
        None
    }
}

/// Save identity seed to storage.
pub fn save_seed<S: NonVolatile>(storage: &mut S, seed: &[u8; 32]) -> Result<(), S::Error> {
    storage.write(keys::IDENTITY_SEED, seed)
}

/// Load link layer epoch from storage.
pub fn load_epoch<S: NonVolatile>(storage: &S) -> Option<u8> {
    let mut buf = [0u8; 1];
    let n = storage.read(keys::EPOCH, &mut buf)?;
    if n == 1 {
        Some(buf[0])
    } else {
        None
    }
}

/// Save link layer epoch to storage.
pub fn save_epoch<S: NonVolatile>(storage: &mut S, epoch: u8) -> Result<(), S::Error> {
    storage.write(keys::EPOCH, &[epoch])
}

/// Load link layer sequence number from storage.
pub fn load_seqnum<S: NonVolatile>(storage: &S) -> Option<u16> {
    let mut buf = [0u8; 2];
    let n = storage.read(keys::SEQNUM, &mut buf)?;
    if n == 2 {
        Some(u16::from_be_bytes(buf))
    } else {
        None
    }
}

/// Save link layer sequence number to storage.
pub fn save_seqnum<S: NonVolatile>(storage: &mut S, seqnum: u16) -> Result<(), S::Error> {
    storage.write(keys::SEQNUM, &seqnum.to_be_bytes())
}

/// Load peer count from storage.
pub fn load_peer_count<S: NonVolatile>(storage: &S) -> usize {
    let mut buf = [0u8; 1];
    storage
        .read(keys::PEER_COUNT, &mut buf)
        .map(|n| if n == 1 { buf[0] as usize } else { 0 })
        .unwrap_or(0)
}

/// Load a peer pubkey from storage.
pub fn load_peer<S: NonVolatile>(storage: &S, index: usize) -> Option<[u8; 32]> {
    if index >= MAX_PEERS {
        return None;
    }
    let key = peer_key(index);
    let mut buf = [0u8; 32];
    let n = storage.read(&key, &mut buf)?;
    if n == 32 {
        Some(buf)
    } else {
        None
    }
}

/// Save peer table to storage.
///
/// Overwrites existing peers. Pass a slice of pubkeys.
pub fn save_peers<S: NonVolatile>(storage: &mut S, peers: &[[u8; 32]]) -> Result<(), S::Error> {
    let count = peers.len().min(MAX_PEERS);
    storage.write(keys::PEER_COUNT, &[count as u8])?;
    for (i, pubkey) in peers.iter().take(count).enumerate() {
        let key = peer_key(i);
        storage.write(&key, pubkey)?;
    }
    Ok(())
}

/// In-memory NonVolatile implementation for testing.
#[cfg(any(test, feature = "std"))]
pub mod mem {
    extern crate std;
    use std::collections::HashMap;
    use std::string::String;
    use std::vec::Vec;

    use crate::NonVolatile;

    /// In-memory storage for testing.
    #[derive(Debug, Default, Clone)]
    pub struct MemStorage {
        data: HashMap<String, Vec<u8>>,
    }

    impl MemStorage {
        pub fn new() -> Self {
            Self::default()
        }

        /// Simulate reboot by clearing volatile state but keeping persisted data.
        pub fn clear_volatile(&mut self) {
            // No-op for MemStorage since it's all "persistent"
        }
    }

    impl NonVolatile for MemStorage {
        type Error = core::convert::Infallible;

        fn read(&self, key: &str, buf: &mut [u8]) -> Option<usize> {
            let data = self.data.get(key)?;
            let n = data.len().min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Some(n)
        }

        fn write(&mut self, key: &str, data: &[u8]) -> Result<(), Self::Error> {
            self.data.insert(key.into(), data.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &str) -> bool {
            self.data.remove(key).is_some()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mem::MemStorage;

    #[test]
    fn seed_round_trip() {
        let mut storage = MemStorage::new();
        let seed = [0xABu8; 32];

        assert!(load_seed(&storage).is_none());
        save_seed(&mut storage, &seed).unwrap();
        assert_eq!(load_seed(&storage), Some(seed));
    }

    #[test]
    fn epoch_seqnum_round_trip() {
        let mut storage = MemStorage::new();

        assert!(load_epoch(&storage).is_none());
        assert!(load_seqnum(&storage).is_none());

        save_epoch(&mut storage, 5).unwrap();
        save_seqnum(&mut storage, 12345).unwrap();

        assert_eq!(load_epoch(&storage), Some(5));
        assert_eq!(load_seqnum(&storage), Some(12345));
    }

    #[test]
    fn peers_round_trip() {
        let mut storage = MemStorage::new();
        let peers = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];

        assert_eq!(load_peer_count(&storage), 0);
        save_peers(&mut storage, &peers).unwrap();

        assert_eq!(load_peer_count(&storage), 3);
        assert_eq!(load_peer(&storage, 0), Some([0x01u8; 32]));
        assert_eq!(load_peer(&storage, 1), Some([0x02u8; 32]));
        assert_eq!(load_peer(&storage, 2), Some([0x03u8; 32]));
        assert!(load_peer(&storage, 3).is_none());
    }

    #[test]
    fn seed_survives_simulated_reboot() {
        let mut storage = MemStorage::new();
        let seed = [0xDEu8; 32];
        save_seed(&mut storage, &seed).unwrap();

        // Simulate "reboot" - data persists
        storage.clear_volatile();
        assert_eq!(load_seed(&storage), Some(seed));
    }
}
