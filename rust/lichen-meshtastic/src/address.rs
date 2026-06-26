//! Meshtastic node ID ↔ LICHEN IPv6 address mapping.
//!
//! Meshtastic uses 32-bit node IDs while LICHEN uses 128-bit IPv6 addresses
//! derived from Ed25519 public keys. This module provides bidirectional
//! mapping between the two address spaces.
//!
//! For nodes with known public keys (learned from NodeInfo packets), the
//! LICHEN IID is derived from SHA-256(pubkey). For unknown nodes, a synthetic
//! IID is generated that embeds the Meshtastic node ID.

use alloc::vec::Vec;
use hashbrown::HashMap;
use sha2::{Digest, Sha256};

// Re-export Ipv6Addr from lichen-core
pub use lichen_core::addr::Ipv6Addr;

/// Link-local prefix (fe80::/64).
const LINK_LOCAL_PREFIX: [u8; 8] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0];

/// Marker for synthetic IIDs: first 4 bytes are 0x4d_45_53_48 ("MESH").
/// This distinguishes synthetic addresses from real LICHEN addresses.
const SYNTHETIC_MARKER: [u8; 4] = [0x4d, 0x45, 0x53, 0x48];

/// Extension trait for Meshtastic-specific IPv6 address operations.
///
/// Provides methods for working with synthetic addresses that embed
/// Meshtastic node IDs.
pub trait Ipv6AddrMeshtasticExt {
    /// Returns true if this address has a synthetic IID (unknown Meshtastic node).
    fn is_synthetic(&self) -> bool;

    /// Extract the Meshtastic node ID from a synthetic address.
    /// Returns None if this is not a synthetic address.
    fn synthetic_node_id(&self) -> Option<u32>;
}

impl Ipv6AddrMeshtasticExt for Ipv6Addr {
    fn is_synthetic(&self) -> bool {
        self.0[8..12] == SYNTHETIC_MARKER
    }

    fn synthetic_node_id(&self) -> Option<u32> {
        if self.is_synthetic() {
            Some(u32::from_be_bytes([
                self.0[12], self.0[13], self.0[14], self.0[15],
            ]))
        } else {
            None
        }
    }
}

/// Entry storing a node's public key and derived IID.
#[derive(Clone, Debug)]
struct NodeEntry {
    pubkey: [u8; 32],
    iid: [u8; 8],
}

/// Maps between Meshtastic node IDs and LICHEN IPv6 addresses.
///
/// Maintains bidirectional mappings learned from NodeInfo packets.
/// For unknown nodes, generates synthetic addresses that embed the node ID.
#[derive(Debug, Default)]
pub struct AddressMapper {
    /// node_id -> NodeEntry (pubkey + derived IID)
    by_node_id: HashMap<u32, NodeEntry>,
    /// IID -> node_id (for reverse lookups)
    by_iid: HashMap<[u8; 8], u32>,
}

impl AddressMapper {
    /// Create a new empty mapper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Learn a mapping from a NodeInfo packet.
    ///
    /// The public key must be exactly 32 bytes (Ed25519). Invalid keys are
    /// silently ignored.
    pub fn learn_mapping(&mut self, node_id: u32, pubkey: &[u8]) {
        if pubkey.len() != 32 {
            return;
        }

        let mut pk = [0u8; 32];
        pk.copy_from_slice(pubkey);
        let iid = iid_from_pubkey(&pk);

        // Remove old IID mapping if this node had a different key
        if let Some(old) = self.by_node_id.get(&node_id) {
            if old.iid != iid {
                self.by_iid.remove(&old.iid);
            }
        }

        self.by_iid.insert(iid, node_id);
        self.by_node_id.insert(node_id, NodeEntry { pubkey: pk, iid });
    }

    /// Convert a Meshtastic node ID to a LICHEN link-local IPv6 address.
    ///
    /// If the node's public key is known, returns the real LICHEN address.
    /// Otherwise, returns a synthetic address with the node ID embedded.
    pub fn meshtastic_to_ipv6(&self, node_id: u32) -> Ipv6Addr {
        if let Some(entry) = self.by_node_id.get(&node_id) {
            // Known node: use derived IID (flip U/L bit per RFC 4291)
            iid_to_link_local(&entry.iid)
        } else {
            // Unknown node: synthetic address
            synthetic_addr(node_id)
        }
    }

    /// Convert a LICHEN IPv6 address to a Meshtastic node ID.
    ///
    /// Returns Some(node_id) if the address is known or synthetic.
    /// Returns None if the address is not in the mapping.
    pub fn ipv6_to_meshtastic(&self, addr: Ipv6Addr) -> Option<u32> {
        // Check for synthetic address first
        if let Some(node_id) = addr.synthetic_node_id() {
            return Some(node_id);
        }

        // Extract IID and undo the U/L bit flip
        let mut iid = addr.iid();
        iid[0] ^= 0x02;

        self.by_iid.get(&iid).copied()
    }

    /// Get the public key for a node ID, if known.
    pub fn get_pubkey(&self, node_id: u32) -> Option<&[u8; 32]> {
        self.by_node_id.get(&node_id).map(|e| &e.pubkey)
    }

    /// Get all known node IDs.
    pub fn known_nodes(&self) -> Vec<u32> {
        self.by_node_id.keys().copied().collect()
    }

    /// Returns the number of known mappings.
    pub fn len(&self) -> usize {
        self.by_node_id.len()
    }

    /// Returns true if there are no known mappings.
    pub fn is_empty(&self) -> bool {
        self.by_node_id.is_empty()
    }
}

/// Derive a LICHEN IID from an Ed25519 public key.
///
/// IID = SHA-256(pubkey)[0:8] with the U/L bit (bit 1 of byte 0) cleared.
fn iid_from_pubkey(pubkey: &[u8; 32]) -> [u8; 8] {
    let hash = Sha256::digest(pubkey);
    // SAFETY: SHA-256 output is 32 bytes, so [..8] is exactly 8 bytes
    let mut iid: [u8; 8] = hash[..8].try_into().unwrap();
    iid[0] &= 0b1111_1101; // clear U/L bit
    iid
}

/// Convert an IID to a link-local IPv6 address.
///
/// Flips the U/L bit per RFC 4291.
fn iid_to_link_local(iid: &[u8; 8]) -> Ipv6Addr {
    let mut addr = [0u8; 16];
    addr[..8].copy_from_slice(&LINK_LOCAL_PREFIX);
    addr[8..16].copy_from_slice(iid);
    addr[8] ^= 0x02; // flip U/L bit
    Ipv6Addr(addr)
}

/// Generate a synthetic link-local address for an unknown node.
///
/// Format: fe80::4d45:5348:XXXX:XXXX where XXXX:XXXX is the node ID.
/// The "MESH" marker (0x4d455348) distinguishes synthetic addresses.
fn synthetic_addr(node_id: u32) -> Ipv6Addr {
    let id_bytes = node_id.to_be_bytes();
    Ipv6Addr([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0,                    // link-local prefix
        SYNTHETIC_MARKER[0], SYNTHETIC_MARKER[1],        // "ME"
        SYNTHETIC_MARKER[2], SYNTHETIC_MARKER[3],        // "SH"
        id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3], // node_id
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iid_from_pubkey_clears_ul_bit() {
        let pubkey = [0u8; 32];
        let iid = iid_from_pubkey(&pubkey);
        assert_eq!(iid[0] & 0x02, 0, "U/L bit must be cleared");
    }

    #[test]
    fn test_iid_deterministic() {
        let pk = [0xab; 32];
        assert_eq!(iid_from_pubkey(&pk), iid_from_pubkey(&pk));
    }

    #[test]
    fn test_synthetic_addr_format() {
        let addr = synthetic_addr(0x12345678);
        assert_eq!(&addr.0[0..8], &LINK_LOCAL_PREFIX);
        assert_eq!(&addr.0[8..12], &SYNTHETIC_MARKER);
        assert_eq!(&addr.0[12..16], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_synthetic_addr_roundtrip() {
        let node_id = 0xDEADBEEF;
        let addr = synthetic_addr(node_id);
        assert!(addr.is_synthetic());
        assert_eq!(addr.synthetic_node_id(), Some(node_id));
    }

    #[test]
    fn test_learn_mapping_and_lookup() {
        let mut mapper = AddressMapper::new();
        let node_id = 0x12345678u32;
        let pubkey = [0xAB; 32];

        mapper.learn_mapping(node_id, &pubkey);

        // Forward lookup
        let addr = mapper.meshtastic_to_ipv6(node_id);
        assert!(!addr.is_synthetic(), "Known node should not have synthetic addr");

        // Reverse lookup
        let result = mapper.ipv6_to_meshtastic(addr);
        assert_eq!(result, Some(node_id));
    }

    #[test]
    fn test_unknown_node_gets_synthetic() {
        let mapper = AddressMapper::new();
        let node_id = 0x87654321u32;

        let addr = mapper.meshtastic_to_ipv6(node_id);
        assert!(addr.is_synthetic());
        assert_eq!(addr.synthetic_node_id(), Some(node_id));
    }

    #[test]
    fn test_synthetic_reverse_lookup() {
        let mapper = AddressMapper::new();
        let node_id = 0xCAFEBABE;

        let addr = mapper.meshtastic_to_ipv6(node_id);
        let result = mapper.ipv6_to_meshtastic(addr);
        assert_eq!(result, Some(node_id));
    }

    #[test]
    fn test_invalid_pubkey_ignored() {
        let mut mapper = AddressMapper::new();
        let node_id = 123u32;

        // Too short
        mapper.learn_mapping(node_id, &[0u8; 16]);
        assert!(mapper.is_empty());

        // Too long
        mapper.learn_mapping(node_id, &[0u8; 64]);
        assert!(mapper.is_empty());
    }

    #[test]
    fn test_relearn_with_different_key() {
        let mut mapper = AddressMapper::new();
        let node_id = 42u32;
        let pubkey1 = [0x11; 32];
        let pubkey2 = [0x22; 32];

        mapper.learn_mapping(node_id, &pubkey1);
        let addr1 = mapper.meshtastic_to_ipv6(node_id);

        mapper.learn_mapping(node_id, &pubkey2);
        let addr2 = mapper.meshtastic_to_ipv6(node_id);

        // Addresses should differ
        assert_ne!(addr1, addr2);

        // Old address should no longer resolve
        assert_eq!(mapper.ipv6_to_meshtastic(addr1), None);

        // New address should resolve
        assert_eq!(mapper.ipv6_to_meshtastic(addr2), Some(node_id));
    }

    #[test]
    fn test_get_pubkey() {
        let mut mapper = AddressMapper::new();
        let node_id = 99u32;
        let pubkey = [0x55; 32];

        assert_eq!(mapper.get_pubkey(node_id), None);

        mapper.learn_mapping(node_id, &pubkey);
        assert_eq!(mapper.get_pubkey(node_id), Some(&pubkey));
    }

    #[test]
    fn test_known_nodes() {
        let mut mapper = AddressMapper::new();
        mapper.learn_mapping(1, &[0x11; 32]);
        mapper.learn_mapping(2, &[0x22; 32]);
        mapper.learn_mapping(3, &[0x33; 32]);

        let mut nodes = mapper.known_nodes();
        nodes.sort();
        assert_eq!(nodes, vec![1, 2, 3]);
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut mapper = AddressMapper::new();
        assert!(mapper.is_empty());
        assert_eq!(mapper.len(), 0);

        mapper.learn_mapping(1, &[0x11; 32]);
        assert!(!mapper.is_empty());
        assert_eq!(mapper.len(), 1);
    }

    #[test]
    fn test_ipv6_addr_iid() {
        let addr = Ipv6Addr([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]);
        assert_eq!(addr.iid(), [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_non_synthetic_has_no_node_id() {
        let mut mapper = AddressMapper::new();
        mapper.learn_mapping(123, &[0xAA; 32]);
        let addr = mapper.meshtastic_to_ipv6(123);
        assert!(!addr.is_synthetic());
        assert_eq!(addr.synthetic_node_id(), None);
    }
}
