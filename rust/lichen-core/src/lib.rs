//! LICHEN protocol primitives.
//!
//! Provides the constants, address types, and shared definitions used by every
//! other crate in the stack. Canonical values are derived from `constants.toml`
//! at the repo root.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod addr;
pub mod announce;
pub mod checksum;
pub mod compact_cot;
pub mod constants;
pub mod duty_cycle;
pub mod error;
pub mod icmpv6;
pub mod ipv6;
pub mod l2_payload;
pub mod loadng;
pub mod rf_health;
pub mod tx_queue;
pub mod udp;

#[cfg(feature = "std")]
extern crate std;

pub fn lichen_hash_32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193u32);
    }
    hash
}

pub fn lichen_select_channel(eui64: &[u8; 8], sfn: u32, density: u8, n_channels: u8) -> u8 {
    if density > 8 {
        return 0;
    }
    let mut data = [0u8; 12];
    data[..8].copy_from_slice(eui64);
    data[8..12].copy_from_slice(&sfn.to_le_bytes());
    let h = lichen_hash_32(&data);
    let n = core::cmp::max(n_channels, 3);
    1 + (h % n as u32) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_channel_hop_sfn0_8ch() {
        let eui64 = [0u8; 8];
        assert_eq!(lichen_select_channel(&eui64, 0, 0, 8), 6);
    }

    #[test]
    fn test_select_channel_ccp16_vec1() {
        let eui64 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert_eq!(lichen_select_channel(&eui64, 1, 3, 3), 2);
    }

    #[test]
    fn test_select_channel_ccp16_vec2() {
        let eui64 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert_eq!(lichen_select_channel(&eui64, 0, 4, 3), 2);
    }

    #[test]
    fn test_select_channel_ccp9_sync_hop() {
        let eui64 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert_eq!(lichen_select_channel(&eui64, 1000, 0, 8), 5);
    }

    #[test]
    fn test_select_channel_density_high_ch0() {
        let eui64 = [0u8; 8];
        assert_eq!(lichen_select_channel(&eui64, 0, 9, 8), 0);
    }

    #[test]
    fn test_select_channel_sfn_wrap() {
        let eui64 = [0u8; 8];
        assert_eq!(lichen_select_channel(&eui64, 0xFFFFFFFF, 0, 8), 2);
    }

    #[test]
    fn test_select_channel_min_channels() {
        let eui64 = [0u8; 8];
        let ch = lichen_select_channel(&eui64, 0, 0, 1);
        assert!(ch >= 1 && ch <= 3);
    }
}
