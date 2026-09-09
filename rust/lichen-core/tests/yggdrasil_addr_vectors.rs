//! Tests for the upstream Yggdrasil address derivations (i72x.2).
//!
//! Per the settled `upstream-yggdrasil-addressing` decision, the routable
//! /128 derivation is EXACT upstream `AddrForKey` and routed /64 prefixes
//! are upstream `SubnetForKey`. The conformance oracle is byte-equality
//! against pinned upstream vectors (yggdrasil-go@422836ee
//! src/address/address_test.go), cross-checked by an independent Python
//! port of the Go algorithm — NEVER derived from the Rust implementation.
//!
//! The shared corpus test/vectors/yggdrasil_address.json is intentionally
//! UNTOUCHED here (worker-2 collision avoidance); its regeneration is
//! i72x.6. The `iid_from_pubkey_bytes` SHA-512 IID is retained for
//! link-local per the settled decision and pinned below as a legacy
//! profile test.

use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/yggdrasil_address.json");

/// Upstream anchor (address_test.go @422836ee): AddrForKey for this pubkey.
const ANCHOR_PUBKEY: &str = "bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb";
const ANCHOR_ADDRESS: [u8; 16] = [
    0x02, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e, 0x43, 0x84, 0x65, 0xdb, 0x8d, 0xb6, 0x68, 0x95,
];
const ANCHOR_SUBNET: [u8; 8] = [0x03, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e];

// usize::is_multiple_of stabilized in Rust 1.87; the workspace MSRV is 1.81
// (Cargo.toml rust-version), so keep the modulo form here.
#[allow(clippy::manual_is_multiple_of)]
fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "odd-length hex: {value}");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// The corpus still carries the anchor entry; pin that the bytes the
/// corpus advertises equal the upstream test-vector constants, so a corpus
/// edit that diverges from upstream fails here.
#[test]
fn corpus_anchor_matches_upstream_constants() {
    let document: Value =
        serde_json::from_str(VECTORS_JSON).expect("yggdrasil_address.json must parse");
    let anchor = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "upstream_addr_for_key")
        .expect("anchor present");
    assert_eq!(anchor["public_key"].as_str().unwrap(), ANCHOR_PUBKEY);
    assert_eq!(
        decode_hex(anchor["address"].as_str().unwrap()),
        ANCHOR_ADDRESS
    );
}

#[test]
fn addr_for_key_matches_upstream_anchor() {
    let pubkey: [u8; 32] = decode_hex(ANCHOR_PUBKEY).try_into().expect("32-byte key");
    assert_eq!(lichen_core::addr::ygg_addr_from_pubkey(&pubkey), ANCHOR_ADDRESS);
}

#[test]
fn subnet_for_key_matches_upstream_anchor() {
    let pubkey: [u8; 32] = decode_hex(ANCHOR_PUBKEY).try_into().expect("32-byte key");
    assert_eq!(lichen_core::addr::subnet_for_key(&pubkey), ANCHOR_SUBNET);
}

#[test]
fn addr_for_key_leading_ones_counted_in_byte_one() {
    // Inverted key 0xff 0x7f ... => 8 leading ones, first zero at bit 8.
    // Byte 1 of the address is the leading-ones count (8); remaining bits
    // after the first zero pack from the 0x3f... tail.
    let mut pubkey = [0xdeu8; 32];
    pubkey[0] = !0xff;
    pubkey[1] = !0x7f;
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(addr[0], 0x02);
    assert_eq!(addr[1], 8);
    // After the first zero the packed bits are the 0x7f low bits then the
    // 0x21 (0b0010_0001) tail: 111_1111 0010_0001 ... => 0xfe 0x42 ...
    assert_eq!(addr[2], 0xfe);
    assert_eq!(addr[3], 0x42);
}

#[test]
fn addr_for_key_degenerate_all_zero_key_wraps_count_and_zero_packs() {
    // pubkey all 0x00 => inverted all 0xff: 256 leading ones wrap to 0,
    // no first zero, nothing packs.
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&[0x00; 32]);
    assert_eq!(addr[0], 0x02);
    assert_eq!(addr[1], 0, "Go byte counter wraps 256 -> 0");
    assert_eq!(&addr[2..], &[0u8; 14]);
}

#[test]
fn addr_for_key_trailing_partial_byte_discarded() {
    // Inverted key with first zero at bit 0 (inverted[0] top bit clear,
    // i.e. pubkey[0] top bit set): 254 bits remain = 31 whole bytes + 6
    // trailing bits, which MUST be discarded; only 14 bytes fit the
    // address regardless.
    let mut pubkey = [0x00u8; 32];
    pubkey[0] = 0x80; // inverted 0x7f: first zero at bit 0
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(addr[1], 0);
    // Packed bits are the remaining 0x7f low bits then all-ones inverted
    // tail: 0b111_1111 1111_1111 ... => 0xff everywhere in the window.
    assert_eq!(&addr[2..], &[0xff; 14]);
}

#[test]
fn iid_retains_sha512_legacy_profile() {
    // The SHA-512 IID is retained for link-local per the settled decision.
    // Pinned from the SHA-512 of the anchor pubkey (independent oracle:
    // sha2 crate against Python hashlib, see test comment history).
    let pubkey: [u8; 32] = decode_hex(ANCHOR_PUBKEY).try_into().expect("32-byte key");
    let iid = lichen_core::addr::iid_from_pubkey_bytes(&pubkey);
    assert_eq!(iid[0] & 0x02, 0, "U/L bit must be clear in IID");
    // The routable address no longer embeds the IID (settled migration):
    // this MUST NOT hold, and pinning the divergence guards the sweep.
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_ne!(&addr[8..16], &iid[..]);
}
