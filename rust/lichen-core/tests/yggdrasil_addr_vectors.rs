//! Tests against the shared corpus in test/vectors/yggdrasil_address.json.
//!
//! Per spec/decisions.jsonl upstream-yggdrasil-addressing, a node's routable
//! address MUST equal upstream Yggdrasil `AddrForKey(Ed25519PublicKey)` and a
//! routed /64 subnet MUST equal upstream `SubnetForKey` in `0300::/8`. The
//! implementation under test IS the upstream algorithm; the single upstream
//! yggdrasil-go anchor (`upstream_addr_for_key`) is the pinned external
//! oracle, kept verbatim, and MUST match byte-for-byte.
//!
//! The former `lichen_native_sha512` profile is REJECTED; its vectors are
//! quarantined in test/vectors/legacy/yggdrasil_address_native_sha512.json and
//! are NOT consumed here (they assert a derivation that no longer exists).
//!
//! Entry kinds:
//! 1. The upstream anchor — byte-equality for both address and subnet.
//! 2. `error_case` length rejections (live corpus) — not expressible here
//!    because the Rust API takes `&[u8; 32]`, which enforces key length at
//!    the type level.
//! 3. A unit-level check of the upstream degenerate-key semantics (all-zero
//!    public key → inverted all-ones → no separator bit → empty payload).

use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/yggdrasil_address.json");

const ANCHOR_NAME: &str = "upstream_addr_for_key";
// Pinned external oracle, from upstream yggdrasil-go address_test.go
// @422836ee for pubkey bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb.
const ANCHOR_ADDRESS: [u8; 16] = [
    0x02, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e, 0x43, 0x84, 0x65, 0xdb, 0x8d, 0xb6, 0x68, 0x95,
];
const ANCHOR_SUBNET: [u8; 8] = [0x03, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e];

fn load_document() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("yggdrasil_address.json must parse")
}

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

fn anchor_vector(document: &Value) -> &Value {
    document["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|v| v["name"] == ANCHOR_NAME)
        .expect("anchor present")
}

#[test]
fn corpus_shape() {
    let document = load_document();
    let vectors = document["vectors"].as_array().unwrap();
    assert_eq!(
        vectors.iter().filter(|v| v["name"] == ANCHOR_NAME).count(),
        1,
        "exactly one upstream anchor expected"
    );
    let error_cases = vectors
        .iter()
        .filter(|v| v["expect_error"] == "pubkey_length")
        .count();
    assert!(error_cases >= 2, "length-rejection cases expected");
    // The rejected native profile must not leak back into the live corpus.
    assert!(
        vectors.iter().all(|v| v["profile"] != "lichen_native_sha512"),
        "live corpus must not hold rejected native-profile vectors"
    );
}

#[test]
fn upstream_addr_for_key_byte_equality() {
    // The implementation under test IS upstream AddrForKey; the anchor is the
    // pinned external oracle (upstream address_test.go @422836ee). This MUST
    // hold byte-for-byte.
    let document = load_document();
    let anchor = anchor_vector(&document);
    let expected = decode_hex(anchor["address"].as_str().unwrap());
    assert_eq!(&expected[..], &ANCHOR_ADDRESS[..]);

    let pubkey_vec = decode_hex(anchor["public_key"].as_str().unwrap());
    let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
    let derived = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(
        &derived[..],
        &ANCHOR_ADDRESS[..],
        "ygg_addr_from_pubkey must equal upstream AddrForKey byte-for-byte"
    );
}

#[test]
fn upstream_subnet_for_key_byte_equality() {
    // SubnetForKey = AddrForKey first 8 bytes with the low prefix bit set.
    let document = load_document();
    let anchor = anchor_vector(&document);
    let pubkey_vec = decode_hex(anchor["public_key"].as_str().unwrap());
    let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
    let subnet = lichen_core::addr::subnet_for_key(&pubkey);
    assert_eq!(
        &subnet[..],
        &ANCHOR_SUBNET[..],
        "subnet_for_key must equal upstream SubnetForKey byte-for-byte"
    );
    // Subnet lives in 0300::/8 (prefix byte low bit set).
    assert_eq!(subnet[0] & 0x01, 0x01, "subnet prefix bit must be set");
    // And shares the leading-1 count byte with the address.
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(subnet[1], addr[1], "subnet and address share leading-1 count");
}

#[test]
fn degenerate_all_zero_key_matches_upstream_semantics() {
    // All-zero public key -> inverted key is all 1 bits -> 256 leading ones,
    // which wraps to 0 in a u8 (Go `byte` overflow), and no separator 0 bit is
    // ever seen, so no payload bits are appended. Result: [0x02, 0x00, 0; 14].
    let pubkey = [0u8; 32];
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(addr[0], 0x02, "prefix byte");
    assert_eq!(addr[1], 0x00, "leading-1 count wraps 256 -> 0");
    assert!(
        addr[2..].iter().all(|&b| b == 0),
        "no separator bit -> no payload bytes appended"
    );
}

#[test]
fn prefix_byte_and_no_iid_embedding() {
    // Routable address carries no SHA-512 IID in its lower 64 bits.
    let document = load_document();
    let anchor = anchor_vector(&document);
    let pubkey_vec = decode_hex(anchor["public_key"].as_str().unwrap());
    let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    let iid = lichen_core::addr::iid_from_pubkey_bytes(&pubkey);
    assert_eq!(addr[0], 0x02, "0200::/8 prefix byte");
    assert_ne!(
        &addr[8..16],
        &iid[..],
        "routable address must NOT embed the SHA-512 IID"
    );
}
