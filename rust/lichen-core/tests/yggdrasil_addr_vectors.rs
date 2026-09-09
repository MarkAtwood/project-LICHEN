//! Tests against the shared corpus in test/vectors/yggdrasil_address.json.
//!
//! Post-migration (i72x.2, `upstream-yggdrasil-addressing` decision):
//! [`ygg_addr_from_pubkey`] MUST equal upstream yggdrasil-go `AddrForKey`
//! byte-for-byte; the corpus anchor (`upstream_addr_for_key`) is the pinned
//! external oracle from upstream `address_test.go` @422836ee.
//!
//! The `lichen_native_sha512` vectors in the corpus encode the REJECTED
//! SHA-512 native profile and are intentionally not consumed here anymore;
//! quarantining them out of the live corpus is tracked by q6ko.2/i72x.6.
//! `error_case` length rejections are not expressible here because the Rust
//! API takes `&[u8; 32]`, which enforces key length at the type level.

use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/yggdrasil_address.json");

const ANCHOR_NAME: &str = "upstream_addr_for_key";
const ANCHOR_ADDRESS: [u8; 16] = [
    0x02, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e, 0x43, 0x84, 0x65, 0xdb, 0x8d, 0xb6, 0x68, 0x95,
];
/// Upstream `SubnetForKey` for the anchor key, from `address_test.go` @422836ee.
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

fn anchor(document: &Value) -> &Value {
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
    assert!(
        vectors.iter().any(|v| v["expect_error"] == "pubkey_length"),
        "length-rejection cases expected"
    );
}

#[test]
fn upstream_anchor_matches_byte_exact() {
    // Conformance oracle per spec/decisions.jsonl upstream-yggdrasil-addressing:
    // the corpus anchor bytes come verbatim from upstream address_test.go.
    let document = load_document();
    let expected = decode_hex(anchor(&document)["address"].as_str().unwrap());
    assert_eq!(&expected[..], &ANCHOR_ADDRESS[..]);

    let pubkey_vec = decode_hex(anchor(&document)["public_key"].as_str().unwrap());
    let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
    let derived = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(
        &derived[..],
        &ANCHOR_ADDRESS[..],
        "MUST equal upstream AddrForKey byte-for-byte"
    );
}

#[test]
fn upstream_subnet_anchor_matches_byte_exact() {
    let pubkey_vec = decode_hex(anchor(&load_document())["public_key"].as_str().unwrap());
    let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
    assert_eq!(
        lichen_core::addr::subnet_for_key(&pubkey),
        ANCHOR_SUBNET,
        "MUST equal upstream SubnetForKey byte-for-byte (0300::/8)"
    );
}

/// Test-local pins produced by running upstream's own `address.go` @422836ee
/// (external oracle — never this crate) over edge-class keys. These cover the
/// oracle gaps the anchor alone misses: addr[1] != 0, the degenerate ones-count
/// wrap, and trailing-partial-byte discard. Shared-corpus enrichment with these
/// classes is tracked in q6ko/i72x.6.
#[test]
fn upstream_edge_classes() {
    let cases: [(&str, &str); 6] = [
        // Inverted key starts with 6 leading 1 bits (0x02 -> 0xfd = 11111101..).
        (
            "0202020202020202020202020202020202020202020202020202020202020202",
            "0206fefefefefefefefefefefefefefe",
        ),
        // Inverted key starts with 7 leading 1 bits (0x01 -> 0xfe).
        (
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0207fefefefefefefefefefefefefefe",
        ),
        // Degenerate: inverted key is 256 one-bits; upstream's byte counter
        // wraps 256 -> 0 and no payload bits are packed.
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "02000000000000000000000000000000",
        ),
        // Inverted key is all zero bits: ones = 0, first 0 consumed, remaining
        // 255 zero bits pack to 31 zero bytes with the tail discarded; the
        // address keeps only 14 zero bytes.
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "02000000000000000000000000000000",
        ),
        // Mixed remainder with a discarded trailing partial byte (255 payload
        // bits -> 31 whole bytes, last 7 bits dropped).
        (
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
            "020042a482206a028a8242a482206a02",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0200aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    ];
    for (pubkey_hex, expected_hex) in cases {
        let pubkey_vec = decode_hex(pubkey_hex);
        let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
        let expected = decode_hex(expected_hex);
        assert_eq!(
            lichen_core::addr::ygg_addr_from_pubkey(&pubkey)[..],
            expected[..],
            "{pubkey_hex}"
        );
    }
}

#[test]
fn iid_remains_sha512_derived_not_address_low_half() {
    // The link-local IID is unchanged (SHA-512(pubkey)[0:8], U/L cleared).
    // Upstream addresses bit-pack the inverted key, so the old
    // addr[8:16] == IID invariant is dead by decision; pin the separation.
    let document = load_document();
    let pubkey_vec = decode_hex(anchor(&document)["public_key"].as_str().unwrap());
    let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
    let iid = lichen_core::addr::iid_from_pubkey_bytes(&pubkey);
    assert_eq!(iid[0] & 0x02, 0, "U/L bit must be clear in IID");
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(addr[0], 0x02, "0200::/8 prefix byte");
}
