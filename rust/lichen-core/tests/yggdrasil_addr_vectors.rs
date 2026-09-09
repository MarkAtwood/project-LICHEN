//! Tests against the shared corpora in test/vectors/yggdrasil_address.json
//! (live) and test/vectors/legacy/yggdrasil_address_native_sha512.json
//! (QUARANTINED).
//!
//! Post-migration (i72x.2, spec/decisions.jsonl `upstream-yggdrasil-addressing`):
//! [`ygg_addr_from_pubkey`] MUST equal upstream yggdrasil-go `AddrForKey`
//! byte-for-byte; the corpus anchor (`upstream_addr_for_key`) is the pinned
//! external oracle from upstream `address_test.go` @422836ee, and
//! [`subnet_for_key`] MUST equal upstream `SubnetForKey` (0300::/8).
//!
//! The `lichen_native_sha512` profile is REJECTED. Its vectors are
//! quarantined in the legacy file and are consumed here ONLY as a
//! corpus-integrity pin (presence and count, checked by `corpus_shape`),
//! never as a conformance oracle and never driven through the implementation:
//! the pre-migration byte-exact pin test and the `assert_ne!` divergence test
//! were deleted when the upstream AddrForKey migration landed, exactly as
//! their own comments required (see test/vectors/legacy/README.md).
//!
//! `error_case` length rejections (live corpus) are not expressible here
//! because the Rust API takes `&[u8; 32]`, which enforces key length at the
//! type level.
//!
//! Upstream degenerate-key semantics (all-zero public key -> inverted
//! all-ones -> leading-1 count wraps 256 -> 0, no separator bit, empty
//! payload) are pinned by the external-oracle edge-class table in
//! `upstream_edge_classes`; the migration branch's standalone unit check of
//! that case is subsumed there (same bytes, stronger oracle) and is not
//! duplicated.
//!
//! Merge note (beads-worker-5): the two sides are incompatible — the branch
//! pinned PRE-migration behavior (`quarantined_native_vectors_byte_exact_pin`
//! driving the rejected SHA-512 profile byte-exact, and
//! `upstream_anchor_diverges_from_current_native_profile` asserting
//! `assert_ne!` against the upstream anchor), while HEAD asserts the
//! post-migration `assert_eq!` byte-equality that spec/decisions.jsonl
//! `upstream-yggdrasil-addressing` settles. HEAD's side is kept because the
//! implementation now bit-packs per upstream (so the branch's pins would
//! fail) and the branch's own comments required deleting those tests once
//! the migration landed.

use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/yggdrasil_address.json");
const LEGACY_NATIVE_JSON: &str =
    include_str!("../../../test/vectors/legacy/yggdrasil_address_native_sha512.json");

const ANCHOR_NAME: &str = "upstream_addr_for_key";
// Pinned external oracle, from upstream yggdrasil-go address_test.go
// @422836ee for pubkey bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb.
const ANCHOR_ADDRESS: [u8; 16] = [
    0x02, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e, 0x43, 0x84, 0x65, 0xdb, 0x8d, 0xb6, 0x68, 0x95,
];
/// Upstream `SubnetForKey` for the anchor key, from `address_test.go` @422836ee.
const ANCHOR_SUBNET: [u8; 8] = [0x03, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e];

fn load_document() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("yggdrasil_address.json must parse")
}

fn load_legacy_document() -> Value {
    serde_json::from_str(LEGACY_NATIVE_JSON)
        .expect("legacy/yggdrasil_address_native_sha512.json must parse")
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

fn legacy_native_vectors(document: &Value) -> Vec<&Value> {
    document["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .filter(|v| v["profile"] == "lichen_native_sha512")
        .collect()
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
    assert_eq!(
        vectors.len(),
        error_cases + 1,
        "live corpus must hold exactly the anchor plus the error cases"
    );
    // The rejected native profile must not leak back into the live corpus.
    assert!(
        vectors.iter().all(|v| v["profile"] != "lichen_native_sha512"),
        "live corpus must not hold rejected native-profile vectors"
    );
    let legacy = load_legacy_document();
    assert!(
        legacy_native_vectors(&legacy).len() >= 10,
        "quarantined native corpus must keep its vectors verbatim"
    );
}

#[test]
fn upstream_anchor_matches_byte_exact() {
    // Conformance oracle per spec/decisions.jsonl upstream-yggdrasil-addressing:
    // the corpus anchor bytes come verbatim from upstream address_test.go.
    // (This is the flipped-to-byte-equality successor of the pre-migration
    // `assert_ne!` divergence pin, which HEAD required to flip on landing.)
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
    // SubnetForKey = AddrForKey first 8 bytes with the low prefix bit set.
    let pubkey_vec = decode_hex(anchor(&load_document())["public_key"].as_str().unwrap());
    let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
    let subnet = lichen_core::addr::subnet_for_key(&pubkey);
    assert_eq!(
        subnet, ANCHOR_SUBNET,
        "MUST equal upstream SubnetForKey byte-for-byte (0300::/8)"
    );
    // Subnet lives in 0300::/8 (prefix byte low bit set).
    assert_eq!(subnet[0] & 0x01, 0x01, "subnet prefix bit must be set");
    // And shares the leading-1 count byte with the address.
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(subnet[1], addr[1], "subnet and address share leading-1 count");
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
    // Pin the separation this test's name claims: the routable address's low
    // 64 bits are bit-packed inverted key, NOT the SHA-512 IID.
    assert_ne!(
        &addr[8..16],
        &iid[..],
        "routable address must NOT embed the SHA-512 IID"
    );
}
