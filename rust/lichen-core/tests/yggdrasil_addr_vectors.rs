//! Tests against the shared corpora in test/vectors/yggdrasil_address.json
//! (live) and test/vectors/legacy/yggdrasil_address_native_sha512.json
//! (QUARANTINED).
//!
//! Per spec/decisions.jsonl upstream-yggdrasil-addressing, a node's routable
//! address MUST equal upstream Yggdrasil `AddrForKey(Ed25519PublicKey)`. The
//! upstream AddrForKey migration has landed; the anchor test below pins the
//! implementation byte-for-byte against the verbatim upstream
//! address_test.go vector (external oracle).
//!
//! Three entry kinds:
//! 1. The single upstream yggdrasil-go anchor (`upstream_addr_for_key`) —
//!    the pinned external oracle, kept verbatim; byte-equality conformance.
//! 2. QUARANTINED `lichen_native_sha512` cases — checked against a
//!    test-local transcription of the rejected pre-migration profile
//!    ([`native_profile_reference`]), never against the live implementation.
//!    They pin the quarantined file's bytes as data integrity only.
//! 3. `error_case` length rejections (live corpus) — not expressible here
//!    because the Rust API takes `&[u8; 32]`, which enforces key length at
//!    the type level.

mod native_profile_reference;

use native_profile_reference::native_sha512_addr;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/yggdrasil_address.json");
const LEGACY_NATIVE_JSON: &str =
    include_str!("../../../test/vectors/legacy/yggdrasil_address_native_sha512.json");

const ANCHOR_NAME: &str = "upstream_addr_for_key";
const ANCHOR_ADDRESS: [u8; 16] = [
    0x02, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e, 0x43, 0x84, 0x65, 0xdb, 0x8d, 0xb6, 0x68, 0x95,
];
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
    // Non-error vectors are the anchor (which carries no profile field)
    // plus any upstream-profile entries; the corpus may grow (e.g.
    // shared-fixture keys) but every entry must carry the upstream profile.
    let upstream_cases = vectors
        .iter()
        .filter(|v| v["profile"] == "upstream_addr_for_key")
        .count();
    assert!(upstream_cases >= 10, "upstream derivation corpus expected");
    assert_eq!(
        vectors.len(),
        error_cases + upstream_cases + 1,
        "live corpus must hold only the anchor, upstream-profile vectors, and error cases"
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
fn upstream_anchor_byte_equality() {
    // External oracle from upstream address_test.go @422836ee, pinned
    // verbatim in the live corpus. Per spec/decisions.jsonl
    // upstream-yggdrasil-addressing the implementation MUST match it
    // byte-for-byte.
    let document = load_document();
    let anchor = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == ANCHOR_NAME)
        .expect("anchor present");
    let expected = decode_hex(anchor["address"].as_str().unwrap());
    assert_eq!(&expected[..], &ANCHOR_ADDRESS[..]);

    let pubkey_vec = decode_hex(anchor["public_key"].as_str().unwrap());
    let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
    let derived = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(&derived[..], &ANCHOR_ADDRESS[..]);

    let subnet = lichen_core::addr::subnet_for_key(&pubkey);
    assert_eq!(&subnet[..], &ANCHOR_SUBNET[..]);
}

#[test]
fn quarantined_native_vectors_pin_rejected_profile_data() {
    // DATA-INTEGRITY PIN of the QUARANTINED corpus, not a conformance
    // oracle: the rejected SHA-512 native profile is checked against a
    // test-local transcription ([`native_profile_reference`]), never
    // against the live implementation, which now derives upstream
    // AddrForKey (spec/decisions.jsonl upstream-yggdrasil-addressing).
    for vector in legacy_native_vectors(&load_legacy_document()) {
        let name = vector["name"].as_str().unwrap();
        let pubkey_vec = decode_hex(vector["public_key"].as_str().unwrap());
        let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
        let expected = decode_hex(vector["address"].as_str().unwrap());

        let addr = native_sha512_addr(&pubkey);
        assert_eq!(&addr[..], &expected[..], "{name}");

        assert_eq!(addr[0], 0x02, "{name}: 0200::/8 prefix byte");
    }
}
