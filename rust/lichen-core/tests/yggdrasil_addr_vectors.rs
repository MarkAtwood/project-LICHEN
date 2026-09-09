//! Tests against the shared corpora in test/vectors/yggdrasil_address.json
//! (live) and test/vectors/legacy/yggdrasil_address_native_sha512.json
//! (QUARANTINED).
//!
//! Per spec/decisions.jsonl upstream-yggdrasil-addressing, a node's routable
//! address MUST equal upstream Yggdrasil `AddrForKey(Ed25519PublicKey)`. The
//! former `lichen_native_sha512` profile is REJECTED; its vectors are
//! quarantined in the legacy file and are consumed here ONLY as a
//! quarantine-integrity pin of pre-migration behavior, never as a conformance
//! oracle (see test/vectors/legacy/README.md).
//!
//! Three entry kinds:
//! 1. The single upstream yggdrasil-go anchor (`upstream_addr_for_key`) —
//!    the pinned external oracle, kept verbatim.
//! 2. QUARANTINED `lichen_native_sha512` cases — driven byte-exact through
//!    [`ygg_addr_from_pubkey`] / [`iid_from_pubkey_bytes`]. The implementation
//!    still derives the rejected profile; this test trips if that derivation
//!    changes accidentally before the upstream AddrForKey migration lands.
//!    When the migration lands, these cases MUST be deleted and the anchor
//!    test below MUST flip from `assert_ne!` to byte-equality.
//! 3. `error_case` length rejections (live corpus) — not expressible here
//!    because the Rust API takes `&[u8; 32]`, which enforces key length at
//!    the type level.

use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/yggdrasil_address.json");
const LEGACY_NATIVE_JSON: &str =
    include_str!("../../../test/vectors/legacy/yggdrasil_address_native_sha512.json");

const ANCHOR_NAME: &str = "upstream_addr_for_key";
const ANCHOR_ADDRESS: [u8; 16] = [
    0x02, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e, 0x43, 0x84, 0x65, 0xdb, 0x8d, 0xb6, 0x68, 0x95,
];

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
fn quarantined_native_vectors_byte_exact_pin() {
    // QUARANTINE-INTEGRITY PIN, not a conformance oracle: the implementation
    // still derives the REJECTED SHA-512 native profile — a known, tracked
    // migration gap (spec/decisions.jsonl upstream-yggdrasil-addressing).
    // This test trips if the derivation changes accidentally before the
    // upstream AddrForKey migration lands; when it lands, this test MUST be
    // deleted and upstream_anchor_* MUST assert byte-equality instead.
    for vector in legacy_native_vectors(&load_legacy_document()) {
        let name = vector["name"].as_str().unwrap();
        let pubkey_vec = decode_hex(vector["public_key"].as_str().unwrap());
        let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
        let expected = decode_hex(vector["address"].as_str().unwrap());

        let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
        assert_eq!(&addr[..], &expected[..], "{name}");

        let iid = lichen_core::addr::iid_from_pubkey_bytes(&pubkey);
        assert_eq!(
            &addr[8..16],
            &iid[..],
            "{name}: lower 64 bits must equal IID"
        );
        assert_eq!(addr[0], 0x02, "{name}: 0200::/8 prefix byte");
        assert_eq!(iid[0] & 0x02, 0, "{name}: U/L bit must be clear in IID");
    }
}

#[test]
fn upstream_anchor_diverges_from_current_native_profile() {
    // PINNED MIGRATION GAP, not a target state: upstream AddrForKey never
    // hashes the key; the current implementation still derives the REJECTED
    // SHA-512 profile. decisions.jsonl upstream-yggdrasil-addressing requires
    // AddrForKey equality, so this `assert_ne!` documents exactly the work
    // remaining — when the migration lands this assertion MUST flip to
    // byte-equality (it will fail loudly until it is flipped). Constants are
    // from upstream address_test.go @422836ee (external oracle).
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
    assert_ne!(
        &derived[..],
        &ANCHOR_ADDRESS[..],
        "upstream AddrForKey migration has landed: flip this test to \
         byte-equality per spec/decisions.jsonl upstream-yggdrasil-addressing"
    );
    assert_eq!(derived[0], ANCHOR_ADDRESS[0], "only the prefix byte agrees");
}
