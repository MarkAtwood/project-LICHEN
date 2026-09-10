//! Tests against the shared corpora in test/vectors/yggdrasil_address.json
//! (live) and test/vectors/legacy/yggdrasil_address_native_sha512.json
//! (QUARANTINED).
//!
//! Per spec/decisions.jsonl upstream-yggdrasil-addressing, a node's routable
//! address MUST equal upstream Yggdrasil `AddrForKey(Ed25519PublicKey)`, and
//! routed /64 prefixes MUST equal upstream `SubnetForKey`. The upstream
//! AddrForKey migration has landed; the anchor tests below pin the
//! implementation byte-for-byte against the verbatim upstream
//! address_test.go vector (yggdrasil-go@422836ee, external oracle),
//! cross-checked by an independent Python port of the Go algorithm — NEVER
//! derived from the Rust implementation.
//!
//! Vector entry kinds:
//! 1. The single upstream yggdrasil-go anchor (`upstream_addr_for_key`) —
//!    the pinned external oracle, kept verbatim; byte-equality conformance.
//! 2. QUARANTINED `lichen_native_sha512` cases — checked against a
//!    test-local transcription of the rejected pre-migration profile
//!    ([`native_profile_reference`]), never against the live implementation.
//!    They pin the quarantined file's bytes as data integrity only.
//! 3. `error_case` length rejections (live corpus) — not expressible here
//!    because the Rust API takes `&[u8; 32]`, which enforces key length at
//!    the type level.
//!
//! Additionally pinned here (from the i72x.2 worker): bit-level edge cases
//! of the upstream packing (leading-ones count, degenerate all-zero key,
//! trailing partial byte) and the retained SHA-512 link-local IID legacy
//! profile (`iid_from_pubkey_bytes`), which the routable address MUST NOT
//! embed.

mod native_profile_reference;

use native_profile_reference::native_sha512_addr;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/yggdrasil_address.json");
const LEGACY_NATIVE_JSON: &str =
    include_str!("../../../test/vectors/legacy/yggdrasil_address_native_sha512.json");

const ANCHOR_NAME: &str = "upstream_addr_for_key";
/// Upstream anchor (address_test.go @422836ee): AddrForKey for this pubkey.
const ANCHOR_PUBKEY: &str = "bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb";
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
        vectors
            .iter()
            .all(|v| v["profile"] != "lichen_native_sha512"),
        "live corpus must not hold rejected native-profile vectors"
    );
    let legacy = load_legacy_document();
    assert!(
        legacy_native_vectors(&legacy).len() >= 10,
        "quarantined native corpus must keep its vectors verbatim"
    );
}

/// The corpus still carries the anchor entry; pin that the bytes the
/// corpus advertises equal the upstream test-vector constants, so a corpus
/// edit that diverges from upstream fails here.
#[test]
fn corpus_anchor_matches_upstream_constants() {
    let document = load_document();
    let anchor = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == ANCHOR_NAME)
        .expect("anchor present");
    assert_eq!(anchor["public_key"].as_str().unwrap(), ANCHOR_PUBKEY);
    assert_eq!(
        decode_hex(anchor["address"].as_str().unwrap()),
        ANCHOR_ADDRESS
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
    assert_eq!(
        subnet, ANCHOR_SUBNET,
        "MUST equal upstream SubnetForKey byte-for-byte (0300::/8)"
    );
    // Subnet lives in 0300::/8 (prefix byte low bit set).
    assert_eq!(subnet[0] & 0x01, 0x01, "subnet prefix bit must be set");
    // And shares the leading-1 count byte with the address.
    let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_eq!(
        subnet[1], addr[1],
        "subnet and address share leading-1 count"
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
fn upstream_edge_classes() {
    // Test-local pins from upstream's own address.go @422836ee, never this
    // crate. Retain the migration's full-byte edge oracles alongside the
    // standalone packing tests and main's quarantine-integrity pins.
    let cases: [(&str, &str); 6] = [
        // Six leading one-bits in the inverted key.
        (
            "0202020202020202020202020202020202020202020202020202020202020202",
            "0206fefefefefefefefefefefefefefe",
        ),
        // Seven leading one-bits in the inverted key.
        (
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0207fefefefefefefefefefefefefefe",
        ),
        // Degenerate count wraps 256 -> 0; no payload bits remain.
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "02000000000000000000000000000000",
        ),
        // Zero leading one-bits and an all-zero packed payload.
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "02000000000000000000000000000000",
        ),
        // Mixed remainder: 255 payload bits, with the last seven discarded.
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
    assert_eq!(addr[0], 0x02, "0200::/8 prefix byte");
    assert_ne!(&addr[8..16], &iid[..]);
}
