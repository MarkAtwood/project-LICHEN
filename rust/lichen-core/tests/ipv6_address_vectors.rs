// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Canonical `ipv6-addresses.json` and QUARANTINED legacy corpora consumers
//! (`legacy/yggdrasil-derivation.json`,
//! `legacy/ipv6_addresses_native_sha512.json`).
//!
//! Key-derived identities bind `fe80::/10` to the SHA-512 IID. Since i72x.2
//! (decision `upstream-yggdrasil-addressing`) the routable `0200::/8` address
//! is upstream Yggdrasil `AddrForKey`, which bit-packs the inverted pubkey and
//! does NOT embed the IID. The live `ipv6-addresses.json` corpus carries that
//! upstream derivation (regenerated in the i72x.6 slice); the legacy corpora's
//! `native_packed`/`ygg_addr` fields still encode the REJECTED SHA-512 native
//! profile (see test/vectors/legacy/README.md) and are consumed only as
//! quarantine-integrity pins, never as conformance oracles. Conformance is
//! pinned per key against the external oracle (upstream `address.go`
//! @422836ee).
//! EUI-64 and short-address cases are link-interoperability helpers, not
//! node identities.

use lichen_core::addr::{iid_from_pubkey_bytes, ygg_addr_from_pubkey, Ipv6Addr, NodeId};
use lichen_core::short_addr::{short_addr_from_iid, short_addr_to_iid};
use serde_json::Value;

const IPV6_ADDRESS_VECTORS: &str = include_str!("../../../test/vectors/ipv6-addresses.json");
const YGG_DERIVATION_VECTORS: &str =
    include_str!("../../../test/vectors/legacy/yggdrasil-derivation.json");
const LEGACY_IPV6_NATIVE_VECTORS: &str =
    include_str!("../../../test/vectors/legacy/ipv6_addresses_native_sha512.json");

/// Upstream `AddrForKey` for each corpus pubkey, produced by running
/// upstream's own `address.go` @422836ee (external oracle, never this crate).
fn upstream_addr_for_pubkey(pubkey: &[u8; 32]) -> [u8; 16] {
    let table: [(&str, &str); 8] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "02000000000000000000000000000000",
        ),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "0200389e777ace07c7d6ca08166ecd20",
        ),
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "0200514acffcfa9dea90556802586d37",
        ),
        (
            "abababababababababababababababababababababababababababababababab",
            "0200a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "02000000000000000000000000000000",
        ),
        (
            "0202020202020202020202020202020202020202020202020202020202020202",
            "0206fefefefefefefefefefefefefefe",
        ),
        (
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0207fefefefefefefefefefefefefefe",
        ),
        (
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
            "020042a482206a028a8242a482206a02",
        ),
    ];
    let hex: String = pubkey.iter().map(|b| format!("{b:02x}")).collect();
    let (_, expected) = table
        .iter()
        .find(|(pk, _)| *pk == hex)
        .expect("corpus pubkey must have a pinned upstream address");
    decode_hex::<16>(expected)
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(
        value.len(),
        N * 2,
        "hex vector must contain exactly {N} bytes"
    );
    let mut decoded = [0u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("vector must be hexadecimal");
    }
    decoded
}

fn ipv6_document() -> Value {
    serde_json::from_str(IPV6_ADDRESS_VECTORS).expect("ipv6-addresses.json must parse")
}

fn link_local_from_iid(iid: &[u8; 8]) -> [u8; 16] {
    let mut packed = [0u8; 16];
    packed[0] = 0xfe;
    packed[1] = 0x80;
    packed[8..].copy_from_slice(iid);
    packed
}

#[test]
fn key_derived_identity_binds_link_local_and_quarantined_native() {
    // The live corpus pins the IID + link-local derivations and, since the
    // i72x.6 corpus regeneration, carries the primary 0200::/8 fields as
    // upstream AddrForKey values (native/native_packed/iid_in_native). The
    // REJECTED SHA-512 profile lives only in
    // test/vectors/legacy/ipv6_addresses_native_sha512.json (QUARANTINED —
    // quarantine-integrity pin only, never a conformance oracle).
    let document = ipv6_document();
    assert_eq!(document["format_version"], 2);
    let legacy: Value = serde_json::from_str(LEGACY_IPV6_NATIVE_VECTORS)
        .expect("legacy/ipv6_addresses_native_sha512.json must parse");
    let legacy_by_name: std::collections::BTreeMap<&str, &Value> = legacy["vectors"]
        .as_array()
        .expect("legacy vectors array")
        .iter()
        .map(|v| (v["name"].as_str().expect("legacy vector name"), v))
        .collect();

    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        if vector["profile"] != "key_derived_identity" {
            continue;
        }
        let name = vector["name"].as_str().expect("vector name");
        let pubkey = decode_hex::<32>(vector["pubkey"].as_str().expect("pubkey"));
        let expected_iid = decode_hex::<8>(vector["iid"].as_str().expect("iid"));
        let expected_link_local =
            decode_hex::<16>(vector["link_local_packed"].as_str().expect("link-local"));
        // The regenerated corpus carries the upstream AddrForKey primary;
        // the field is mandatory and MUST equal the external oracle (never
        // the rejected SHA-512 profile, which embeds the IID).
        let corpus_native = decode_hex::<16>(
            vector["native_packed"]
                .as_str()
                .expect("key_derived_identity vectors must carry native_packed"),
        );
        assert_eq!(
            corpus_native,
            upstream_addr_for_pubkey(&pubkey),
            "{name}: live native_packed must equal upstream AddrForKey"
        );
        assert_ne!(
            &corpus_native[8..],
            &expected_iid[..],
            "{name}: live native_packed must not embed the IID (rejected profile)"
        );
        let legacy_vector = legacy_by_name
            .get(name)
            .expect("every key_derived_identity vector keeps a quarantined twin");
        let expected_native =
            decode_hex::<16>(legacy_vector["native_packed"].as_str().expect("native"));

        let iid = iid_from_pubkey_bytes(&pubkey);
        let native = ygg_addr_from_pubkey(&pubkey);
        let link_local = link_local_from_iid(&iid);

        assert_eq!(iid, expected_iid, "{name}");
        // Routable address: upstream AddrForKey, pinned per key from the
        // external oracle (table above; the corpus's native_packed is
        // cross-checked against the same oracle at the top of the loop).
        assert_eq!(native, upstream_addr_for_pubkey(&pubkey), "{name}");
        assert_eq!(link_local, expected_link_local, "{name}");
        assert_eq!(native[0], 0x02, "{name}: 0200::/8 prefix");
        assert_eq!(iid[0] & 0x02, 0, "{name}: U/L bit must be clear");
        assert_eq!(&link_local[8..], &iid[..], "{name}: fe80 IID");
        assert!(Ipv6Addr(link_local).is_link_local(), "{name}");
        // Quarantine-integrity pins on the legacy corpus only — never against
        // the migrated implementation: the rejected-profile record keeps its
        // 0200::/8 prefix, still embeds the IID, and records the binding.
        assert_eq!(
            expected_native[0], 0x02,
            "{name}: quarantined 0200::/8 prefix"
        );
        assert_eq!(
            &expected_native[8..],
            &iid[..],
            "{name}: quarantined record embeds the IID"
        );
        assert_eq!(
            legacy_vector["iid_in_native"], true,
            "{name}: quarantined corpus records the binding"
        );
        checked += 1;
    }
    assert_eq!(checked, 5, "all key-derived identity vectors must run");
}

#[test]
fn eui64_link_local_interoperability_vectors() {
    let document = ipv6_document();
    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        let Some(eui64_hex) = vector["eui64"].as_str() else {
            continue;
        };
        let name = vector["name"].as_str().expect("vector name");
        let eui64 = decode_hex::<8>(eui64_hex);
        let expected_iid = decode_hex::<8>(vector["iid"].as_str().expect("iid"));
        let expected_link_local =
            decode_hex::<16>(vector["link_local_packed"].as_str().expect("link-local"));

        let from_node = NodeId(eui64).link_local_addr();
        let from_addr = Ipv6Addr::link_local_from_eui64(&eui64);
        assert_eq!(from_node, from_addr, "{name}");
        assert_eq!(from_node.0, expected_link_local, "{name}");
        assert_eq!(from_node.iid(), expected_iid, "{name}");
        assert!(from_node.is_link_local(), "{name}");
        checked += 1;
    }
    assert_eq!(checked, 3, "all EUI-64 interoperability vectors must run");
}

#[test]
fn short_address_rfc4944_iid_vectors() {
    let document = ipv6_document();
    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        let Some(short_addr) = vector["short_addr"].as_u64() else {
            continue;
        };
        let name = vector["name"].as_str().expect("vector name");
        let short_addr = short_addr as u16;
        let expected = decode_hex::<8>(vector["iid"].as_str().expect("iid"));
        assert_eq!(short_addr_to_iid(short_addr), expected, "{name}");
        assert_eq!(short_addr_from_iid(&expected), Some(short_addr), "{name}");
        checked += 1;
    }
    assert_eq!(checked, 3, "all short-address IID vectors must run");
}

#[test]
fn yggdrasil_derivation_corpus_matches_upstream_addr_for_key() {
    // The corpus is QUARANTINED under test/vectors/legacy/ and its `ygg_addr`
    // fields encode the rejected SHA-512 native profile
    // (test/vectors/legacy/README.md). The upstream AddrForKey migration has
    // landed, so — exactly as the pre-migration quarantine pin required — the
    // rejected-profile assertions are replaced here with pinned upstream
    // byte-equality values from the external oracle (see module docs), and
    // this test takes its post-migration name.
    let entries: Vec<Value> =
        serde_json::from_str(YGG_DERIVATION_VECTORS).expect("yggdrasil-derivation.json must parse");

    let mut positive = 0;
    let mut binding = 0;
    let mut negative = 0;
    for entry in entries {
        if entry["test_type"] == "negative" {
            let attacker =
                decode_hex::<32>(entry["attacker_pubkey"].as_str().expect("attacker pubkey"));
            let victim = decode_hex::<8>(entry["victim_iid"].as_str().expect("victim iid"));
            assert_ne!(
                iid_from_pubkey_bytes(&attacker),
                victim,
                "attacker pubkey must not derive victim IID"
            );
            negative += 1;
            continue;
        }
        let pubkey = decode_hex::<32>(entry["pubkey"].as_str().expect("pubkey"));
        let addr = ygg_addr_from_pubkey(&pubkey);
        let iid = iid_from_pubkey_bytes(&pubkey);
        // The corpus's ygg_addr is the rejected native profile; the upstream
        // AddrForKey value is pinned per key from the external oracle.
        assert_eq!(addr, upstream_addr_for_pubkey(&pubkey));
        if let Some(expected) = entry["iid"].as_str() {
            assert_eq!(iid, decode_hex::<8>(expected));
        }
        assert_eq!(addr[0], 0x02);
        if entry["test_type"] == "binding_invariant"
            || entry["test_type"] == "binding_invariant_rejected"
        {
            // The addr[8..] == IID invariant is retired with the rejected
            // profile; the entry now pins the upstream address for its key.
            binding += 1;
            continue;
        }
        positive += 1;
    }
    assert!(positive >= 4, "positive derivation entries must run");
    assert!(binding >= 1, "binding-invariant entry must run");
    assert_eq!(negative, 1, "negative attack entry must run");
}
