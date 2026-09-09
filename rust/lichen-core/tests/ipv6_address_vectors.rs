// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Canonical `ipv6-addresses.json` consumer (IID + link-local derivations).
//!
//! Key-derived identities bind `fe80::/10` to the SHA-512 IID. The routable
//! 0200::/8 primary address is upstream Yggdrasil `AddrForKey` (see
//! `yggdrasil_addr_vectors.rs`); the former SHA-512 native profile is REJECTED
//! and its quarantined corpora are no longer consumed here (the upstream
//! AddrForKey migration has landed). EUI-64 and short-address cases are
//! link-interoperability helpers, not node identities.

use lichen_core::addr::{iid_from_pubkey_bytes, Ipv6Addr, NodeId};
use lichen_core::short_addr::{short_addr_from_iid, short_addr_to_iid};
use serde_json::Value;

const IPV6_ADDRESS_VECTORS: &str = include_str!("../../../test/vectors/ipv6-addresses.json");
// IID derivations + anti-collision negative case only; its native-address
// fields encode the REJECTED SHA-512 profile and are not asserted.
const YGG_DERIVATION_VECTORS: &str =
    include_str!("../../../test/vectors/legacy/yggdrasil-derivation.json");

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
fn key_derived_identity_binds_link_local() {
    // The live corpus pins only the IID + link-local derivations. The routable
    // 0200::/8 address is upstream AddrForKey (see yggdrasil_addr_vectors.rs);
    // the rejected native profile and the IID-in-native binding are gone.
    let document = ipv6_document();
    assert_eq!(document["format_version"], 2);

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
        // The rejected-profile corpus must not leak back into the live file.
        assert!(
            vector.get("native_packed").is_none()
                && vector.get("native").is_none()
                && vector.get("iid_in_native").is_none(),
            "{name}: live corpus must not carry rejected native fields"
        );

        let iid = iid_from_pubkey_bytes(&pubkey);
        let link_local = link_local_from_iid(&iid);

        assert_eq!(iid, expected_iid, "{name}");
        assert_eq!(link_local, expected_link_local, "{name}");
        assert_eq!(iid[0] & 0x02, 0, "{name}: U/L bit must be clear");
        assert_eq!(&link_local[8..], &iid[..], "{name}: fe80 IID");
        assert!(Ipv6Addr(link_local).is_link_local(), "{name}");
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
fn legacy_derivation_corpus_iid_only() {
    // Consumes legacy/yggdrasil-derivation.json for its IID derivations and
    // the anti-collision negative case ONLY. Its `ygg_addr` / native-address
    // and IID-binding-invariant fields encode the REJECTED SHA-512 native
    // profile and are NOT asserted (the routable address is now upstream
    // AddrForKey; see yggdrasil_addr_vectors.rs). The IID itself is unchanged
    // by the migration, so the IID assertions and the attacker/victim
    // anti-collision check remain valid conformance checks.
    let entries: Vec<Value> =
        serde_json::from_str(YGG_DERIVATION_VECTORS).expect("yggdrasil-derivation.json must parse");

    let mut iid_checked = 0;
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
        // IID assertion (profile-independent of the routable address).
        if let Some(expected) = entry["iid"].as_str() {
            let pubkey = decode_hex::<32>(entry["pubkey"].as_str().expect("pubkey"));
            assert_eq!(iid_from_pubkey_bytes(&pubkey), decode_hex::<8>(expected));
            iid_checked += 1;
        }
    }
    assert!(iid_checked >= 4, "IID derivation entries must run");
    assert_eq!(negative, 1, "negative attack entry must run");
}
