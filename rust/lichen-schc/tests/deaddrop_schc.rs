// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//! /deaddrop SCHC compressed-packet vector coverage (appendix-schc.md A.4.1).
//!
//! Vectors are produced by an independent wire-spec generator
//! (`test/vectors/generate_deaddrop_schc.py`) that imports neither SCHC
//! implementation. This test pins the Rust codec against that oracle for
//! OSCORE POSTs (Rule 5/6), a protected GET (Rule 5), and public GETs
//! (Rule 0/1 with Uri-Path carried verbatim in the tail).

use lichen_schc::{compress, decompress};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    format_version: u32,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    rule_id: u8,
    coap_code: u8,
    ipv6_packet: String,
    compressed: String,
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn vectors() -> VectorFile {
    let document: VectorFile =
        serde_json::from_str(include_str!("../../../test/vectors/deaddrop_schc.json")).unwrap();
    assert_eq!(document.format_version, 2);
    document
}

#[test]
fn deaddrop_vectors_cover_every_provisioned_rule() {
    let document = vectors();
    let names: Vec<&str> = document.vectors.iter().map(|v| v.name.as_str()).collect();
    for required in [
        "deaddrop_post_linklocal",
        "deaddrop_post_global",
        "deaddrop_get_protected_linklocal",
        "deaddrop_get_public_linklocal",
        "deaddrop_get_public_global",
    ] {
        assert!(names.contains(&required), "missing vector {required}");
    }
}

#[test]
fn deaddrop_compress_matches_independent_oracle() {
    for vector in vectors().vectors {
        let packet = hex(&vector.ipv6_packet);
        let expected = hex(&vector.compressed);
        let mut output = vec![0xa5; packet.len() + 1];
        let length = compress(&packet, &mut output).unwrap();
        assert_eq!(
            &output[..length],
            expected.as_slice(),
            "compress {}",
            vector.name
        );
        assert_eq!(output[0], vector.rule_id, "rule id {}", vector.name);
    }
}

#[test]
fn deaddrop_roundtrip_is_lossless() {
    for vector in vectors().vectors {
        let packet = hex(&vector.ipv6_packet);
        let compressed = hex(&vector.compressed);
        let mut restored = vec![0xa5; packet.len()];
        let length = decompress(&compressed, &mut restored).unwrap();
        assert_eq!(
            &restored[..length],
            packet.as_slice(),
            "roundtrip {}",
            vector.name
        );
    }
}

#[test]
fn deaddrop_coap_code_is_preserved() {
    // The CoAP code travels in the residue; confirm it survives the round
    // trip so POSTs (0.02) and GETs (0.01) are not conflated on decompress.
    for vector in vectors().vectors {
        let packet = hex(&vector.ipv6_packet);
        let compressed = hex(&vector.compressed);
        let mut restored = vec![0u8; packet.len()];
        let length = decompress(&compressed, &mut restored).unwrap();
        // CoAP code is the second byte of the CoAP header (after IPv6+UDP).
        assert_eq!(restored[49], vector.coap_code, "code {}", vector.name);
        assert_eq!(length, packet.len());
    }
}
