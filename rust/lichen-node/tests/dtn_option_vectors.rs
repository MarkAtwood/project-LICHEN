// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! DTN S-flag/HBH option parity tests, consuming the shared vector corpus
//! test/vectors/dtn_sflag_hbh.json (spec-derived independent oracle) — the
//! same corpus the Python suite (python/tests/test_dtn_option.py) consumes.
//! Bead b7z9.8.3: Rust/Python/C three-way parity.

use lichen_node::routing::dtn_option::{decide_expiry_action, parse_dtn_option};

const VECTORS_JSON: &str = include_str!("../../../test/vectors/dtn_sflag_hbh.json");

fn vectors() -> Vec<serde_json::Value> {
    serde_json::from_str(VECTORS_JSON).expect("parse vector corpus")
}

fn hex(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn dtn_hbh_option_vectors() {
    for case in vectors().iter().filter(|c| c["type"] == "dtn_hbh") {
        let name = case["name"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        if expected == "reject_malformed" {
            assert!(
                parse_dtn_option(&hex(case["option_hex"].as_str().unwrap())).is_none(),
                "{name}: expected rejection"
            );
            continue;
        }
        let parsed = parse_dtn_option(&hex(case["option_hex"].as_str().unwrap()))
            .unwrap_or_else(|| panic!("{name}: expected parse"));
        assert_eq!(parsed.s_flag, case["s_flag"].as_i64().unwrap() != 0, "{name}");
        assert_eq!(
            parsed.expiry_unix,
            case["expiry_unix"].as_u64().unwrap(),
            "{name}"
        );
        if expected == "parse_no_store" {
            assert!(!parsed.s_flag, "{name}: S flag clear means no store");
        }
    }
}

#[test]
fn dtn_expiry_decision_vectors() {
    for case in vectors().iter().filter(|c| c["type"] == "dtn_semantic") {
        let name = case["name"].as_str().unwrap();
        let action = decide_expiry_action(
            case["expiry_unix"].as_u64().unwrap(),
            case["now_unix"].as_u64().unwrap(),
            case["wall_clock_valid"].as_bool().unwrap(),
        );
        assert_eq!(action.as_str(), case["expected"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn absent_option_is_none() {
    // Only padding: no DTN intent.
    assert!(parse_dtn_option(&[0x01, 0x02, 0x00, 0x00]).is_none());
    assert!(parse_dtn_option(&[]).is_none());
}

#[test]
fn duplicate_option_rejected() {
    let opt = hex("0305806553f600");
    let mut doubled = opt.clone();
    doubled.extend_from_slice(&opt);
    assert!(parse_dtn_option(&doubled).is_none());
}

#[test]
fn truncated_option_rejected() {
    assert!(parse_dtn_option(&[0x03, 0x05, 0x80, 0x65]).is_none());
}

#[test]
fn zero_expiry_rejected() {
    // Implementation-pinned: expiry==0 is the C fail-open "no validated
    // deadline" sentinel (routing/dtn.h); the spec is silent on it.
    assert!(parse_dtn_option(&hex("03058000000000")).is_none());
}

#[test]
fn reserved_bits_ignored() {
    // Spec-backed (9.8: reserved ignored on receive); duplicates the
    // vector case as a direct unit check.
    let clean = parse_dtn_option(&hex("0305006553f600"));
    let noisy = parse_dtn_option(&hex("03057f6553f600"));
    assert_eq!(clean, noisy);
}

#[test]
fn expiry_boundary_not_before_is_kept() {
    // Implementation-pinned: expiry == now is not expired (strict <),
    // matching the C parser; the spec does not state the boundary.
    assert_eq!(
        decide_expiry_action(1000, 1000, true),
        lichen_node::routing::dtn_option::ExpiryAction::StoreOrForward
    );
}
