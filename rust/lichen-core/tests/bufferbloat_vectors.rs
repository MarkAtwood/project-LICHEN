// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! B.2 Design Principles vs shared bufferbloat vectors.
//!
//! Independent oracle: `test/vectors/tx_queue_{bounded,expiry,priority}.json`
//! and `test/vectors/forwarding_buffer.json` (spec/appendix-bufferbloat.md).
//! Does not derive expected values from lichen-core.

use lichen_core::tx_queue::{
    TxPriority, DEADLINE_ACK_MS, DEADLINE_BULK_MS, DEADLINE_NORMAL_MS, DEADLINE_ROUTING_MS,
    DEADLINE_SOS_MS, DEADLINE_URGENT_MS, TX_QUEUE_CAPACITY,
};
use serde_json::Value;

const BOUNDED_JSON: &str = include_str!("../../../test/vectors/tx_queue_bounded.json");
const EXPIRY_JSON: &str = include_str!("../../../test/vectors/tx_queue_expiry.json");
const PRIORITY_JSON: &str = include_str!("../../../test/vectors/tx_queue_priority.json");
const FORWARD_JSON: &str = include_str!("../../../test/vectors/forwarding_buffer.json");

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("vector json")
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("missing {key}"))
}

#[test]
fn tx_queue_capacity_matches_bounded_vector() {
    let document = parse(BOUNDED_JSON);
    let case = document["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["name"] == "capacity_default_4")
        .expect("capacity_default_4");
    assert_eq!(
        TX_QUEUE_CAPACITY as u64,
        u64_field(&case["expected"], "capacity")
    );
}

#[test]
fn deadline_constants_match_expiry_vector() {
    let constants = &parse(EXPIRY_JSON)["constants"];
    assert_eq!(DEADLINE_SOS_MS, u64_field(constants, "DEADLINE_SOS_MS"));
    assert_eq!(
        DEADLINE_ROUTING_MS,
        u64_field(constants, "DEADLINE_ROUTING_MS")
    );
    assert_eq!(DEADLINE_ACK_MS, u64_field(constants, "DEADLINE_ACK_MS"));
    assert_eq!(
        DEADLINE_URGENT_MS,
        u64_field(constants, "DEADLINE_URGENT_MS")
    );
    assert_eq!(
        DEADLINE_NORMAL_MS,
        u64_field(constants, "DEADLINE_NORMAL_MS")
    );
    assert_eq!(DEADLINE_BULK_MS, u64_field(constants, "DEADLINE_BULK_MS"));
    assert_eq!(TX_QUEUE_CAPACITY as u64, u64_field(constants, "CAPACITY"));
}

#[test]
fn priority_discriminants_match_priority_vector() {
    let constants = &parse(PRIORITY_JSON)["constants"];
    assert_eq!(TxPriority::Sos as u64, u64_field(constants, "PRIORITY_SOS"));
    assert_eq!(
        TxPriority::Routing as u64,
        u64_field(constants, "PRIORITY_ROUTING")
    );
    assert_eq!(
        TxPriority::Routing as u64,
        u64_field(constants, "PRIORITY_ACK")
    );
    assert_eq!(
        TxPriority::Urgent as u64,
        u64_field(constants, "PRIORITY_URGENT")
    );
    assert_eq!(
        TxPriority::Normal as u64,
        u64_field(constants, "PRIORITY_NORMAL")
    );
    assert_eq!(
        TxPriority::Bulk as u64,
        u64_field(constants, "PRIORITY_BULK")
    );
    assert_eq!(TX_QUEUE_CAPACITY as u64, u64_field(constants, "CAPACITY"));
}

#[test]
fn forwarding_buffer_oracle_matches_spec_b2() {
    let oracle = &parse(FORWARD_JSON)["oracle"];
    assert_eq!(u64_field(oracle, "max_forwarding_sources"), 8);
    assert_eq!(u64_field(oracle, "max_packets_per_source"), 2);
    assert_eq!(u64_field(oracle, "total_capacity"), 16);
}

#[test]
fn forwarding_vectors_have_independent_operation_expectations() {
    let document = parse(FORWARD_JSON);
    assert_eq!(document["vector_type"], "forwarding_buffer");
    assert_eq!(u64_field(&document, "format_version"), 1);

    let vectors = document["vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        let operation = vector["operation"].as_str().expect("operation");
        let expected = &vector["expected"];
        match operation {
            "try_buffer" => {
                let inputs = &vector["inputs"];
                assert!(inputs["packet_id"].is_string(), "{name}: packet_id");
                assert!(inputs["source_iid"].is_string(), "{name}: source_iid");
                assert!(inputs["now_ms"].is_u64(), "{name}: now_ms");
                assert!(inputs["deadline_ms"].is_u64(), "{name}: deadline_ms");
                assert!(matches!(
                    expected["result"].as_str(),
                    Some("ACCEPTED") | Some("BACKPRESSURE") | Some("EVICTED")
                ));
            }
            "expire_old" => {
                assert!(vector["inputs"]["now_ms"].is_u64(), "{name}: now_ms");
                assert!(expected["expired_count"].is_u64(), "{name}: expired_count");
            }
            "dequeue" => {
                assert!(
                    vector["inputs"]["source_iid"].is_string(),
                    "{name}: source_iid"
                );
                assert!(
                    expected["packet_id"].is_string() || expected["result"].is_null(),
                    "{name}: dequeue expectation"
                );
            }
            "get_stats" => {
                for field in [
                    "total_packets",
                    "sources",
                    "max_sources",
                    "max_per_source",
                    "accepted",
                    "backpressure",
                    "expired",
                    "evicted",
                ] {
                    assert!(expected[field].is_u64(), "{name}: {field}");
                }
            }
            "fill_to_capacity" => {
                for field in ["total_packets", "source_count", "accepted"] {
                    assert!(expected[field].is_u64(), "{name}: {field}");
                }
            }
            other => panic!("unexpected forwarding operation {other}"),
        }
    }
}

const CONGESTION_JSON: &str = include_str!("../../../test/vectors/bufferbloat_congestion.json");

#[test]
fn b5_congestion_vectors_match_spec_testing_table() {
    let document = parse(CONGESTION_JSON);
    let mut names = Vec::new();
    for case in document["vectors"].as_array().expect("vectors") {
        let name = case["name"].as_str().unwrap();
        names.push(name);
        match name {
            "queue_full" => {
                assert_eq!(u64_field(case, "tx_capacity"), TX_QUEUE_CAPACITY as u64);
                assert_eq!(case["expected"], "ENOBUFS");
            }
            "deadline_expiry" => {
                assert_eq!(u64_field(case, "routing_deadline_ms"), DEADLINE_ROUTING_MS);
                assert_eq!(u64_field(case, "ack_deadline_ms"), DEADLINE_ACK_MS);
                assert_eq!(u64_field(case, "app_deadline_ms"), DEADLINE_NORMAL_MS);
                assert_eq!(case["expected"], "drop_before_tx");
            }
            "priority_preemption" => {
                assert_eq!(case["expected"], "higher_preempts_lower");
            }
            "multihop_latency" => {
                assert_eq!(case["expected"], "bounded_e2e_delay");
            }
            "fairness" => {
                assert_eq!(u64_field(case, "max_packets_per_source"), 2);
                assert_eq!(u64_field(case, "max_forwarding_sources"), 8);
                assert_eq!(
                    case["expected"],
                    "local_backpressure_recorded_when_source_full"
                );
            }
            other => panic!("unexpected congestion vector {other}"),
        }
    }
    assert_eq!(
        names,
        [
            "queue_full",
            "deadline_expiry",
            "priority_preemption",
            "multihop_latency",
            "fairness"
        ]
    );
}
