// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! CCP-15 interference-score vectors (spec 02a 2a.10.4): the committed
//! corpus test/vectors/ccp-interference.json is an independent math oracle
//! for RfHealthMetrics::interference_score_tenths. Score units: the corpus
//! carries percent points (busy_pct + per*100); the Rust metric returns
//! tenths of a point (busy_percent*10 + packet_error_permille), so each
//! expected value is scaled by 10.

use lichen_core::rf_health::interference_score_tenths;
use serde_json::Value;

#[test]
fn ccp_interference_vectors_match() {
    let content = include_str!("../../../test/vectors/ccp-interference.json");
    let doc: Value = serde_json::from_str(content).unwrap();
    let vectors = doc.get("vectors").and_then(|v| v.as_array()).unwrap();
    assert!(vectors.len() >= 6, "corpus lost interference cases");
    for v in vectors {
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let input = v.get("input").unwrap_or(v);
        let output = v.get("output").unwrap_or(v);
        let busy_percent = input
            .get("busy_pct")
            .and_then(|x| x.as_f64())
            .map(|b| b.round())
            .expect("busy_pct") as u8;
        let per_permille = (input
            .get("per")
            .and_then(|x| x.as_f64())
            .map(|p| p * 1000.0)
            .expect("per")
            .round()) as u16;
        let expected_points = output
            .get("interference_score")
            .and_then(|x| x.as_f64())
            .expect("interference_score");
        let expected_tenths = (expected_points * 10.0).round() as u16;

        let score = interference_score_tenths(busy_percent, per_permille);
        assert_eq!(
            score,
            Some(expected_tenths),
            "{name}: interference score mismatch"
        );
    }
}
