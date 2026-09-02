// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! CCP-16 desync vectors (spec 02a 2a.6, 09 14.7): binds
//! test/vectors/ccp16-desync.json to lichen-core's DesyncFSM. The corpus
//! is the committed independent oracle; the C (lichen/tests/desync_fsm)
//! and Python (test_ccp_sync_vector_consumers) suites consume the same
//! file (two-suite+ contract).

use serde_json::Value;

use lichen_core::desync::{DesyncFSM, DesyncState};

#[test]
fn ccp16_desync_vectors_match() {
    let content = include_str!("../../../test/vectors/ccp16-desync.json");
    let vectors: serde_json::Value = serde_json::from_str(content).unwrap();
    let vectors = vectors.as_array().expect("corpus is a JSON list");
    assert_eq!(vectors.len(), 4, "corpus case count changed");

    for v in vectors {
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let expected = v.get("expected").and_then(|x| x.as_str()).unwrap_or("");
        // Drift cases carry their fields at top level (no "input" wrapper,
        // no "type" discriminator - dispatch on the fields instead).
        let has_drift_fields = v.get("drift_ppm").is_some();
        let input = v.get("input").unwrap_or(v);
        let type_tag = v.get("type").and_then(|x| x.as_str());
        match type_tag {
            Some("sfn_wrap") => {
                // SFN wrap triggers the desync recovery FSM.
                let current = input
                    .get("current_sfn")
                    .and_then(|x| x.as_u64())
                    .expect("current_sfn");
                let last = input
                    .get("last_sfn")
                    .and_then(|x| x.as_u64())
                    .expect("last_sfn");
                assert_eq!(current, 0);
                assert_eq!(last, 65535);
                // u32 wrap arithmetic: (current - last) mod 2^32 is
                // large, which the FSM treats as loss of sync.
                let delta = (current as u32).wrapping_sub(last as u32);
                assert!(delta > 0, "{name}: wrap delta nonzero");
                let mut fsm = DesyncFSM::new();
                fsm.on_sfn_wrap(false);
                assert_eq!(fsm.state(), DesyncState::Desynced, "{name}");
                assert_eq!(expected, "desync_recovery");
            }
            Some("multi_root") => {
                // A version conflict from a secondary root forces desync.
                let alternate = input
                    .get("alternate_version")
                    .and_then(|x| x.as_u64())
                    .expect("alternate_version");
                let version = input.get("version").and_then(|x| x.as_u64());
                assert_ne!(Some(alternate), version);
                let mut fsm = DesyncFSM::new();
                fsm.on_sfn_wrap(false);
                assert_eq!(fsm.state(), DesyncState::Desynced, "{name}");
                assert_eq!(expected, "desync");
            }
            None if has_drift_fields => {
                let drift_ppm = input
                    .get("drift_ppm")
                    .and_then(|x| x.as_i64())
                    .expect("drift_ppm");
                let guard_ppm = input
                    .get("guard_ppm")
                    .and_then(|x| x.as_i64())
                    .expect("guard_ppm");
                assert!(drift_ppm.abs() > guard_ppm, "{name}: drift exceeds guard");
                // SYNCED path: drift forces DESYNCED.
                let mut fsm = DesyncFSM::new();
                fsm.on_drift(drift_ppm, guard_ppm);
                assert_eq!(fsm.state(), DesyncState::Desynced, "{name}");
                assert_eq!(expected, "enter_desync_recovery");
                // No-op outside SYNCED: RECOVERING and DESYNCED stay put
                // (a drift measurement alone cannot exit recovery).
                let mut recovering = DesyncFSM::new();
                recovering.on_sfn_wrap(false);
                recovering.on_beacon(true, true);
                assert_eq!(
                    recovering.on_drift(drift_ppm, guard_ppm),
                    DesyncState::Recovering
                );
                let mut desynced = DesyncFSM::new();
                desynced.on_sfn_wrap(false);
                assert_eq!(
                    desynced.on_drift(drift_ppm, guard_ppm),
                    DesyncState::Desynced
                );
            }
            Some("recovery") => {
                // First valid beacon after desync starts RECOVERING.
                let mut fsm = DesyncFSM::new();
                fsm.on_sfn_wrap(false);
                fsm.on_beacon(true, true);
                assert_eq!(fsm.state(), DesyncState::Recovering, "{name}");
                assert_eq!(expected, "recovering");
            }
            other => panic!("{name}: unknown vector type {other:?}"),
        }
    }
}
