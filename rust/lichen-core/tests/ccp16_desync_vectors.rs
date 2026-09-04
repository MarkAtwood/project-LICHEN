// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Rust consumer for test/vectors/ccp16-desync.json (spec 02a 2a.6, 09 14.7,
//! R-02a-079; bead qn9l). Drives lichen_core::desync::DesyncFSM against
//! the committed vectors — matching the C consumer (lichen/tests/desync_fsm)
//! and the python oracle (timing.sfn DesyncFSM). Two-suite+ contract: the
//! corpus is the committed independent oracle for all three suites.

use lichen_core::desync::{DesyncFSM, DesyncState};

fn vectors() -> Vec<Value> {
    let content = include_str!("../../../test/vectors/ccp16-desync.json");
    serde_json::from_str(content).expect("ccp16-desync.json parses")
}

fn find_case(name: &str) -> Value {
    vectors()
        .into_iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("vector {name} missing"))
}

#[test]
fn corpus_case_count_is_pinned() {
    // Guard against corpus case-count drift (beads-worker-4); the C and
    // Python consumers pin the same count.
    assert_eq!(vectors().len(), 4, "corpus case count changed");
}

#[test]
fn desync_on_sfn_wrap_vector() {
    let v = find_case("desync_on_sfn_wrap");
    assert_eq!(v["expected"], "desync_recovery");
    assert_eq!(v["current_sfn"], 0);
    assert_eq!(v["last_sfn"], 65535);

    // The vector's core arithmetic claim: unsigned-32 (current - last)
    // wraps to 4294901761 (python test_ccp_sync_vector_consumers parity).
    let current: u32 = v["current_sfn"].as_u64().unwrap() as u32;
    let last: u32 = v["last_sfn"].as_u64().unwrap() as u32;
    assert_eq!(current.wrapping_sub(last), 4_294_901_761);

    // A synced node whose time provider is invalid at a wrap drops to
    // Desynced and the first valid beacon re-enters Recovering.
    let mut fsm = DesyncFSM::new();
    fsm.on_beacon(true, true);
    fsm.on_beacon(true, true);
    assert_eq!(fsm.on_sfn_wrap(true), DesyncState::Synced);
    assert_eq!(fsm.on_sfn_wrap(false), DesyncState::Desynced);
    assert_eq!(fsm.on_beacon(true, true), DesyncState::Recovering);
}

#[test]
fn desync_recovery_beacon_revalidate_vector() {
    let v = find_case("desync_recovery_beacon_revalidate");
    assert_eq!(v["expected"], "recovering");

    // After desync, the first valid beacon re-enters Recovering;
    // three consecutive valid beacons are required for Synced (14.7).
    let mut fsm = DesyncFSM::new();
    fsm.on_sfn_wrap(false);
    assert_eq!(fsm.on_beacon(true, true), DesyncState::Recovering);
    // An invalid beacon resets the consecutive-valid count.
    assert_eq!(fsm.on_beacon(false, true), DesyncState::Desynced);
    assert_eq!(fsm.on_beacon(true, true), DesyncState::Recovering);
    assert_eq!(fsm.on_beacon(true, true), DesyncState::Recovering);
    assert_eq!(fsm.on_beacon(true, true), DesyncState::Synced);
}

#[test]
fn excessive_clock_drift_desync_vector() {
    let v = find_case("excessive_clock_drift_desync");
    assert_eq!(v["expected"], "enter_desync_recovery");
    let drift = v["drift_ppm"].as_i64().unwrap();
    let guard = v["guard_ppm"].as_i64().unwrap();
    assert!(
        drift.abs() > guard,
        "vector drift {drift} must exceed guard {guard}"
    );

    // Real FSM drive (beads-worker-4): DesyncFSM::on_drift (spec 02a
    // 2a.6.2) now exists in the merged API, superseding the HEAD
    // semantics-pin-only treatment. SYNCED + |drift| > guard -> Desynced.
    let mut fsm = DesyncFSM::new();
    assert_eq!(fsm.on_drift(drift, guard), DesyncState::Desynced);

    // No-op outside Synced: a drift measurement alone cannot exit
    // recovery, and an already-desynced node stays Desynced.
    let mut recovering = DesyncFSM::new();
    recovering.on_sfn_wrap(false);
    recovering.on_beacon(true, true);
    assert_eq!(recovering.on_drift(drift, guard), DesyncState::Recovering);

    let mut desynced = DesyncFSM::new();
    desynced.on_sfn_wrap(false);
    assert_eq!(desynced.on_drift(drift, guard), DesyncState::Desynced);
}

#[test]
fn multi_root_version_conflict_vector_semantics() {
    // SEMANTICS-PIN ONLY (not an FSM drive): the version-conflict -> desync
    // trigger. The root-selection/version gate lives in the
    // gradient/root-selection layer (b7z9.24.2), not the desync FSM.
    // Merge note: beads-worker-4 drove on_sfn_wrap(false) here, but an SFN
    // wrap is not this vector's trigger — driving it would test SFN-wrap
    // behavior, not the version gate — so the semantics pin is kept.
    let v = find_case("multi_root_version_conflict_desync");
    assert_eq!(v["expected"], "desync");
    assert_ne!(v["version"], v["alternate_version"]);
}
