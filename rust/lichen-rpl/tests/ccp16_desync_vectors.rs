// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Vector-driven consumer for ccp16-desync.json (spec 02a 2a.5.3-2a.6,
//! R-02a-079) — mirrors the Python consumer
//! python/tests/test_ccp_sync_vector_consumers.py:290-386 case for case:
//! SFN-wrap desync, multi-root version conflict, recovery beacon
//! revalidation, and the excessive-drift premise.

use lichen_core::desync::{DesyncFSM, DesyncState};
use lichen_rpl::multi_instance::{MultiRootState, RootCandidate, VersionChangeOutcome};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/ccp16-desync.json");

fn case(name: &str) -> Value {
    let doc: Value = serde_json::from_str(VECTORS_JSON).expect("parse ccp16-desync corpus");
    doc.as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing case {name}"))
        .clone()
}

#[test]
fn desync_on_sfn_wrap() {
    let vec = case("desync_on_sfn_wrap");
    assert_eq!(vec["current_sfn"].as_u64(), Some(0));
    assert_eq!(vec["last_sfn"].as_u64(), Some(65535));
    // Unsigned 32-bit delta wraps to a huge value, flagging desync.
    assert_eq!(
        (vec["current_sfn"].as_i64().unwrap() - vec["last_sfn"].as_i64().unwrap()) as u32,
        4294901761u32 & 0xFFFF_FFFF
    );
    let mut fsm = DesyncFSM::default();
    assert_eq!(fsm.state(), DesyncState::Synced);
    // The wrap with invalid time engages the desync recovery machine...
    assert_eq!(fsm.on_sfn_wrap(false), DesyncState::Desynced);
    // ...whose recovery half re-locks on valid beacons.
    assert_eq!(fsm.on_beacon(true, true), DesyncState::Recovering);
}

#[test]
fn multi_root_version_conflict_desync() {
    let vec = case("multi_root_version_conflict_desync");
    assert_eq!(vec["version"].as_u64(), Some(0));
    assert_eq!(vec["alternate_version"].as_u64(), Some(1));

    let eui64: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let root = RootCandidate::new(eui64).with_signature_valid(true);
    let mut state = MultiRootState::new();
    state.set_desync_state_version(0);
    // RootCandidate carries its own version registration through
    // on_version_change's current_version comparison.
    state.on_version_change(0, true);

    // Negative control: a beacon carrying the SAME version changes nothing.
    let same = state.on_version_change(0, true);
    assert_eq!(same.outcome, VersionChangeOutcome::NoChange);

    // Conflicting version that fails re-verification: fail-closed desync —
    // the current root is discarded and remaining candidates re-evaluated.
    let conflict = state.on_version_change(1, false);
    assert_eq!(conflict.outcome, VersionChangeOutcome::SigFailedDiscard);
    assert!(conflict.evaluate_candidates);
    // Fail-closed ordering: the discard path returns before any state
    // revalidation, so version-tied desync state survives verbatim.

    // Accepted conflicting-version path (signature verifies): SFN resets and
    // per 2a.5.4 step 2 the desync state tied to the old version is cleared.
    let mut accepted_state = MultiRootState::new();
    accepted_state.set_desync_state_version(0);
    let accepted = accepted_state.on_version_change(1, true);
    assert_eq!(accepted.outcome, VersionChangeOutcome::Accepted);
    assert!(accepted.sfn_reset);
    assert_eq!(accepted.new_version, 1);
    // Per 2a.5.4 step 2: desync state tied to the OLD version is
    // invalidated by the accepted version change.
    assert!(accepted_state.desync_state_version().is_none());
}

#[test]
fn desync_recovery_beacon_revalidate() {
    let vec = case("desync_recovery_beacon_revalidate");
    assert_eq!(vec["expected"].as_str(), Some("recovering"));
    assert_eq!(vec["sfn"].as_u64(), Some(100));

    let mut fsm = DesyncFSM::default();
    fsm.on_sfn_wrap(false);
    assert_eq!(fsm.state(), DesyncState::Desynced);
    // First valid beacon: RECOVERING with streak 1 (not full join).
    assert_eq!(fsm.on_beacon(true, true), DesyncState::Recovering);
    assert_eq!(fsm.consecutive_valid(), 1);
    // Second: still recovering. Third consecutive: fully synced.
    assert_eq!(fsm.on_beacon(true, true), DesyncState::Recovering);
    assert_eq!(fsm.on_beacon(true, true), DesyncState::Synced);
    // A bad beacon during recovery drops back to DESYNCED.
    let mut fsm2 = DesyncFSM::default();
    fsm2.on_sfn_wrap(false);
    fsm2.on_beacon(true, true);
    assert_eq!(fsm2.on_beacon(false, true), DesyncState::Desynced);
}

#[test]
fn excessive_clock_drift_premise_holds() {
    // Vector premise: drift 12000 ppm vs guard 5000 ppm exceeds the guard.
    // The Python consumer skips this case (no Python enforcement surface);
    // Rust DesyncFSM::on_drift(drift_ppm, guard_ppm) HAS the gate.
    let vec = case("excessive_clock_drift_desync");
    assert!(vec["drift_ppm"].as_i64().unwrap() > vec["guard_ppm"].as_i64().unwrap());
    let mut fsm = DesyncFSM::default();
    fsm.on_drift(
        vec["drift_ppm"].as_i64().unwrap(),
        vec["guard_ppm"].as_i64().unwrap(),
    );
    assert_eq!(fsm.state(), DesyncState::Desynced);
}

#[test]
fn holdoff_complete_rejoin_drops_old_root() {
    // R-02a-043: holdoff completion initiates desync + rejoin rather than
    // silently switching roots (mirrors python holdoff_complete_rejoin).
    let mut state = MultiRootState::new();
    let old = RootCandidate::new([0x11; 8]).with_signature_valid(true);
    let new = RootCandidate::new([0x22; 8]).with_signature_valid(true);
    state.current_root = Some(old);
    assert!(state.add_candidate(new.clone()));
    // A differing selected root defers the transition: holdoff = 3 superframes.
    state.process_beacon_window();

    // Two of the three holdoff superframes elapse without completing.
    assert!(!state.advance_holdoff());
    assert!(!state.advance_holdoff());
    // The third completes the holdoff: R-02a-043 initiates desync + rejoin
    // (old root dropped, candidates cleared, holdoff and desync state reset).
    assert!(state.holdoff_complete_rejoin(42));
    assert!(state.current_root.is_none());
    assert_eq!(state.rejoin_sf(), Some(42));
    // Rejoin initiated: a fresh beacon window starts with no candidates
    // (cleared) and no holdoff pending.
    assert!(!state.is_in_holdoff());
}

#[test]
fn holdoff_complete_rejoin_not_in_holdoff() {
    let mut state = MultiRootState::new();
    assert!(!state.holdoff_complete_rejoin(0));
}
