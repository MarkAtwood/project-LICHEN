# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression guard for the fleet-guards.sh provider-outage latch (7djg).

total_used() prints 0 on any OpenRouter credits-API failure; fleet_burn.py
then returns {"evaluated": false, "reason": "invalid-observation"} without
touching the baseline. Before the fix, the guards discarded 'reason' and
treated this as the normal mid-window case: no WARN, every cycle, forever —
with the $2000 burn marker (same dead USED) dying alongside the waste alarm.

The fix latches one bd alarm per outage episode (flag
$REPO/.fleet-provider-obs, mirroring the .fleet-waste-helper pattern) and
clears it on the first valid observation. The loop body cannot be executed
in a test (real bd store writes, provider API — see
test_fleet_guards_cycle_min.py), so this asserts the structural invariants:
  1. the guards extract 'reason' from the helper JSON,
  2. an invalid-observation latch fires exactly once per episode,
  3. the latch clears only on a non-invalid reason inside the healthy-parse
     branch (not on parse failure or missing output — those must not clear),
  4. fleet_burn.py actually emits the invalid-observation reason for used<=0
     (the contract the shell half depends on), checked by executing the
     helper's pure update() function directly.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
GUARDS = SCRIPT_DIR / "fleet-guards.sh"

_spec = importlib.util.spec_from_file_location("fleet_burn", SCRIPT_DIR / "fleet_burn.py")
assert _spec and _spec.loader
fleet_burn = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("fleet_burn", fleet_burn)
_spec.loader.exec_module(fleet_burn)


def test_invalid_observation_reason_is_latched_and_cleared() -> None:
    text = GUARDS.read_text()

    # 1. reason extraction exists alongside evaluated.
    assert ".get('reason', '')" in text, "guards no longer extract reason"

    # 2. Latch: invalid-observation triggers the alarm path, gated by the
    #    episode flag so it fires once, not every cycle.
    assert '[ "$W_REASON" = "invalid-observation" ]' in text
    assert '.fleet-provider-obs' in text
    latch_pos = text.index('[ "$W_REASON" = "invalid-observation" ]')
    flag_write = text.index('> "$REPO/.fleet-provider-obs"', latch_pos)
    alarm_create = text.index("Provider credits observations failing", latch_pos)
    assert latch_pos < flag_write < alarm_create, "latch must set the flag before/along the alarm"

    # 3. Clear: the flag is removed only for a non-invalid reason, and only
    #    inside the healthy-parse branch (after the [ -z "$WASTE" ] and
    #    PARSE_FAIL branches, whose bodies must not clear it).
    clear_marker = 'if [ "$W_REASON" != "invalid-observation" ]; then rm -f "$REPO/.fleet-provider-obs"; fi'
    clear_pos = text.index(clear_marker)
    empty_branch = text.index('if [ -z "$WASTE" ]')
    parse_fail_branch = text.index('"PARSE_FAIL" ]; then')
    healthy_branch = text.index("rm -f \"$REPO/.fleet-waste-helper\"")
    assert empty_branch < parse_fail_branch < healthy_branch < clear_pos, (
        "latch clear must live in the healthy-parse branch, after the "
        "empty/PARSE_FAIL branches"
    )


def test_fleet_burn_emits_invalid_observation_reason(tmp_path: Path) -> None:
    # Independent oracle: the helper's own documented contract is that a
    # non-positive observation (provider failure prints 0) yields
    # invalid-observation and never writes the baseline.
    result = fleet_burn.update(str(tmp_path), 0, 5, 1_700_000_000)
    assert result == {"evaluated": False, "reason": "invalid-observation"}
    assert not (tmp_path / fleet_burn.SNAPSHOT_NAME).exists(), (
        "invalid observation must not establish a baseline"
    )
    # Sanity: a valid first observation establishes the baseline with a
    # different reason, so the latch-clear condition would engage.
    result = fleet_burn.update(str(tmp_path), 10, 5, 1_700_000_000)
    assert result == {"evaluated": False, "reason": "baseline-established"}
