# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression guard for the fleet-guards.sh state-dir re-creation (tpcn).

The guards keep fleet_burn stderr at $STATE/fleet_burn.err, where
$STATE=/tmp/fleet-driver-state can vanish mid-run (tmp cleaner, reboot).
The 2> redirect opens BEFORE the helper process starts, so if the directory
is gone the helper never runs and its own os.makedirs self-heal
(fleet_burn.py) never executes — WASTE comes back empty every cycle and the
waste alarm stays blind until the guards restart.

The fix re-creates $STATE inside the loop before the helper invocation.
The loop body itself cannot be executed in a test (real bd store writes,
provider API — see test_fleet_guards_cycle_min.py), so this asserts the
structural invariant directly: within the while loop, a mkdir -p of $STATE
precedes the fleet_burn.py invocation line.
"""
from __future__ import annotations

import re
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "fleet-guards.sh"


def test_state_dir_recreated_before_helper_in_loop() -> None:
    text = SCRIPT.read_text()
    loop_start = text.index("while :; do")
    helper_call = text.index('python3 "$REPO/scripts/fleet_burn.py"', loop_start)
    segment = text[loop_start:helper_call]
    matches = re.findall(r'^(\s*)mkdir -p "\$STATE"$', segment, re.MULTILINE)
    assert matches, (
        "no 'mkdir -p \"$STATE\"' between loop start and the fleet_burn.py "
        "invocation — the 2>$W_ERR redirect will fail if /tmp loses $STATE "
        "mid-run and the helper's self-heal never runs (tpcn)"
    )
    # Indented: the re-creation must be inside the loop body, not dedented
    # back to startup level.
    assert all(m.startswith("    ") for m in matches)
