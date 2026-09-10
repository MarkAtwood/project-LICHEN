# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for fleet_burn.py 24h retained-baseline tracking (lh2z).

Deterministic: explicit epoch timestamps, no sleeps, no provider calls.
Expected values are hand-computed literals, not derived from the module.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fleet_burn  # noqa: E402

T0 = 1_760_000_000  # arbitrary fixed epoch
SNAP = "burn-snapshot.json"


def _read(tmp_path: Path) -> dict:
    return json.loads((tmp_path / SNAP).read_text())


def test_first_run_establishes_baseline_without_evaluating(tmp_path: Path) -> None:
    r = fleet_burn.update(str(tmp_path), used=100, closes=50, now=T0)
    assert r == {"evaluated": False, "reason": "baseline-established"}
    assert _read(tmp_path) == {"usage": 100, "ts": T0}


def test_mid_window_observations_do_not_touch_baseline(tmp_path: Path) -> None:
    # The original bug: every 10-minute cycle overwrote the snapshot, so
    # age never crossed 24h. Baseline ts/usage must survive mid-window.
    fleet_burn.update(str(tmp_path), used=100, closes=50, now=T0)
    for i in range(1, 143):  # 142 mid-window cycles, last at T0+85200 (<86400)
        r = fleet_burn.update(str(tmp_path), used=100 + i, closes=50, now=T0 + i * 600)
        assert r["evaluated"] is False
    assert _read(tmp_path) == {"usage": 100, "ts": T0}


def test_window_boundary_exactly_24h_does_not_evaluate(tmp_path: Path) -> None:
    # Guard compares age > 86400 strictly; age == 86400 must not evaluate.
    fleet_burn.update(str(tmp_path), used=100, closes=50, now=T0)
    r = fleet_burn.update(str(tmp_path), used=200, closes=50, now=T0 + 86400)
    assert r["evaluated"] is False
    assert _read(tmp_path) == {"usage": 100, "ts": T0}


def test_sequence_crossing_24h_evaluates_and_rolls_baseline(tmp_path: Path) -> None:
    # Acceptance: a deterministic sequence of 10-minute observations
    # crosses 24h and triggers the cost-per-close evaluation.
    fleet_burn.update(str(tmp_path), used=1000, closes=0, now=T0)
    now = T0
    for _ in range(144):  # 144*600 = 86400s, still inside the window
        now += 600
        fleet_burn.update(str(tmp_path), used=1000, closes=0, now=now)
    now += 600  # T0 + 87000: first observation past the window
    r = fleet_burn.update(str(tmp_path), used=1300, closes=100, now=now)
    # burn = 1300-1000 = 300; cpc = 300/100 = 3.00; over threshold is strict >
    assert r["evaluated"] is True
    assert r["burn"] == 300
    assert r["closes"] == 100
    assert r["cpc"] == 3.0
    assert r["cpc_str"] == "3.00"
    assert r["over"] is False
    assert _read(tmp_path) == {"usage": 1300, "ts": now}


def test_over_threshold_flags_waste(tmp_path: Path) -> None:
    fleet_burn.update(str(tmp_path), used=1000, closes=0, now=T0)
    r = fleet_burn.update(str(tmp_path), used=1500, closes=100, now=T0 + 86500)
    # burn 500 / 100 closes = $5.00/close > $3.00
    assert r["evaluated"] is True
    assert r["cpc_str"] == "5.00"
    assert r["over"] is True


def test_zero_closes_at_window_end_rolls_without_evaluating(tmp_path: Path) -> None:
    fleet_burn.update(str(tmp_path), used=1000, closes=0, now=T0)
    r = fleet_burn.update(str(tmp_path), used=1100, closes=0, now=T0 + 86500)
    assert r == {"evaluated": False, "rolled": True, "burn": 100, "closes": 0}
    assert _read(tmp_path) == {"usage": 1100, "ts": T0 + 86500}


def test_usage_reset_rolls_without_evaluating(tmp_path: Path) -> None:
    fleet_burn.update(str(tmp_path), used=1000, closes=0, now=T0)
    r = fleet_burn.update(str(tmp_path), used=50, closes=10, now=T0 + 86500)
    assert r == {"evaluated": False, "rolled": True, "burn": -950, "closes": 10}
    assert _read(tmp_path) == {"usage": 50, "ts": T0 + 86500}


def test_invalid_observation_never_establishes_nor_rolls(tmp_path: Path) -> None:
    # total_used prints 0 when the provider call fails.
    r = fleet_burn.update(str(tmp_path), used=0, closes=50, now=T0)
    assert r == {"evaluated": False, "reason": "invalid-observation"}
    assert not (tmp_path / SNAP).exists()
    fleet_burn.update(str(tmp_path), used=100, closes=50, now=T0)
    r = fleet_burn.update(str(tmp_path), used=0, closes=50, now=T0 + 86500)
    assert r == {"evaluated": False, "reason": "invalid-observation"}
    assert _read(tmp_path) == {"usage": 100, "ts": T0}  # not rolled by a failed call


def test_restart_continues_window_from_persisted_baseline(tmp_path: Path) -> None:
    # Restart = a new process reading the existing snapshot file; each
    # update() call here already models a fresh process, and the mid-window
    # assertions prove the baseline survives across them.
    fleet_burn.update(str(tmp_path), used=100, closes=50, now=T0)
    r = fleet_burn.update(str(tmp_path), used=110, closes=50, now=T0 + 600)
    assert r["evaluated"] is False
    assert _read(tmp_path) == {"usage": 100, "ts": T0}


def test_corrupt_snapshot_reestablishes_baseline(tmp_path: Path) -> None:
    (tmp_path / SNAP).write_text("{not json")
    r = fleet_burn.update(str(tmp_path), used=100, closes=50, now=T0)
    assert r == {"evaluated": False, "reason": "baseline-established"}
    assert _read(tmp_path) == {"usage": 100, "ts": T0}


def test_fractional_negative_usage_is_rejected_not_truncated(tmp_path: Path) -> None:
    # Raw -0.5 used to int()-truncate to 0 and pass as valid (v0gm).
    (tmp_path / SNAP).write_text(json.dumps({"usage": -0.5, "ts": T0 - 90000}))
    r = fleet_burn.update(str(tmp_path), used=100, closes=50, now=T0)
    assert r == {"evaluated": False, "reason": "baseline-established"}
    assert _read(tmp_path) == {"usage": 100, "ts": T0}


def test_baseline_shape_rejections_reestablish_baseline(tmp_path: Path) -> None:
    # Bools, numeric strings, and fractional floats are corrupt shapes;
    # each must re-establish rather than coerce.
    for raw in (
        '{"usage": true, "ts": %d}' % (T0 - 90000),
        '{"usage": "100", "ts": %d}' % (T0 - 90000),
        '{"usage": 100.5, "ts": %d}' % (T0 - 90000),
    ):
        (tmp_path / SNAP).write_text(raw)
        r = fleet_burn.update(str(tmp_path), used=100, closes=50, now=T0)
        assert r == {"evaluated": False, "reason": "baseline-established"}, raw
        assert _read(tmp_path) == {"usage": 100, "ts": T0}


def test_integral_float_baseline_is_tolerated(tmp_path: Path) -> None:
    # Legacy fleet-driver.sh snapshots wrote float usage/ts.
    (tmp_path / SNAP).write_text(json.dumps({"usage": 100.0, "ts": float(T0 - 90000)}))
    # Mid-window observation (age 600s < 24h): must not evaluate and must
    # leave the tolerated baseline untouched.
    r = fleet_burn.update(str(tmp_path), used=110, closes=50, now=T0 - 90000 + 600)
    assert r["evaluated"] is False
    assert _read(tmp_path) == {"usage": 100.0, "ts": T0 - 90000}


def test_no_tmp_files_linger_after_update(tmp_path: Path) -> None:
    fleet_burn.update(str(tmp_path), used=100, closes=50, now=T0)
    fleet_burn.update(str(tmp_path), used=200, closes=50, now=T0 + 86500)
    assert list(tmp_path.glob("*.tmp")) == []


def test_cli_matches_library(tmp_path: Path) -> None:
    import subprocess

    out = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("fleet_burn.py")),
         str(tmp_path), "100", "50", str(T0)],
        capture_output=True, text=True, check=True,
    )
    assert json.loads(out.stdout) == {"evaluated": False, "reason": "baseline-established"}
    assert _read(tmp_path) == {"usage": 100, "ts": T0}
