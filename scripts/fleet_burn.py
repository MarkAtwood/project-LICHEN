# SPDX-License-Identifier: GPL-3.0-or-later
"""Retained-baseline 24h burn tracking for the fleet-guards waste alarm.

fleet-guards.sh previously overwrote burn-snapshot.json every 10-minute
cycle, so the snapshot age never crossed 24h and the cost-per-close waste
alarm never evaluated (lh2z). This module keeps a retained baseline: the
snapshot is written only on the first valid observation or after a full
24h window has elapsed and been evaluated.

ponytail: one evaluation per 24h window (detection latency up to ~48h for
waste starting just after an evaluation). Upgrade path: rolling history
for a sliding trailing-24h window evaluated every cycle.
"""
from __future__ import annotations

import json
import os
import sys

WINDOW_S = 86400
THRESHOLD_CPC = 3.0
SNAPSHOT_NAME = "burn-snapshot.json"


def _coerce_count(v: object) -> int | None:
    """Validate a raw JSON counter and coerce to non-negative int, or None.

    Coercion happens only after the RAW value is validated: bools (an int
    subclass), non-numeric shapes, and negatives — including fractional
    negatives in (-1, 0) that int() truncates to 0 — must never pass as
    valid (v0gm). Integral floats are tolerated (legacy snapshots).
    """
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        n = v
    elif isinstance(v, float):
        if not v.is_integer():
            return None  # fractional counters are corrupt, not truncatable
        n = int(v)
    else:
        return None  # str/list/dict/None are never coerced silently
    return n if n >= 0 else None


def _load_baseline(path: str) -> dict | None:
    """Return {'usage': int, 'ts': int} or None if missing/corrupt/absurd."""
    try:
        with open(path) as f:
            d = json.load(f)
        usage = _coerce_count(d["usage"])
        ts = _coerce_count(d["ts"])
        if usage is None or ts is None:
            return None  # semantically absurd values are corrupt
        return {"usage": usage, "ts": ts}
    except Exception:
        return None


def _write_baseline(path: str, usage: int, ts: int) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump({"usage": usage, "ts": ts}, f)
    os.replace(tmp, path)  # atomic: concurrent guards never read a torn file


def update(
    state_dir: str,
    used: int,
    closes: int,
    now: int,
    window: int = WINDOW_S,
    threshold: float = THRESHOLD_CPC,
) -> dict:
    """Advance the burn baseline by one observation.

    'used' is total provider usage in whole USD, 'closes' the 24h closure
    count, 'now' the observation time in epoch seconds. Returns a dict;
    result['evaluated'] is True only when a full window elapsed and a
    cost-per-close was computed (then 'burn', 'closes', 'cpc', 'cpc_str',
    'over' are present).
    """
    # Self-heal: the guards loop runs for weeks; if the state dir vanishes
    # mid-run (tmp cleaner, manual cleanup), recreate it instead of crashing
    # every cycle until restart (rmza).
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, SNAPSHOT_NAME)
    if used <= 0:
        # Provider call failed (total_used prints 0 on error): an invalid
        # observation must neither poison nor roll the baseline.
        return {"evaluated": False, "reason": "invalid-observation"}
    baseline = _load_baseline(path)
    if baseline is None:
        # First run, restart after state loss, or corrupt snapshot.
        _write_baseline(path, used, now)
        return {"evaluated": False, "reason": "baseline-established"}
    age = now - baseline["ts"]
    if age < 0:
        # Clock stepped backwards (or a future ts got in): a negative age
        # would be treated as mid-window forever, disabling the alarm.
        # Treat the baseline as corrupt and re-establish at 'now'.
        _write_baseline(path, used, now)
        return {"evaluated": False, "reason": "baseline-reestablished-clock"}
    if age <= window:
        return {"evaluated": False, "age": age}
    burn = used - baseline["usage"]
    # Roll the window even when this one cannot produce a CPC, so a
    # zero-close or credit-reset window cannot stall evaluation forever.
    _write_baseline(path, used, now)
    if closes <= 0 or burn <= 0:
        return {"evaluated": False, "rolled": True, "burn": burn, "closes": closes}
    cpc = burn / closes
    return {
        "evaluated": True,
        "burn": burn,
        "closes": closes,
        "cpc": cpc,
        "cpc_str": f"{cpc:.2f}",
        "over": cpc > threshold,
    }


def main(argv: list[str]) -> int:
    state_dir, used, closes, now = argv[1], int(argv[2]), int(argv[3]), int(argv[4])
    print(json.dumps(update(state_dir, used, closes, now)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
