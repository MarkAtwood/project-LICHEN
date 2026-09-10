# SPDX-License-Identifier: GPL-3.0-or-later
"""Rejection tests for the fleet-guards.sh CYCLE_MIN startup guard.

The guard at the top of scripts/fleet-guards.sh must reject any cycle
argument that is not a plain ASCII decimal integer without leading zeros
and not above 1440, before any side effect (bd writes, provider API).
Expected outcomes are hand-enumerated, not derived from the script.

Two environments are exercised:
- the default bash startup of the test host (BASH_ENV explicitly cleared,
  so a host-level BASH_ENV cannot collapse the two environments), and
- a BASH_ENV stub that disables the globasciiranges shopt AND forces a
  collation-folding UTF-8 locale, which together make the old [0-9]
  range pattern admit multibyte digits (the 048n defect; the explicit-
  list pattern must reject in both states).

KNOWN WINDOW (inherent, no dry-run mode in the script): if a guard
regression makes a rejection case accepted, the script enters the guard
loop and runs one live cycle — real bd calls against the hardcoded
production REPO and a provider credits GET — before the 30 s timeout
kills it. The failure is reported with per-case context.

Only rejection cases run the script; accepted values enter the guard
loop and must not be exercised here.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent / "fleet-guards.sh"

SHOPT_OFF = "shopt -u globasciiranges 2>/dev/null || true\n"

# (arg, why) — every value must exit 1 with the usage error on stderr.
# NOTE: no empty-string case — an empty argv[1] hits "${1:-10}" and is
# treated as the default (10), so the ''| alternative in the case is
# defensively unreachable; accepted values must not run the loop here.
REJECT_CASES = [
    ("abc", "non-numeric"),
    ("-3", "negative"),
    ("+5", "explicit sign"),
    (" 5", "leading space"),
    ("5 ", "trailing space"),
    ("0", "zero"),
    ("00", "leading zero"),
    ("08", "leading zero (would be invalid octal)"),
    ("010", "leading zero (would parse as octal 8)"),
    ("١٢٣", "Arabic-Indic digits (collation folds into 0-9)"),
    ("１４４", "fullwidth digits"),
    ("१२", "Devanagari digits"),
    ("5٣", "mixed ASCII + Arabic-Indic digit"),
    ("12x", "trailing junk"),
    ("1441", "one over the cap"),
    ("9999", "four digits over the cap"),
    ("99999", "five digits, length-bounded"),
    ("99999999999999999999999", "wraps signed 64-bit in arithmetic"),
    ("307445734561825861", "wraparound PoC value from c5s6"),
]


def _run(value: str, bash_env: Path | None) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    if bash_env is None:
        env.pop("BASH_ENV", None)  # hermetic: host BASH_ENV must not leak in
    else:
        env["BASH_ENV"] = str(bash_env)
    return subprocess.run(
        ["bash", str(SCRIPT), value],
        capture_output=True,
        timeout=30,
        env=env,
    )


def _assert_rejected(value: str, why: str, bash_env: Path | None) -> None:
    try:
        r = _run(value, bash_env)
    except subprocess.TimeoutExpired as e:
        pytest.fail(
            f"{why}: guard ACCEPTED {value!r} — the script entered the "
            "guard loop and ran one live cycle (real bd store, provider "
            "API) before the timeout kill"
        )
    assert r.returncode == 1, f"{why}: rc={r.returncode} for {value!r}"
    assert b"cycle_minutes" in r.stderr, (
        f"{why}: missing usage error for {value!r}, stderr={r.stderr!r}"
    )


def _folding_locale() -> str | None:
    """Return an installed UTF-8 locale whose collation folds multibyte
    digits into the [0-9] range, verified with an isolated probe of the
    pre-048n range pattern under globasciiranges off, or None."""
    try:
        listed = subprocess.run(
            ["locale", "-a"], capture_output=True, text=True, timeout=10
        ).stdout.split()
    except OSError:
        return None
    candidates = [c for c in listed if c.lower().endswith((".utf8", ".utf-8"))]
    candidates.sort(key=lambda c: (not c.lower().startswith("en_us"), c))
    for loc in candidates:
        probe = subprocess.run(
            ["bash", "-c", 'case "١٢٣" in *[!0-9]*) echo REJECT;; *) echo PASS;; esac'],
            capture_output=True,
            text=True,
            env={**os.environ, "LC_ALL": loc, "BASH_ENV": ""},
        )
        if probe.stdout.strip() == "PASS":
            return loc
    return None


def test_rejects_all_bad_forms_default_startup() -> None:
    for value, why in REJECT_CASES:
        _assert_rejected(value, why, None)


def test_rejects_all_bad_forms_with_globasciiranges_off(tmp_path: Path) -> None:
    # Reproduces the 048n environment: globasciiranges off plus a
    # collation-folding UTF-8 locale makes the old [0-9] range admit
    # Unicode digits. The probe asserts the defect condition is actually
    # present in the chosen environment; without one the test skips
    # rather than passing vacuously.
    locale = _folding_locale()
    if locale is None:
        pytest.skip("no collation-folding UTF-8 locale installed: 048n condition unreproducible")
    stub = tmp_path / "bashenv.sh"
    stub.write_text(SHOPT_OFF + f'export LC_ALL="{locale}"\n')
    for value, why in REJECT_CASES:
        _assert_rejected(value, why, stub)