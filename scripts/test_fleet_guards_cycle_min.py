# SPDX-License-Identifier: GPL-3.0-or-later
"""Rejection tests for the fleet-guards.sh CYCLE_MIN startup guard.

The guard at the top of scripts/fleet-guards.sh must reject any cycle
argument that is not a plain ASCII decimal integer without leading zeros
and not above 1440, before any side effect (bd writes, provider API).
Expected outcomes are hand-enumerated, not derived from the script.

Two environments are exercised:
- the default bash startup of the test host, and
- a BASH_ENV stub that disables the globasciiranges shopt, which makes
  the old [0-9] range pattern collation-fold multibyte digits under
  UTF-8 locales (the 048n defect; the explicit-list pattern must reject
  in both states).

Only rejection cases run the script; accepted values enter the guard
loop (real bd store, provider API) and must not be exercised here.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "fleet-guards.sh"

SHOPT_OFF_STUB = "shopt -u globasciiranges 2>/dev/null || true\n"

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

ACCEPTED_VALUES = ["1", "10", "1440"]


def _run(value: str, bash_env: Path | None) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    if bash_env is not None:
        env["BASH_ENV"] = str(bash_env)
    return subprocess.run(
        ["bash", str(SCRIPT), value],
        capture_output=True,
        timeout=30,
        env=env,
    )


def _assert_rejected(value: str, why: str, bash_env: Path | None) -> None:
    r = _run(value, bash_env)
    assert r.returncode == 1, f"{why}: rc={r.returncode} for {value!r}"
    assert b"cycle_minutes" in r.stderr, (
        f"{why}: missing usage error for {value!r}, stderr={r.stderr!r}"
    )


def test_rejects_all_bad_forms_default_startup() -> None:
    for value, why in REJECT_CASES:
        _assert_rejected(value, why, None)


def test_rejects_all_bad_forms_with_globasciiranges_off(tmp_path: Path) -> None:
    # Reproduces the 048n environment: with globasciiranges off the old
    # [0-9] range admitted Unicode digits under UTF-8 collation.
    stub = tmp_path / "bashenv.sh"
    stub.write_text(SHOPT_OFF_STUB)
    for value, why in REJECT_CASES:
        _assert_rejected(value, why, stub)


def test_accepted_values_are_digit_pure_form() -> None:
    # Oracle for the pattern itself (no side effects): each accepted value
    # must contain only ASCII digits — this is what the guard enforces so
    # the length/magnitude checks at the next line stay authoritative.
    for value in ACCEPTED_VALUES:
        assert value.isascii() and value.isdigit()
        assert 1 <= int(value) <= 1440