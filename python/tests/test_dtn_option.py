# SPDX-FileCopyrightText: The contributors to the LICHEN project
# SPDX-License-Identifier: GPL-3.0-or-later

"""DTN S-flag/HBH option tests consuming test/vectors/dtn_sflag_hbh.json
(spec 05-routing.md 9.8; bead 0kli)."""

import json
from pathlib import Path

import pytest

from lichen.routing.dtn_option import decide_expiry_action, parse_dtn_option

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "test" / "vectors" / "dtn_sflag_hbh.json").read_text()
)


def _option_bytes(case: dict) -> bytes:
    return bytes.fromhex(case["option_hex"])


@pytest.mark.parametrize("case", [c for c in VECTORS if c["type"] == "dtn_hbh"], ids=lambda c: c["name"])
def test_dtn_hbh_option(case: dict) -> None:
    parsed = parse_dtn_option(_option_bytes(case))
    expected = case["expected"]
    if expected == "reject_malformed":
        assert parsed is None
        return
    assert parsed is not None
    assert parsed.s_flag == bool(case["s_flag"])
    assert parsed.expiry_unix == case["expiry_unix"]
    if expected == "parse_no_store":
        assert parsed.s_flag is False


@pytest.mark.parametrize(
    "case", [c for c in VECTORS if c["type"] == "dtn_semantic"], ids=lambda c: c["name"]
)
def test_dtn_expiry_decision(case: dict) -> None:
    action = decide_expiry_action(
        case["expiry_unix"], case["now_unix"], case["wall_clock_valid"]
    )
    assert action == case["expected"]


def test_absent_option_is_none() -> None:
    # Only padding: no DTN intent.
    assert parse_dtn_option(bytes([0x01, 0x02, 0x00, 0x00])) is None
    assert parse_dtn_option(b"") is None


def test_duplicate_option_rejected() -> None:
    opt = bytes.fromhex("0305806553f600")
    assert parse_dtn_option(opt + opt) is None


def test_truncated_option_rejected() -> None:
    assert parse_dtn_option(bytes([0x03, 0x05, 0x80, 0x65])) is None


def test_zero_expiry_rejected() -> None:
    # Implementation-pinned: expiry==0 is the C fail-open "no validated
    # deadline" sentinel (routing/dtn.h); the spec is silent on it.
    assert parse_dtn_option(bytes.fromhex("03058000000000")) is None


def test_reserved_bits_ignored() -> None:
    # Spec-backed (9.8: reserved ignored on receive); duplicates the
    # vector case as a direct unit check.
    clean = parse_dtn_option(bytes.fromhex("0305006553f600"))
    noisy = parse_dtn_option(bytes.fromhex("03057f6553f600"))
    assert clean == noisy


def test_expiry_boundary_not_before_is_kept() -> None:
    # Implementation-pinned: expiry == now is not expired (strict <),
    # matching the C parser; the spec does not state the boundary.
    assert decide_expiry_action(1000, 1000, True) == "store_or_forward"
