# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""PoW join-gate tests (spec 02a 2a.5.4, bead b7z9.79 python slice)."""

from __future__ import annotations

import hashlib

import pytest

from lichen.timing.pow import (
    CHALLENGE_LEN,
    RESPONSE_LEN,
    solve_pow_response,
    verify_pow_response,
)

CHALLENGE = bytes(range(8))
IID = bytes.fromhex("0011223344556677")


def test_solve_and_verify_roundtrip() -> None:
    response = solve_pow_response(CHALLENGE, IID)
    assert response is not None
    assert len(response) == RESPONSE_LEN
    digest = hashlib.sha256(CHALLENGE + IID + response).digest()
    assert digest[0:2] == b"\x00\x00"


def test_verify_accepts_solved_and_rejects_rest() -> None:
    response = solve_pow_response(CHALLENGE, IID)
    assert response is not None
    assert verify_pow_response(CHALLENGE, IID, response)
    assert not verify_pow_response(CHALLENGE, IID, b"\x00\x00\x00\x01")
    wrong_challenge = bytes([0xFF]) * 8
    assert not verify_pow_response(wrong_challenge, IID, response)


def test_verify_rejects_malformed_lengths() -> None:
    assert not verify_pow_response(b"\x00" * 7, IID, b"\x00" * 4)
    assert not verify_pow_response(CHALLENGE, b"\x01" * 7, b"\x00" * 4)
    assert not verify_pow_response(CHALLENGE, IID, b"\x00" * 3)
    assert not verify_pow_response(CHALLENGE, IID, b"\x00" * 5)


def test_known_vector_determinism() -> None:
    """The solver is deterministic for a given (challenge, iid) pair."""
    a = solve_pow_response(CHALLENGE, IID)
    b = solve_pow_response(CHALLENGE, IID)
    assert a == b
    digest = hashlib.sha256(CHALLENGE + IID + (a or b"")).digest()
    assert digest[0] == 0


def test_zero_response_edge() -> None:
    """The all-zero response verifies when the digest prefix is zeros."""
    response = b"\x00\x00\x00\x00"
    digest = hashlib.sha256(CHALLENGE + IID + response).digest()
    assert verify_pow_response(CHALLENGE, IID, response) == (
        digest[0:2] == b"\x00\x00"
    )


def test_challenge_length_validated() -> None:
    with pytest.raises(ValueError):
        solve_pow_response(b"\x00" * 7, IID)
    with pytest.raises(ValueError):
        solve_pow_response(b"\x00" * 9, IID)
    with pytest.raises(ValueError):
        solve_pow_response(CHALLENGE, b"\x01" * 7)


def test_constants() -> None:
    assert CHALLENGE_LEN == 8
    assert RESPONSE_LEN == 4
