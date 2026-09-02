# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Proof-of-Work for TDMA join admission (spec 02a 2a.5.4, bead b7z9.79).

The root advertises an 8-byte ``pow_challenge`` nonce in the beacon CBOR
options under join pressure. Joiners MUST reply with a 4-byte
``pow_response`` such that ``SHA-256(pow_challenge || joiner_iid ||
pow_response)`` starts with 2 zero bytes (16 leading zero bits). PoW is
disabled by default; absence of the challenge TLV means no PoW required.
"""

from __future__ import annotations

import hashlib
import struct

# CBOR options TLV type for the 8-byte pow_challenge (bead b7z9.79;
# provisional project-local type after the 0x01-0x06 chain). The joiner's
# 4-byte pow_response travels in the join frame, not in a beacon TLV, so
# there is exactly one PoW TLV type.
APP_DATA_TYPE_POW_CHALLENGE = 0x07

CHALLENGE_LEN = 8
RESPONSE_LEN = 4
DIFFICULTY_PREFIX_BYTES = 2

_POW_RESPONSE_LIMIT = 1 << 32


def _meets_difficulty(digest: bytes) -> bool:
    """True when the digest starts with 2 zero bytes (16 leading zeros)."""
    return digest[0:DIFFICULTY_PREFIX_BYTES] == b"\x00\x00"


def solve_pow_response(
    challenge: bytes, joiner_iid: bytes, *, max_iterations: int = _POW_RESPONSE_LIMIT
) -> bytes | None:
    """Derive a 4-byte pow_response meeting the difficulty (2 zero bytes).

    Args:
        challenge: 8-byte nonce from the beacon.
        joiner_iid: The joining node's 8-byte EUI-64/IID.
        max_iterations: Search bound; exhaustive over the 4-byte response.

    Returns:
        The 4-byte pow_response (big-endian counter), or None when the
        search space is exhausted without a solution (cannot happen for
        the canonical 2-byte difficulty within 2^32 iterations).
    """
    if len(challenge) != CHALLENGE_LEN:
        raise ValueError(f"challenge must be {CHALLENGE_LEN} bytes")
    if len(joiner_iid) != 8:
        raise ValueError("joiner_iid must be 8 bytes")
    prefix = challenge + joiner_iid
    for counter in range(max_iterations):
        response = struct.pack(">I", counter)
        if _meets_difficulty(hashlib.sha256(prefix + response).digest()):
            return response
    return None


def verify_pow_response(
    challenge: bytes, joiner_iid: bytes, response: bytes
) -> bool:
    """Verify a joiner's pow_response against the advertised challenge.

    Args:
        challenge: 8-byte nonce from the beacon.
        joiner_iid: The joining node's 8-byte IID.
        response: The joiner's 4-byte pow_response.

    Returns:
        True when SHA-256(challenge || joiner_iid || response) starts with
        2 zero bytes; False otherwise (including malformed lengths).
    """
    if len(challenge) != CHALLENGE_LEN or len(joiner_iid) != 8:
        return False
    if type(response) is not bytes or len(response) != RESPONSE_LEN:
        return False
    return _meets_difficulty(
        hashlib.sha256(challenge + joiner_iid + response).digest()
    )
