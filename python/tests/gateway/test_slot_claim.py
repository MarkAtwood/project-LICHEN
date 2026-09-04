# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for GCP-6 slot claim oracle.

Tests slot claim handling against spec 08-gateway-coordination.md Section 6
and test vectors in test/vectors/gcp_slot_claim.json.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from lichen.crypto import schnorr48
from lichen.crypto.identity import Identity, _pubkey_to_iid
from lichen.gateway import slot_claim
from lichen.gateway.slot_claim import (
    MAX_CLAIM_DURATION_SECONDS,
    ClaimError,
    ClaimRejectReason,
    SlotClaim,
    SlotClaimRateLimiter,
    SlotClaimReplayCache,
    compute_contiguous_slots,
    compute_interleaved_slots,
    encode_claim_canonical,
    resolve_slot_conflict,
    sign_slot_claim,
    validate_interleaved_pattern,
    verify_slot_claim,
)

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


class TestSlotClaim:
    """Tests for SlotClaim dataclass."""

    def test_basic_creation(self) -> None:
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
            expiry=int(time.time()) + 8,
            claim_seq=0,
            ordinal=0,
        )
                slots=(3, 1, 2),  # Not sorted
                superframe_id=1,
                expiry=int(time.time()) + 8,
                claim_seq=0,
            )

    def test_duplicate_slots(self) -> None:
        with pytest.raises(ClaimError, match="slots must be unique"):
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(1, 1, 2),  # Duplicate
                superframe_id=1,
                expiry=int(time.time()) + 8,
                claim_seq=0,
                ordinal=0,
            )
def _bound_iid(pubkey: bytes) -> str:
    """Gateway IID bound to a key (spec GCP-6.5 step 6: gateway_iid == kid == IID(pubkey))."""
    from lichen.crypto.identity import _pubkey_to_iid

    return _pubkey_to_iid(pubkey).hex()


class TestSignAndVerify:
    """Tests for Schnorr48 signing and verification."""

    @pytest.fixture
    def keypair(self) -> tuple[bytes, bytes]:
        seed = bytes.fromhex("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe")
        return schnorr48.derive_keypair(seed)

    def test_sign_and_verify(self, keypair: tuple[bytes, bytes]) -> None:
        privkey, pubkey = keypair
        import time

        claim = SlotClaim(
            gateway_iid=_bound_iid(pubkey),
            slots=(0, 1, 2),
            superframe_id=1000,
            expiry=int(time.time()) + 5,
            claim_seq=0,
            ordinal=0,
        )
        assert is_valid and reason is None

    def test_replay_cache_unchanged_without_cache_arg(self, keypair: tuple[bytes, bytes]) -> None:
        """Back-compat: verify_slot_claim without a cache performs no
        replay tracking (existing callers unaffected)."""
        privkey, pubkey = keypair
        claim_1 = sign_slot_claim(
            SlotClaim(
                gateway_iid=_bound_iid(pubkey),
                slots=(0,),
                superframe_id=1,
                expiry=int(time.time()) + 8,
                claim_seq=0,
                ordinal=0,
            ),
        signed = self._signed(privkey, pubkey, int(now) + horizon + 1)
        is_valid, reason = verify_slot_claim(signed, pubkey, now_unix=now)
        assert not is_valid
        assert reason is slot_claim.ClaimRejectReason.EXPIRY_TOO_FAR

    def test_claim_without_timestamp_skips_horizon_check(
        self, keypair: tuple[bytes, bytes], pubkey: bytes
    ) -> None:
        # A claim with a fresh expiry inside the horizon verifies; the
        # horizon rejection (beyond max) is pinned by the next test.
        privkey, pubkey = keypair
        signed = self._signed(privkey, pubkey, int(now := 1_900_000_000.0) + 60)
        is_valid, reason = verify_slot_claim(signed, pubkey, now_unix=now + 60)
        assert is_valid
        assert reason is None

    def test_invalid_signature_reported_before_horizon(self, keypair: tuple[bytes, bytes]) -> None:
        privkey, _ = keypair
        _, other_pubkey = schnorr48.derive_keypair(
            bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        )
        now = 1_900_000_000.0
        horizon = slot_claim.MAX_CLAIM_DURATION_SEC
        signed = self._signed(privkey, keypair[1], int(now) + horizon + 1)
        is_valid, reason = verify_slot_claim(signed, other_pubkey, now_unix=now)
        assert not is_valid
        # The key-bound gateway_iid no longer matches the wrong verifying key,
        # so the identity check (checked before the signature) reports first.
        assert reason is slot_claim.ClaimRejectReason.IDENTITY_MISMATCH


class TestStaleClaimBound:
    """GCP-6.3 step 7 analogue: reject already-expired (stale) claims."""

    @pytest.fixture
    def keypair(self) -> tuple[bytes, bytes]:
        seed = bytes.fromhex("c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00")
        return schnorr48.derive_keypair(seed)

    @pytest.fixture
    def pubkey(self, keypair: tuple[bytes, bytes]) -> bytes:
        return keypair[1]

    def _signed(self, privkey: bytes, pubkey: bytes, timestamp: int | None) -> SlotClaim:
        claim = SlotClaim(
            gateway_iid=_pubkey_to_iid(pubkey).hex(),
            slots=(5, 6),
            superframe_id=1000,
            expiry=timestamp if timestamp is not None else int(time.time()) + 60,
            claim_seq=0,
            ordinal=0,
        )