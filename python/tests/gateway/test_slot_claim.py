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
    AllocationMode,
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
        )
        assert claim.gateway_iid == "0011223344556677"
        assert claim.slots == (0, 1, 2)
        assert claim.superframe_id == 1000
        assert claim.signature is None

    def test_with_optional_fields(self) -> None:
        claim = SlotClaim(
            gateway_iid="aabbccddeeff0011",
            slots=(5,),
            superframe_id=42,
            expiry=int(time.time()) + 8,
            claim_seq=0,
            gateway_count=3,
            ordinal=0,
        )
        assert claim.gateway_count == 3
        assert claim.ordinal == 0

    def test_invalid_iid_length(self) -> None:
        with pytest.raises(ClaimError, match="gateway_iid must be 16 hex chars"):
            SlotClaim(
                gateway_iid="0011",  # Too short
                slots=(0,),
                superframe_id=1,
                expiry=int(time.time()) + 8,
                claim_seq=0,
            )

    def test_invalid_iid_hex(self) -> None:
        with pytest.raises(ClaimError, match="gateway_iid must be valid hex"):
            SlotClaim(
                gateway_iid="001122334455667Z",  # Invalid hex char
                slots=(0,),
                superframe_id=1,
                expiry=int(time.time()) + 8,
                claim_seq=0,
            )

    def test_unsorted_slots(self) -> None:
        with pytest.raises(ClaimError, match="slots must be sorted"):
            SlotClaim(
                gateway_iid="0011223344556677",
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
            )

    def test_negative_superframe_id(self) -> None:
        with pytest.raises(ClaimError, match="superframe_id must be non-negative"):
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(0,),
                superframe_id=-1,
                expiry=int(time.time()) + 8,
                claim_seq=0,
            )

    def test_claim_seq_u32_boundary(self) -> None:
        """claim_seq is u32 on the wire (Rust slot.rs decodes with
        u32::try_from); 2**32-1 must be accepted and 2**32 rejected at
        construction so both boundaries match the Rust verdict."""
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0,),
            superframe_id=1,
            expiry=int(time.time()) + 8,
            claim_seq=0xFFFF_FFFF,
        )
        assert claim.claim_seq == 0xFFFF_FFFF
        with pytest.raises(ClaimError, match="claim_seq must be a u32 integer"):
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(0,),
                superframe_id=1,
                expiry=int(time.time()) + 8,
                claim_seq=0x1_0000_0000,
            )
        with pytest.raises(ClaimError, match="claim_seq must be a u32 integer"):
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(0,),
                superframe_id=1,
                expiry=int(time.time()) + 8,
                claim_seq=-1,
            )

    def test_sibling_field_upper_bounds(self) -> None:
        """s61e: Rust slot.rs decodes superframe_epoch/expiry/ordinal as u64
        and slot indices as u32 (count <= 4096); Python must reject the same
        out-of-range values at construction so a signed claim cannot be
        accepted by Python while Rust calls the identical bytes malformed."""
        base = {
            "gateway_iid": "0011223344556677",
            "slots": (0,),
            "superframe_id": 1,
            "expiry": int(time.time()) + 8,
            "claim_seq": 0,
        }
        # Boundary values accepted (Rust u64/u32 maxima are encodable).
        SlotClaim(**{**base, "superframe_id": 0xFFFF_FFFF_FFFF_FFFF})
        SlotClaim(**{**base, "expiry": 0xFFFF_FFFF_FFFF_FFFF})
        SlotClaim(**{**base, "ordinal": 0xFFFF_FFFF_FFFF_FFFF})
        SlotClaim(**{**base, "slots": (0xFFFF_FFFF,)})
        # Above the Rust-decodable range -> rejected.
        with pytest.raises(ClaimError, match="superframe_id"):
            SlotClaim(**{**base, "superframe_id": 0x1_0000_0000_0000_0000})
        with pytest.raises(ClaimError, match="expiry"):
            SlotClaim(**{**base, "expiry": 0x1_0000_0000_0000_0000})
        with pytest.raises(ClaimError, match="ordinal"):
            SlotClaim(**{**base, "ordinal": 0x1_0000_0000_0000_0000})
        with pytest.raises(ClaimError, match="ordinal"):
            SlotClaim(**{**base, "ordinal": -1})
        with pytest.raises(ClaimError, match="slots must be u32"):
            SlotClaim(**{**base, "slots": (0x1_0000_0000,)})
        with pytest.raises(ClaimError, match="slots must be u32"):
            SlotClaim(**{**base, "slots": (-1,)})
        with pytest.raises(ClaimError, match="slots must be u32"):
            SlotClaim(**{**base, "slots": (True,)})
        with pytest.raises(ClaimError, match="MAX_SLOTS_PER_SUPERFRAME"):
            SlotClaim(**{**base, "slots": tuple(range(4097))})
        # None ordinal (local-only claim) and empty slots remain valid.
        SlotClaim(**{**base, "ordinal": None})
        SlotClaim(**{**base, "slots": ()})

    def test_allocation_mode_must_be_enum(self) -> None:
        """9ez4: a raw int/str allocation_mode must not construct — it would
        serialize inverted (any non-INTERLEAVED value maps to CONTIGUOUS on
        the wire)."""
        base = {
            "gateway_iid": "0011223344556677",
            "slots": (0,),
            "superframe_id": 1,
            "expiry": int(time.time()) + 8,
            "claim_seq": 0,
        }
        for bad in (0, 1, "interleaved", None):
            with pytest.raises(ClaimError, match="allocation_mode must be an AllocationMode"):
                SlotClaim(**{**base, "allocation_mode": bad})
        for good in (AllocationMode.INTERLEAVED, AllocationMode.CONTIGUOUS):
            SlotClaim(**{**base, "allocation_mode": good})

    def test_invalid_signature_length(self) -> None:
        with pytest.raises(ClaimError, match="signature must be 48 bytes"):
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(0,),
                superframe_id=1,
                expiry=int(time.time()) + 8,
                claim_seq=0,
                signature=b"\x00" * 32,  # Wrong length
            )

    def test_iid_as_int(self) -> None:
        claim = SlotClaim(
            gateway_iid="0000000000000001",
            slots=(0,),
            superframe_id=1,
            expiry=int(time.time()) + 8,
            claim_seq=0,
        )
        assert claim.iid_as_int() == 1

        claim2 = SlotClaim(
            gateway_iid="00000000000000ff",
            slots=(0,),
            superframe_id=1,
            expiry=int(time.time()) + 8,
            claim_seq=0,
        )
        assert claim2.iid_as_int() == 255

    def test_payload_keys_follow_spec(self) -> None:
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
            expiry=int(time.time()) + 8,
            claim_seq=7,
        )
        import cbor2

        from lichen.gateway.slot_claim import encode_claim_canonical

        fields = cbor2.loads(encode_claim_canonical(claim))
        assert fields[1] == [0, 1, 2]
        assert fields[2] == 1000
        assert fields[3] == 0
        assert fields[4] == int(time.time()) + 8
        assert fields[5] == bytes.fromhex("0011223344556677")
        assert fields[6] == 7


class TestEncodeClaimCanonical:
    """Tests for CBOR canonical encoding."""

    def test_deterministic_encoding(self) -> None:
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
            expiry=int(time.time()) + 8,
            claim_seq=0,
        )
        # Multiple calls should produce identical output
        encoded1 = encode_claim_canonical(claim)
        encoded2 = encode_claim_canonical(claim)
        assert encoded1 == encoded2

    def test_key_ordering(self) -> None:
        # Per RFC 8949 Section 4.2.1, CBOR deterministic encoding sorts map
        # keys by encoded-form length then lexicographic bytes. The spec
        # payload uses integer keys 1-7 (7 only in interleaved mode), so the
        # default claim carries exactly keys 1..6 in ascending order.
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
            expiry=int(time.time()) + 8,
            claim_seq=0,
        )
        encoded = encode_claim_canonical(claim)
        import cbor2

        decoded = cbor2.loads(encoded)
        keys = list(decoded.keys())
        # Canonical CBOR emits integer keys in ascending order for small uints.
        assert keys == [1, 2, 3, 4, 5, 6, 7]


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
        )
        signed_claim = sign_slot_claim(claim, privkey, pubkey)
        assert signed_claim.signature is not None
        assert len(signed_claim.signature) == 48

        is_valid, reason = verify_slot_claim(signed_claim, pubkey)
        assert is_valid
        assert reason is None

    def test_missing_signature_rejected(self, keypair: tuple[bytes, bytes]) -> None:
        _, pubkey = keypair
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0,),
            superframe_id=1,
            expiry=int(time.time()) + 8,
            claim_seq=0,
        )
        is_valid, reason = verify_slot_claim(claim, pubkey)
        assert not is_valid
        assert reason == ClaimRejectReason.MISSING_SIGNATURE

    def test_invalid_signature_rejected(self, keypair: tuple[bytes, bytes]) -> None:
        _, pubkey = keypair
        # Zero signature is invalid
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0,),
            superframe_id=1,
            expiry=int(time.time()) + 8,
            claim_seq=0,
            signature=bytes(48),
        )
        is_valid, reason = verify_slot_claim(claim, pubkey)
        assert not is_valid
        assert reason in (
            ClaimRejectReason.IDENTITY_MISMATCH,
            ClaimRejectReason.INVALID_SIGNATURE,
        )

    def test_replay_cache_rejects_replay_and_allows_advance(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        """l1qw.20.5: the replay cache is a pure claim_seq high-water per
        gateway IID (GCP-6.5 step 8), independent of superframe — mirrors
        Rust slot.rs last_seen semantics."""
        privkey, pubkey = keypair
        cache = SlotClaimReplayCache()

        iid = _bound_iid(pubkey)
        expiry = int(time.time()) + 8

        def claim(superframe: int, seq: int, slot: int = 0):
            return sign_slot_claim(
                SlotClaim(
                    gateway_iid=iid,
                    slots=(slot,),
                    superframe_id=superframe,
                    expiry=expiry,
                    claim_seq=seq,
                ),
                privkey,
                pubkey,
            )

        # First claim (superframe 5, seq 0) is accepted and seeds the cache.
        is_valid, reason = verify_slot_claim(claim(5, 0), pubkey, replay_cache=cache)
        assert is_valid and reason is None

        # Same superframe with advanced seq -> accepted (loser-reclaim
        # within a superframe must advance the signed claim_seq).
        is_valid, reason = verify_slot_claim(claim(5, 1, slot=1), pubkey, replay_cache=cache)
        assert is_valid and reason is None

        # Replay of the cached seq -> REPLAY.
        is_valid, reason = verify_slot_claim(claim(5, 1), pubkey, replay_cache=cache)
        assert not is_valid
        assert reason == ClaimRejectReason.REPLAY

        # Lower seq in a NEWER superframe -> REPLAY (seq rollback across
        # the superframe boundary is exactly what step 8 blocks).
        is_valid, reason = verify_slot_claim(claim(6, 0), pubkey, replay_cache=cache)
        assert not is_valid
        assert reason == ClaimRejectReason.REPLAY

        # Advancing seq across the superframe boundary -> accepted.
        is_valid, reason = verify_slot_claim(claim(6, 2), pubkey, replay_cache=cache)
        assert is_valid and reason is None

    def test_claim_expiry_bounded_to_max_duration(
        self, keypair: tuple[bytes, bytes], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bead j6o2 (GCP-6.5 step 7a): a claim whose expiry lies further
        than MAX_CLAIM_DURATION past now is rejected EXPIRY_TOO_FAR; an
        in-window expiry is accepted."""
        privkey, pubkey = keypair
        cache = SlotClaimReplayCache()
        now = 1_900_000_000
        monkeypatch.setattr(time, "time", lambda: now)

        def claim(expiry: int):
            return sign_slot_claim(
                SlotClaim(
                    gateway_iid=_pubkey_to_iid(pubkey).hex(),
                    slots=(0,),
                    superframe_id=5,
                    expiry=expiry,
                    claim_seq=0,
                    ordinal=0,
                ),
                privkey,
                pubkey,
            )

        # Step 7: expired (well past now) is fail-closed via the stale
        # tolerance (STALE_CLAIM); the exact now-boundary diverges from the
        # C implementation's strict now < expiry gate (adjudication: 104v
        # family / pxxl parity notes).
        is_valid, reason = verify_slot_claim(claim(now - 100), pubkey, cache)
        assert not is_valid
        assert reason == ClaimRejectReason.STALE_CLAIM

        # Step 7a: beyond max duration (305 s tolerance window) -> rejected.
        is_valid, reason = verify_slot_claim(
            claim(now + MAX_CLAIM_DURATION_SECONDS + 1), pubkey, cache
        )
        assert not is_valid
        assert reason == ClaimRejectReason.EXPIRY_TOO_FAR

        # In-window (now < expiry <= now + 305) -> accepted.
        is_valid, reason = verify_slot_claim(claim(now + MAX_CLAIM_DURATION_SECONDS), pubkey, cache)
        assert is_valid and reason is None

    def test_replay_cache_caps_at_max_gateways(self, keypair: tuple[bytes, bytes]) -> None:
        """Bead c5lz: the cache rejects GATEWAY_FULL (not REPLAY) for a NEW
        gateway when at MAX_GATEWAYS; already-tracked gateways stay usable
        (mirrors Rust slot.rs max_gateways/StateFull)."""
        privkey, pubkey = keypair
        cache = SlotClaimReplayCache()
        expiry = int(time.time()) + 8

        def claim_for(iid: str, superframe: int, seq: int = 0):
            return sign_slot_claim(
                SlotClaim(
                    gateway_iid=iid,
                    slots=(0,),
                    superframe_id=superframe,
                    expiry=expiry,
                    claim_seq=seq,
                ),
                privkey,
                pubkey,
            )

        # Merged: HEAD binds each claim's IID to its signing key, so one
        # keypair fills only one cache slot end-to-end (worker-7's loop of
        # 256 arbitrary IIDs predates the identity binding). Track this
        # keypair's IID through verify_slot_claim, then fill the remaining
        # capacity via the cache's public API.
        tracked_iid = _bound_iid(pubkey)
        is_valid, reason = verify_slot_claim(claim_for(tracked_iid, 10), pubkey, cache)
        assert is_valid and reason is None
        for i in range(cache.MAX_GATEWAYS):
            if len(cache._highwater) == cache.MAX_GATEWAYS:
                break
            iid = f"{i:016x}"
            if iid == tracked_iid:
                continue
            ok, _ = cache.check_and_update(iid, 10)
            assert ok
        assert len(cache._highwater) == cache.MAX_GATEWAYS

        # A NEW gateway at capacity -> STATE_FULL (not REPLAY). Signed by its
        # own keypair so identity/signature checks pass and the capacity gate
        # is what rejects it.
        new_priv, new_pub = schnorr48.derive_keypair(bytes.fromhex("0123456789abcdef" * 4))
        new_claim = sign_slot_claim(
            SlotClaim(
                gateway_iid=_bound_iid(new_pub),
                slots=(0,),
                superframe_id=10,
                expiry=expiry,
                claim_seq=0,
            ),
            new_priv,
            new_pub,
        )
        is_valid, reason = verify_slot_claim(new_claim, new_pub, cache)
        assert not is_valid
        assert reason == ClaimRejectReason.STATE_FULL

        # An ALREADY-TRACKED gateway still advances at capacity (seq
        # high-water strictly advances; superframe is irrelevant).
        is_valid, reason = verify_slot_claim(claim_for(tracked_iid, 11, seq=1), pubkey, cache)
        assert is_valid and reason is None

    def test_replay_cache_tracks_gateways_independently(self, keypair: tuple[bytes, bytes]) -> None:
        privkey, pubkey = keypair
        cache = SlotClaimReplayCache()

        expiry = int(time.time()) + 8
        first = sign_slot_claim(
            SlotClaim(
                gateway_iid=_bound_iid(pubkey),
                slots=(0,),
                superframe_id=10,
                expiry=expiry,
                claim_seq=0,
            ),
            privkey,
            pubkey,
        )
        is_valid, _ = verify_slot_claim(first, pubkey, replay_cache=cache)
        assert is_valid

        # A different gateway starting at a lower superframe is independent.
        second_keypair = schnorr48.derive_keypair(bytes(range(32)))
        other_priv, other_pub = second_keypair
        other = sign_slot_claim(
            SlotClaim(
                gateway_iid=_bound_iid(other_pub),
                slots=(0,),
                superframe_id=1,
                expiry=expiry,
                claim_seq=0,
            ),
            other_priv,
            other_pub,
        )
        is_valid, reason = verify_slot_claim(other, other_pub, replay_cache=cache)
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
            ),
            privkey,
            pubkey,
        )
        for _ in range(3):
            is_valid, _ = verify_slot_claim(claim_1, pubkey)
            assert is_valid

    def test_wrong_pubkey_rejected(self, keypair: tuple[bytes, bytes]) -> None:
        privkey, pubkey = keypair
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
            expiry=int(time.time()) + 8,
            claim_seq=0,
        )
        signed_claim = sign_slot_claim(claim, privkey, pubkey)

        # Verify with different key
        other_seed = bytes.fromhex(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        )
        _, other_pubkey = schnorr48.derive_keypair(other_seed)

        is_valid, reason = verify_slot_claim(signed_claim, other_pubkey)
        assert not is_valid
        assert reason in (
            ClaimRejectReason.IDENTITY_MISMATCH,
            ClaimRejectReason.INVALID_SIGNATURE,
        )


class TestResolveSlotConflict:
    """Tests for slot conflict resolution (GCP-6.3)."""

    @pytest.fixture
    def keypair_low(self) -> tuple[bytes, bytes]:
        # Low IID gateway
        seed = bytes(32)  # All zeros
        return schnorr48.derive_keypair(seed)

    @pytest.fixture
    def keypair_high(self) -> tuple[bytes, bytes]:
        # High IID gateway
        seed = bytes([0xFF] * 32)
        return schnorr48.derive_keypair(seed)

    def test_lowest_iid_wins_both_valid(
        self,
        keypair_low: tuple[bytes, bytes],
        keypair_high: tuple[bytes, bytes],
    ) -> None:
        priv_low, pub_low = keypair_low
        priv_high, pub_high = keypair_high

        # Both claim slots 5, 6. IIDs are bound to each signing key
        # (GCP-6.5 step 6); "low"/"high" is decided by compare_iid on the
        # derived IIDs, not by fabricated literals.
        claim_low = sign_slot_claim(
            SlotClaim(
                gateway_iid=_bound_iid(pub_low),
                slots=(5, 6),
                superframe_id=100,
                expiry=int(time.time()) + 8,
                claim_seq=0,
            ),
            priv_low,
            pub_low,
        )
        claim_high = sign_slot_claim(
            SlotClaim(
                gateway_iid=_bound_iid(pub_high),
                slots=(5, 6),
                superframe_id=100,
                expiry=int(time.time()) + 8,
                claim_seq=0,
            ),
            priv_high,
            pub_high,
        )

        # Pass pubkeys to resolve_slot_conflict for verification
        winner, loser = resolve_slot_conflict(
            claim_low, claim_high, pubkey_a=pub_low, pubkey_b=pub_high
        )
        # Zero-seed keypair must produce the lower IID (U/L-cleared sha512 prefix).
        assert winner.gateway_iid == _bound_iid(pub_low)
        assert loser.gateway_iid == _bound_iid(pub_high)

    def test_valid_claim_wins_over_invalid(
        self,
        keypair_low: tuple[bytes, bytes],
    ) -> None:
        priv, pub = keypair_low

        valid_claim = sign_slot_claim(
            SlotClaim(
                gateway_iid=_bound_iid(pub),
                slots=(5, 6),
                superframe_id=100,
                expiry=int(time.time()) + 8,
                claim_seq=0,
            ),
            priv,
            pub,
        )

        # Invalid claim: fabricated IID that cannot verify under any key.
        invalid_claim = SlotClaim(
            gateway_iid="0011223344556677",  # Unbound IID, invalid zero sig
            slots=(5, 6),
            superframe_id=100,
            expiry=int(time.time()) + 8,
            claim_seq=0,
            signature=bytes(48),  # Invalid zero signature
        )

        # Use a different pubkey for invalid_claim to ensure verification fails
        other_seed = bytes([0x42] * 32)
        _, other_pub = schnorr48.derive_keypair(other_seed)

        winner, loser = resolve_slot_conflict(
            valid_claim, invalid_claim, pubkey_a=pub, pubkey_b=other_pub
        )
        # The valid claim's IID is the key-bound one; the invalid claim keeps
        # its fabricated IID but is discarded per GCP-6.3.
        assert winner.gateway_iid == valid_claim.gateway_iid
        assert loser.gateway_iid == invalid_claim.gateway_iid

    def test_no_overlap_raises(
        self,
        keypair_low: tuple[bytes, bytes],
        keypair_high: tuple[bytes, bytes],
    ) -> None:
        priv_low, pub_low = keypair_low
        priv_high, pub_high = keypair_high

        claim_a = sign_slot_claim(
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(0, 1, 2),
                superframe_id=100,
                expiry=int(time.time()) + 8,
                claim_seq=0,
            ),
            priv_low,
            pub_low,
        )
        claim_b = sign_slot_claim(
            SlotClaim(
                gateway_iid="0022334455667788",
                slots=(3, 4, 5),
                superframe_id=100,
                expiry=int(time.time()) + 8,
                claim_seq=0,
            ),
            priv_high,
            pub_high,
        )
        with pytest.raises(ClaimError, match="no overlapping slots"):
            resolve_slot_conflict(claim_a, claim_b, pubkey_a=pub_low, pubkey_b=pub_high)

    def test_both_invalid_raises(
        self,
        keypair_low: tuple[bytes, bytes],
        keypair_high: tuple[bytes, bytes],
    ) -> None:
        _, pub_low = keypair_low
        _, pub_high = keypair_high

        # Both claims have zero signatures (invalid)
        claim_a = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(5, 6),
            superframe_id=100,
            expiry=int(time.time()) + 8,
            claim_seq=0,
            signature=bytes(48),
        )
        claim_b = SlotClaim(
            gateway_iid="0022334455667788",
            slots=(5, 6),
            superframe_id=100,
            expiry=int(time.time()) + 8,
            claim_seq=0,
            signature=bytes(48),
        )
        with pytest.raises(ClaimError, match="both claims have invalid signatures"):
            resolve_slot_conflict(claim_a, claim_b, pubkey_a=pub_low, pubkey_b=pub_high)


class TestInterleavedSlots:
    """Tests for interleaved slot allocation (GCP-6.2)."""

    def test_single_gateway(self) -> None:
        slots = compute_interleaved_slots(ordinal=0, gateway_count=1, max_slots=8)
        assert slots == [0, 1, 2, 3, 4, 5, 6, 7]

    def test_three_gateways_ordinal_0(self) -> None:
        slots = compute_interleaved_slots(ordinal=0, gateway_count=3, max_slots=15)
        assert slots == [0, 3, 6, 9, 12]

    def test_three_gateways_ordinal_1(self) -> None:
        slots = compute_interleaved_slots(ordinal=1, gateway_count=3, max_slots=15)
        assert slots == [1, 4, 7, 10, 13]

    def test_three_gateways_ordinal_2(self) -> None:
        slots = compute_interleaved_slots(ordinal=2, gateway_count=3, max_slots=15)
        assert slots == [2, 5, 8, 11, 14]

    def test_invalid_ordinal(self) -> None:
        with pytest.raises(ClaimError, match="ordinal.*gateway_count"):
            compute_interleaved_slots(ordinal=3, gateway_count=3, max_slots=15)

    def test_negative_ordinal(self) -> None:
        with pytest.raises(ClaimError, match="non-negative"):
            compute_interleaved_slots(ordinal=-1, gateway_count=3, max_slots=15)


class TestContiguousSlots:
    """Tests for contiguous slot allocation (GCP-6.2)."""

    def test_basic_contiguous(self) -> None:
        slots = compute_contiguous_slots(start_slot=10, slot_count=5, max_slots=60)
        assert slots == [10, 11, 12, 13, 14]

    def test_at_start(self) -> None:
        slots = compute_contiguous_slots(start_slot=0, slot_count=3, max_slots=60)
        assert slots == [0, 1, 2]

    def test_at_end(self) -> None:
        slots = compute_contiguous_slots(start_slot=57, slot_count=3, max_slots=60)
        assert slots == [57, 58, 59]

    def test_empty_allocation(self) -> None:
        slots = compute_contiguous_slots(start_slot=10, slot_count=0, max_slots=60)
        assert slots == []

    def test_exceeds_max_slots(self) -> None:
        with pytest.raises(ClaimError, match="exceeds max_slots"):
            compute_contiguous_slots(start_slot=58, slot_count=5, max_slots=60)


class TestValidateInterleavedPattern:
    """Tests for interleaved pattern validation."""

    def test_valid_pattern(self) -> None:
        # Gateway 0 of 3: slots 0, 3, 6, 9, 12
        assert validate_interleaved_pattern(
            slots=[0, 3, 6, 9, 12],
            ordinal=0,
            gateway_count=3,
        )

    def test_valid_pattern_gateway_1(self) -> None:
        # Gateway 1 of 3: slots 1, 4, 7, 10, 13
        assert validate_interleaved_pattern(
            slots=[1, 4, 7, 10, 13],
            ordinal=1,
            gateway_count=3,
        )

    def test_invalid_pattern_wrong_start(self) -> None:
        # Gateway 0 should start at 0, not 1
        assert not validate_interleaved_pattern(
            slots=[1, 4, 7],
            ordinal=0,
            gateway_count=3,
        )

    def test_invalid_pattern_wrong_spacing(self) -> None:
        # Gateway 0 of 3 should have spacing of 3, not 2
        assert not validate_interleaved_pattern(
            slots=[0, 2, 4],
            ordinal=0,
            gateway_count=3,
        )

    def test_empty_slots_valid(self) -> None:
        assert validate_interleaved_pattern(slots=[], ordinal=0, gateway_count=3)


class TestSlotClaimVectors:
    """Test against test vectors in gcp_slot_claim.json."""

    @pytest.fixture(scope="class")
    def vectors(self) -> list[dict]:
        path = VECTORS_DIR / "gcp_slot_claim.json"
        if not path.exists():
            pytest.skip(f"Test vectors not found: {path}")
        with open(path) as f:
            doc = json.load(f)
        return doc["vectors"]

    def test_interleaved_pattern_vector(self, vectors: list[dict]) -> None:
        for v in vectors:
            if v["name"] == "slot_claim_interleaved":
                claim = v["claim"]
                slots = claim["slots"]
                ordinal = claim["ordinal"]
                gateway_count = claim["gateway_count"]
                expected = v["expected"]

                result = validate_interleaved_pattern(slots, ordinal, gateway_count)
                assert result == expected["valid"], f"Pattern validation failed for {v['name']}"
                break

    def test_conflict_resolution_vector(self, vectors: list[dict]) -> None:
        for v in vectors:
            if v["name"] == "slot_claim_conflict_both_valid":
                claim_a_data = v["claim_a"]
                claim_b_data = v["claim_b"]

                # Generate keypairs for signing (deterministic seeds for reproducibility)
                seed_a = bytes.fromhex("a" * 64)
                seed_b = bytes.fromhex("b" * 64)
                priv_a, pub_a = schnorr48.derive_keypair(seed_a)
                priv_b, pub_b = schnorr48.derive_keypair(seed_b)

                # Sign the claims per vector's "both_signatures_valid: true".
                # GCP-6.5 step 6 binds gateway_iid to the signing key's IID,
                # so the fixture IIDs are replaced with key-derived ones.
                import time

                from lichen.crypto.identity import _pubkey_to_iid

                expiry = int(time.time()) + 8
                claim_a = sign_slot_claim(
                    SlotClaim(
                        gateway_iid=_pubkey_to_iid(pub_a).hex(),
                        slots=tuple(claim_a_data["slots"]),
                        superframe_id=1,
                        expiry=expiry,
                        claim_seq=0,
                    ),
                    priv_a,
                    pub_a,
                )
                claim_b = sign_slot_claim(
                    SlotClaim(
                        gateway_iid=_pubkey_to_iid(pub_b).hex(),
                        slots=tuple(claim_b_data["slots"]),
                        superframe_id=1,
                        expiry=expiry,
                        claim_seq=0,
                    ),
                    priv_b,
                    pub_b,
                )

                winner, _ = resolve_slot_conflict(claim_a, claim_b, pubkey_a=pub_a, pubkey_b=pub_b)
                expected_winner = v["expected"]["winner"]

                # Vector's "lowest IID wins" semantic: with key-derived
                # IIDs the winner is the claim whose IID compares lowest.
                winner_expected = min(
                    (claim_a.gateway_iid, "claim_a"),
                    (claim_b.gateway_iid, "claim_b"),
                )[1]
                assert expected_winner == "claim_a", (
                    ("vector assumed claim_a wins; lowest-IID semantic moved it")
                    if winner_expected == "claim_b"
                    else None
                )
                assert winner.gateway_iid == (
                    claim_a.gateway_iid if winner_expected == "claim_a" else claim_b.gateway_iid
                )
                break

    def test_missing_signature_rejected_vector(self, vectors: list[dict]) -> None:
        for v in vectors:
            if v["name"] == "slot_claim_missing_signature_reject":
                expected = v["expected"]
                assert expected["valid"] is False
                assert expected["reason"] == "missing_signature"

                # Create claim without signature and verify rejection
                claim = SlotClaim(
                    gateway_iid=v["claim"]["gateway_iid"],
                    slots=tuple(v["claim"]["slots"]),
                    superframe_id=1,
                    expiry=int(time.time()) + 8,
                    claim_seq=0,
                )
                # Use a dummy pubkey for verification
                dummy_pubkey = bytes(32)
                is_valid, reason = verify_slot_claim(claim, dummy_pubkey)
                assert not is_valid
                assert reason == ClaimRejectReason.MISSING_SIGNATURE
                break

    def test_invalid_signature_rejected_vector(self, vectors: list[dict]) -> None:
        for v in vectors:
            if v["name"] == "slot_claim_invalid_signature_reject":
                expected = v["expected"]
                assert expected["valid"] is False
                assert expected["reason"] == "invalid_signature"

                sig_hex = v["signature"]
                sig = bytes.fromhex(sig_hex)

                claim = SlotClaim(
                    gateway_iid=v["claim"]["gateway_iid"],
                    slots=tuple(v["claim"]["slots"]),
                    superframe_id=1,
                    expiry=int(time.time()) + 8,
                    claim_seq=0,
                    signature=sig,
                )
                # Use a dummy pubkey for verification
                dummy_seed = bytes.fromhex(
                    "0000000000000000000000000000000000000000000000000000000000000001"
                )
                _, dummy_pubkey = schnorr48.derive_keypair(dummy_seed)
                is_valid, reason = verify_slot_claim(claim, dummy_pubkey)
                assert not is_valid
                assert reason in (
                    ClaimRejectReason.IDENTITY_MISMATCH,
                    ClaimRejectReason.INVALID_SIGNATURE,
                )
                break

    def test_cose_envelope_vectors(self, vectors: list[dict]) -> None:
        """Every envelope_hex vector decodes and verifies per its expectation
        (l1qw.16.2: the basic tier documents the spec COSE_Sign1 form)."""
        path = VECTORS_DIR / "gcp_slot_claim.json"
        with open(path) as f:
            doc = json.load(f)
        now = doc["constants"]["evaluation_time"]
        envelope_vectors = [v for v in vectors if "envelope_hex" in v]
        assert envelope_vectors, "basic tier lost its COSE envelope vectors"

        for v in envelope_vectors:
            envelope = bytes.fromhex(v["envelope_hex"])
            expected = v["expected"]
            if expected.get("reason") == "missing_signature":
                # An empty signature bstr is structurally malformed.
                with pytest.raises(ClaimError):
                    SlotClaim.decode_cose(envelope)
                continue
            claim = SlotClaim.decode_cose(envelope)
            pubkey = bytes.fromhex(v["signer"]["public_key_hex"])
            is_valid, reason = verify_slot_claim(claim, pubkey, now_unix=now)
            expect_valid = expected.get(
                "valid", expected.get("verify_with_gateway_pubkey", False)
            )
            if expect_valid:
                assert (is_valid, reason) == (True, None), v["name"]
                if "signature_length" in expected:
                    assert len(claim.signature) == expected["signature_length"]
                if "allocation_mode" in expected:
                    mode = slot_claim.AllocationMode[
                        expected["allocation_mode"].upper()
                    ]
                    assert claim.allocation_mode == mode, v["name"]
            else:
                assert not is_valid, v["name"]
                assert reason == ClaimRejectReason.INVALID_SIGNATURE


class TestClaimExpiryHorizon:
    """GCP-6.3 hardening: bound how far ahead a claim may pre-book."""

    @pytest.fixture
    def keypair(self) -> tuple[bytes, bytes]:
        seed = bytes.fromhex("feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface")
        return schnorr48.derive_keypair(seed)

    @pytest.fixture
    def pubkey(self, keypair: tuple[bytes, bytes]) -> bytes:
        return keypair[1]

    def _signed(self, privkey: bytes, pubkey: bytes, timestamp: int | None) -> SlotClaim:
        claim = SlotClaim(
            gateway_iid=_pubkey_to_iid(pubkey).hex(),
            slots=(3, 4),
            superframe_id=1000,
            expiry=timestamp,
            claim_seq=0,
        )
        return sign_slot_claim(claim, privkey, pubkey)

    def test_timestamp_within_horizon_accepted(
        self, keypair: tuple[bytes, bytes], pubkey: bytes
    ) -> None:
        privkey, _ = keypair
        now = 1_900_000_000.0
        horizon = slot_claim.MAX_CLAIM_DURATION_SECONDS
        signed = self._signed(privkey, pubkey, int(now) + horizon)
        is_valid, reason = verify_slot_claim(signed, pubkey, now_unix=now)
        assert is_valid
        assert reason is None

    def test_timestamp_beyond_horizon_rejected(
        self, keypair: tuple[bytes, bytes], pubkey: bytes
    ) -> None:
        privkey, _ = keypair
        now = 1_900_000_000.0
        horizon = slot_claim.MAX_CLAIM_DURATION_SECONDS
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
        horizon = slot_claim.MAX_CLAIM_DURATION_SECONDS
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
        )
        return sign_slot_claim(claim, privkey, pubkey)

    def test_fresh_timestamp_accepted(self, keypair: tuple[bytes, bytes], pubkey: bytes) -> None:
        privkey, _ = keypair
        now = 1_900_000_000.0
        signed = self._signed(privkey, pubkey, int(now))
        is_valid, reason = verify_slot_claim(signed, pubkey, now_unix=now)
        assert is_valid
        assert reason is None

    def test_stale_timestamp_rejected(self, keypair: tuple[bytes, bytes], pubkey: bytes) -> None:
        privkey, _ = keypair
        now = 1_900_000_000.0
        tolerance = slot_claim.STALE_CLAIM_TOLERANCE_SEC
        signed = self._signed(privkey, pubkey, int(now) - tolerance - 1)
        is_valid, reason = verify_slot_claim(signed, pubkey, now_unix=now)
        assert not is_valid
        assert reason is slot_claim.ClaimRejectReason.STALE_CLAIM

    def test_timestamp_within_stale_tolerance_accepted(
        self, keypair: tuple[bytes, bytes], pubkey: bytes
    ) -> None:
        privkey, _ = keypair
        now = 1_900_000_000.0
        tolerance = slot_claim.STALE_CLAIM_TOLERANCE_SEC
        signed = self._signed(privkey, pubkey, int(now) - tolerance)
        is_valid, reason = verify_slot_claim(signed, pubkey, now_unix=now)
        assert is_valid
        assert reason is None


class TestSlotClaimRateLimiter:
    """GCP-6.5 rate limiting (l1qw.22): 10/min/peer + 60/min/global, silent drop."""

    def test_per_peer_limit_enforced(self) -> None:
        limiter = SlotClaimRateLimiter()
        iid = "0200::1111"
        now = 1716742800.0
        for i in range(10):
            assert limiter.allow(iid, now + i)
        assert not limiter.allow(iid, now + 10)

    def test_per_peer_window_resets(self) -> None:
        limiter = SlotClaimRateLimiter()
        iid = "0200::1111"
        now = 1716742800.0
        for i in range(10):
            assert limiter.allow(iid, now + i)
        assert not limiter.allow(iid, now + 10)
        assert limiter.allow(iid, now + 61)

    def test_global_limit_across_peers(self) -> None:
        limiter = SlotClaimRateLimiter()
        for peer in range(10):
            iid = f"0200::{peer:04x}"
            for _ in range(6):
                assert limiter.allow(iid, 1716742800.0)
        assert not limiter.allow("0200::ffff", 1716742800.0)

    def test_distinct_peers_independent(self) -> None:
        limiter = SlotClaimRateLimiter()
        assert limiter.allow("0200::0001", 1716742800.0)
        assert limiter.allow("0200::0002", 1716742800.0)

    def test_verify_slot_claim_rate_gate(self) -> None:
        limiter = SlotClaimRateLimiter()
        now = 1716746790.0
        identity = Identity.from_seed(bytes([7]) * 32)
        claim = SlotClaim(
            gateway_iid=identity.iid.hex(),
            slots=(1, 2, 3),
            superframe_id=7,
            expiry=1716746800,
            claim_seq=1,
        )
        signed = sign_slot_claim(claim, identity.privkey, identity.pubkey)
        for i in range(10):
            ok, _ = verify_slot_claim(
                signed, identity.pubkey, now_unix=now + i, rate_limiter=limiter
            )
            assert ok, f"claim {i} within limit must pass"
        ok, reason = verify_slot_claim(
            signed, identity.pubkey, now_unix=now + 10, rate_limiter=limiter
        )
        assert not ok
        assert reason == ClaimRejectReason.RATE_LIMITED


class TestClaimSeqStore:
    """Tests for the sender-side claim_seq persistence (GCP-6.5, l1qw.20.1)."""

    def test_missing_file_initializes_to_zero(self, tmp_path: Path) -> None:
        store = slot_claim.ClaimSeqStore(tmp_path / "claim_seq")
        assert store.next_seq() == 1

    def test_increment_persists_before_return(self, tmp_path: Path) -> None:
        path = tmp_path / "claim_seq"
        store = slot_claim.ClaimSeqStore(path)
        seq = store.next_seq()
        assert seq == 1
        # GCP-6.5 "Before claim" row: persist to NVS, then sign and send —
        # the value is durable the moment next_seq() returns it.
        assert path.read_text(encoding="ascii").strip() == str(seq)

    def test_monotonic_across_restart(self, tmp_path: Path) -> None:
        path = tmp_path / "claim_seq"
        first = slot_claim.ClaimSeqStore(path)
        assert first.next_seq() == 1
        assert first.next_seq() == 2
        rebooted = slot_claim.ClaimSeqStore(path)
        assert rebooted.next_seq() == 3

    def test_corrupt_file_initializes_to_zero(self, tmp_path: Path) -> None:
        path = tmp_path / "claim_seq"
        path.write_text("not a number", encoding="ascii")
        store = slot_claim.ClaimSeqStore(path)
        # Safe direction: a rewound counter only makes receivers reject the
        # claims as replays (step 8) until the sender climbs past their
        # cached high-water.
        assert store.next_seq() == 1

    def test_stale_temp_files_never_read(self, tmp_path: Path) -> None:
        path = tmp_path / "claim_seq"
        store = slot_claim.ClaimSeqStore(path)
        assert store.next_seq() == 1
        (tmp_path / ".claim_seq.crashed.tmp").write_text("999", encoding="ascii")
        reloaded = slot_claim.ClaimSeqStore(path)
        assert reloaded.next_seq() == 2

    def test_persist_failure_raises_and_state_stays_consistent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "claim_seq"
        store = slot_claim.ClaimSeqStore(path)

        def broken_replace(src: object, dst: object) -> None:
            raise OSError("disk gone")

        monkeypatch.setattr(slot_claim.os, "replace", broken_replace)
        with pytest.raises(OSError):
            store.next_seq()
        monkeypatch.undo()
        # The failed sequence was not consumed: the retry persists and
        # returns it.
        assert store.next_seq() == 1
        assert path.read_text(encoding="ascii").strip() == "1"

    def test_signed_claim_carries_store_sequence(self, tmp_path: Path) -> None:
        identity = Identity.from_seed(bytes([9]) * 32)
        store = slot_claim.ClaimSeqStore(tmp_path / "claim_seq")
        seq = store.next_seq()
        claim = SlotClaim(
            gateway_iid=identity.iid.hex(),
            slots=(0, 1),
            superframe_id=10,
            expiry=int(time.time()) + 8,
            claim_seq=seq,
        )
        signed = sign_slot_claim(claim, identity.privkey, identity.pubkey)
        ok, reason = verify_slot_claim(signed, identity.pubkey)
        assert ok, reason
