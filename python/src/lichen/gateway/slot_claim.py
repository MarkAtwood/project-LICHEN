# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GCP-6 Slot Claim oracle (spec 08-gateway-coordination.md Section 6).

Implements slot claim message handling for gateway-to-gateway coordination:
- Slot claim creation and validation
- CBOR canonical encoding for signatures
- Schnorr48 signature verification (SECURITY requirement)
- Conflict resolution (lowest IID wins)
- Interleaved and contiguous allocation modes

Per GCP-6.3:
- Gateways MUST verify Schnorr signature on any slot-claim message
- Claims with invalid or missing signatures MUST be silently discarded
- Overlapping claims where both signatures verify: lowest IID wins
- Overlapping claims where one signature fails: valid claim wins

All implementations MUST match test vectors in:
- test/vectors/gcp_slot_claim.json
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

import cbor2

from lichen.crypto import schnorr48
from lichen.link.channel import SUPERFRAME_DURATION_US

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "AllocationMode",
    "ClaimError",
    "ClaimRejectReason",
    "SlotClaim",
    "compute_contiguous_slots",
    "compute_interleaved_slots",
    "encode_claim_canonical",
    "resolve_slot_conflict",
    "validate_interleaved_pattern",
    "verify_slot_claim",
    "SlotClaimReplayCache",
]


MAX_CLAIM_DURATION_SEC = 5 * (SUPERFRAME_DURATION_US // 1_000_000)
"""Maximum how far ahead a claim's timestamp may be (5 superframes, GCP-6.3).

Provisional: spec 6.3 step 7a fixes the tolerance at 305s (5 x 60s mesh
superframes + 5s clock tolerance); the constant here derives from the 2s
link-layer superframe until the claim-model decision (bead 70p7, tracked
as vq3a(2)) lands the final wire model.
"""

STALE_CLAIM_TOLERANCE_SEC = 5
"""Acceptable clock skew for a claim's timestamp in the past (step 7 analogue).

Spec 6.3 step 7 rejects already-expired claims; the tolerance absorbs
gateway clock skew so a claim issued moments ago is not dropped."""


class ClaimRejectReason(Enum):
    """Reasons a slot claim may be rejected (GCP-6.3)."""

    MISSING_SIGNATURE = auto()  # No signature provided
    INVALID_SIGNATURE = auto()  # Signature failed verification
    INVALID_CLAIM_DATA = auto()  # Malformed claim structure
    # Merged: keep both reject causes — HEAD binds the claim to the key,
    # beads-worker-7 gates replays by high-water.
    IDENTITY_MISMATCH = auto()  # kid/gateway_iid not bound to verifying key
    REPLAY = auto()  # claim_seq/superframe at or below the stored high-water
    SLOT_CONFLICT = auto()  # Overlapping slots, lower IID wins
    # Merged: HEAD's claim-horizon rejects and worker-7's replay-cache
    # capacity reject are independent causes; keep all three.
    EXPIRY_TOO_FAR = auto()  # Claim timestamp further ahead than the max horizon
    STALE_CLAIM = auto()  # Claim timestamp older than the stale tolerance
    STATE_FULL = auto()  # Replay cache at MAX_GATEWAYS, gateway not tracked
    # Merged: beads-worker-4's GCP-6.5 rate-limit reject is an independent
    # cause from HEAD's STATE_FULL; both are referenced below, keep both.
    RATE_LIMITED = auto()  # GCP-6.5: exceeded 10/min/peer or 60/min global


# GCP-6.5 validation step 7a (spec/08-gateway-coordination.md): a claim may
# not reserve capacity further than MAX_CLAIM_DURATION into the future.
# 5 superframes x 60 s = 300 s, plus 5 s clock tolerance.
SUPERFRAME_SECONDS = 60
MAX_CLAIM_DURATION_SUPERFRAMES = 5
CLOCK_TOLERANCE_SECONDS = 5
MAX_CLAIM_DURATION_SECONDS = (
    MAX_CLAIM_DURATION_SUPERFRAMES * SUPERFRAME_SECONDS + CLOCK_TOLERANCE_SECONDS
)


class AllocationMode(Enum):
    """Slot allocation mode (GCP-6.2)."""

    INTERLEAVED = auto()  # Gateway N owns slots N, N+G, N+2G...
    CONTIGUOUS = auto()  # Gateway owns sequential block of slots


class ClaimError(Exception):
    """Slot claim processing error."""


@dataclass(frozen=True)
class SlotClaim:
    """Slot claim message for POST /.well-known/lichen-gw/slots.

    Per GCP-6.5, the claim is carried in a COSE_Sign1 envelope signed with
    the gateway's Ed25519 key (Schnorr48, alg -65537).

    Attributes:
        gateway_iid: 8-byte gateway Interface Identifier (hex string)
        slots: List of slot indices being claimed (sorted ascending)
        superframe_id: Superframe epoch when the claim was issued
        expiry: Unix timestamp after which the claim is invalid (required)
        claim_seq: Monotonic claim sequence (required, replay gate)
        allocation_mode: Interleaved or contiguous allocation
        ordinal: This gateway's ordinal position (interleaved mode)
        gateway_count: Local federation size parameter (never serialized)
        signature: 48-byte Schnorr signature (hex string or bytes)
    """

    gateway_iid: str  # Hex string, 16 chars (8 bytes)
    slots: tuple[int, ...]  # Immutable, sorted ascending
    superframe_id: int
    expiry: int
    claim_seq: int
    allocation_mode: AllocationMode = AllocationMode.INTERLEAVED

    # Optional fields
    # Merged: worker-7's optional timestamp/expiry fields are dropped; HEAD
    # makes expiry a required field (spec key 4) and exposes `timestamp` as a
    # property alias below, so the optional-None model is superseded.
    ordinal: int | None = None
    gateway_count: int | None = None
    signature: bytes | None = None

    @property
    def timestamp(self) -> int:
        """Backward-compatible alias for expiry (spec: key 4)."""
        return self.expiry

    def __post_init__(self) -> None:
        """Validate claim structure."""
        # Validate gateway_iid is 8 bytes (16 hex chars)
        if len(self.gateway_iid) != 16:
            raise ClaimError(f"gateway_iid must be 16 hex chars, got {len(self.gateway_iid)}")
        try:
            bytes.fromhex(self.gateway_iid)
        except ValueError as e:
            raise ClaimError(f"gateway_iid must be valid hex: {e}") from None

        # Slots must be sorted ascending
        if list(self.slots) != sorted(self.slots):
            raise ClaimError("slots must be sorted ascending")

        # Slots must be unique
        if len(self.slots) != len(set(self.slots)):
            raise ClaimError("slots must be unique")

        # Superframe ID must be non-negative
        if self.superframe_id < 0:
            raise ClaimError("superframe_id must be non-negative")

        # Expiry must be a non-negative integer (spec: key 4)
        if type(self.expiry) is not int or self.expiry < 0:
            raise ClaimError("expiry must be a non-negative integer")

        # claim_seq must be a non-negative integer (spec: key 6)
        if type(self.claim_seq) is not int or self.claim_seq < 0:
            raise ClaimError("claim_seq must be a non-negative integer")

        # Validate signature length if present
        if self.signature is not None and len(self.signature) != 48:
            raise ClaimError(f"signature must be 48 bytes, got {len(self.signature)}")

    def iid_as_int(self) -> int:
        """Return gateway IID as unsigned big-endian integer for comparison."""
        return int.from_bytes(bytes.fromhex(self.gateway_iid), "big")

    # Merged: worker-7's string-keyed to_cbor_map helper is dropped; the
    # spec wire form (GCP-6.5) uses integer-keyed payloads assembled in
    # encode_claim_canonical(), so a parallel string-key encoder would be
    # dead, divergent code.
    @classmethod
    def decode_cose(cls, envelope: bytes) -> SlotClaim:
        """Decode a COSE_Sign1 slot-claim envelope (spec GCP-6.5).

        Structural validation only: envelope shape, alg -65537, kid present,
        payload key/type conformance. Signature verification is the caller's
        (verify_slot_claim) with the resolved gateway pubkey.
        """
        try:
            document = cbor2.loads(envelope)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise ClaimError(f"invalid CBOR envelope: {e}") from None
        if not isinstance(document, list) or len(document) != 4:
            raise ClaimError("COSE_Sign1 must be a 4-element array")
        protected, unprotected, payload, signature = document
        if not isinstance(protected, bytes) or not isinstance(payload, bytes):
            raise ClaimError("COSE protected header and payload must be bytes")
        if not isinstance(unprotected, dict):
            raise ClaimError("COSE unprotected header must be a map")
        if not isinstance(signature, bytes):
            raise ClaimError("COSE signature must be bytes")
        try:
            header = cbor2.loads(protected)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise ClaimError(f"invalid protected header: {e}") from None
        if not isinstance(header, dict) or header.get(1) != -65537:
            # Validation step 4: non-(-65537) algorithms are decoys; reject.
            raise ClaimError("slot-claim alg must be Schnorr48-Ed25519 (-65537)")
        kid = unprotected.get(_COSE_KID_LABEL)
        if not isinstance(kid, bytes) or len(kid) != 8:
            raise ClaimError("slot-claim kid must be an 8-byte gateway IID")
        try:
            fields = cbor2.loads(payload)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise ClaimError(f"invalid payload: {e}") from None
        if not isinstance(fields, dict):
            raise ClaimError("slot-claim payload must be a map")

        raw_slots = fields.get(_PAYLOAD_SLOTS)
        if not isinstance(raw_slots, list) or not all(
            isinstance(s, int) and not isinstance(s, bool) for s in raw_slots
        ):
            raise ClaimError("slots must be an array of integers")
        superframe_epoch = fields.get(_PAYLOAD_SUPERFRAME_EPOCH)
        if type(superframe_epoch) is not int or superframe_epoch < 0:
            raise ClaimError("superframe_epoch must be a non-negative integer")
        mode = fields.get(_PAYLOAD_MODE)
        if mode == _MODE_INTERLEAVED:
            allocation_mode = AllocationMode.INTERLEAVED
        elif mode == _MODE_CONTIGUOUS:
            allocation_mode = AllocationMode.CONTIGUOUS
        else:
            raise ClaimError("mode must be 0 (interleaved) or 1 (contiguous)")
        expiry = fields.get(_PAYLOAD_EXPIRY)
        if type(expiry) is not int or expiry < 0:
            raise ClaimError("expiry must be a non-negative integer")
        iid_bytes = fields.get(_PAYLOAD_GATEWAY_IID)
        if not isinstance(iid_bytes, bytes) or len(iid_bytes) != 8:
            raise ClaimError("gateway_iid must be bstr(8)")
        claim_seq = fields.get(_PAYLOAD_CLAIM_SEQ)
        if type(claim_seq) is not int or claim_seq < 0:
            raise ClaimError("claim_seq must be a non-negative integer")
        ordinal = fields.get(_PAYLOAD_ORDINAL)
        if ordinal is not None and (type(ordinal) is not int or ordinal < 0):
            raise ClaimError("ordinal must be a non-negative integer")

        return cls(
            gateway_iid=iid_bytes.hex(),
            slots=tuple(raw_slots),
            superframe_id=superframe_epoch,
            expiry=expiry,
            claim_seq=claim_seq,
            allocation_mode=allocation_mode,
            ordinal=ordinal,
            signature=signature,
        )


# ─── COSE_Sign1 wire format (spec/08-gateway-coordination.md GCP-6.5) ────────

# Merged: worker-7's string-keyed from_cbor decoder tail is dropped; the
# decoder on this class is HEAD's decode_cose (COSE_Sign1, strict integer
# keys per GCP-6.5). The constants below are its payload key labels.

_PAYLOAD_SLOTS = 1
_PAYLOAD_SUPERFRAME_EPOCH = 2
_PAYLOAD_MODE = 3
_PAYLOAD_EXPIRY = 4
_PAYLOAD_GATEWAY_IID = 5
_PAYLOAD_CLAIM_SEQ = 6
_PAYLOAD_ORDINAL = 7
_COSE_KID_LABEL = 4
_MODE_INTERLEAVED = 0
_MODE_CONTIGUOUS = 1


def encode_claim_canonical(claim: SlotClaim) -> bytes:
    """Encode the claim payload in spec wire form (CBOR map, integer keys).

    Per spec/08 GCP-6.5: payload keys are 1 slots, 2 superframe_epoch,
    3 mode (0 interleaved / 1 contiguous), 4 expiry, 5 gateway_iid bstr(8),
    6 claim_seq, 7 ordinal. gateway_count is a local allocation parameter
    and is NEVER serialized.
    """
    mode = (
        _MODE_INTERLEAVED
        if claim.allocation_mode == AllocationMode.INTERLEAVED
        else _MODE_CONTIGUOUS
    )
    payload: dict[int, object] = {
        _PAYLOAD_SLOTS: list(claim.slots),
        _PAYLOAD_SUPERFRAME_EPOCH: claim.superframe_id,
        _PAYLOAD_MODE: mode,
        _PAYLOAD_EXPIRY: claim.expiry,
        _PAYLOAD_GATEWAY_IID: bytes.fromhex(claim.gateway_iid),
        _PAYLOAD_CLAIM_SEQ: claim.claim_seq,
    }
    if claim.ordinal is not None:
        payload[_PAYLOAD_ORDINAL] = claim.ordinal
    return cbor2.dumps(payload, canonical=True)


class SlotClaimRateLimiter:
    """Bounded sliding-window rate limiter for slot claims (GCP-6.5:
    "at most 10 claims per minute per peer IID and 60 claims per minute
    globally. Claims exceeding these limits MUST be silently dropped.").

    Exceeding a limit returns False from :meth:`allow`; the caller drops
    the claim with the same indistinguishable rejection as a signature
    failure (GCP-6.3) and never advances the replay high-water.
    """

    WINDOW_S = 60
    PER_PEER_LIMIT = 10
    GLOBAL_LIMIT = 60

    def __init__(self) -> None:
        self._per_peer: dict[str, list[float]] = {}
        self._global: list[float] = []

    def _prune(self, now: float) -> None:
        cutoff = now - self.WINDOW_S
        self._global = [t for t in self._global if t > cutoff]
        for stamps in self._per_peer.values():
            stamps[:] = [t for t in stamps if t > cutoff]

    def allow(self, gateway_iid: str, now: float) -> bool:
        """Record one claim at *now* (seconds). False when the claim
        exceeds the per-peer or global rate (caller silently drops)."""
        self._prune(now)
        if len(self._global) >= self.GLOBAL_LIMIT:
            return False
        stamps = self._per_peer.setdefault(gateway_iid, [])
        if len(stamps) >= self.PER_PEER_LIMIT:
            return False
        stamps.append(now)
        self._global.append(now)
        return True


class SlotClaimReplayCache:
    """Per-gateway-IID replay high-water (GCP-6.5 step 8, l1qw.20.2).

    Tracks the highest superframe_id accepted per gateway IID and rejects
    claims at or below it. State is in-memory only; persistence across
    restarts is the l1qw.20.1/NVS follow-up (mirrors Rust slot.rs
    last_seen semantics).

    Capacity is bounded at MAX_GATEWAYS (mirroring Rust slot.rs
    max_gateways/StateFull, bead c5lz): a claim from a gateway with no
    cached high-water when the cache is full is rejected GATEWAY_FULL, so
    IID churn cannot grow the cache without bound. Already-tracked
    gateways always remain usable.
    """

    #: Maximum distinct gateway IIDs tracked (Rust slot.rs parity).
    MAX_GATEWAYS = 256

    def __init__(self) -> None:
        self._highwater: dict[str, int] = {}

    def check_and_update(
        self, gateway_iid: str, superframe_id: int
    ) -> tuple[bool, ClaimRejectReason | None]:
        """Advance the high-water for *gateway_iid*.

        Returns (True, None) and stores the new high-water when the claim
        strictly advances it; returns (False, REPLAY) otherwise.
        """
        previous = self._highwater.get(gateway_iid)
        if previous is not None and superframe_id <= previous:
            return (False, ClaimRejectReason.REPLAY)
        if gateway_iid not in self._highwater and len(self._highwater) >= self.MAX_GATEWAYS:
            return (False, ClaimRejectReason.STATE_FULL)
        self._highwater[gateway_iid] = superframe_id
        return (True, None)


def verify_slot_claim(
    claim: SlotClaim,
    gateway_pubkey: bytes,
    replay_cache: SlotClaimReplayCache | None = None,
    now_unix: float | None = None,
    rate_limiter: SlotClaimRateLimiter | None = None,
) -> tuple[bool, ClaimRejectReason | None]:
    """Verify Schnorr48 signature on slot claim.

    Per GCP-6.3:
    - Gateways MUST verify the Schnorr signature on any slot-claim message
    - Claims with invalid or missing signatures MUST be silently discarded

    SECURITY: This function MUST be called before accepting any slot claim
    from another gateway. Unsigned claims can enable slot hijacking attacks.

    Args:
        claim: SlotClaim to verify
        gateway_pubkey: 32-byte Ed25519 public key of claiming gateway
        replay_cache: Optional per-gateway claim high-water (l1qw.20.2).
        rate_limiter: Optional GCP-6.5 rate limiter (l1qw.22): a claim
            exceeding the 10/min/peer or 60/min/global window returns
            (False, RATE_LIMITED) for a silent drop, never advancing the
            replay high-water.
            When provided, the claim's superframe_id must strictly advance
            the stored high-water for its gateway IID. Signature checks run
            first per GCP-6.3, so the replay state is only consumed by
            signature-valid claims.
        now_unix: Current Unix timestamp for the claim-horizon check;
            defaults to the wall clock. Claims with a timestamp further
            than MAX_CLAIM_DURATION_SEC ahead are rejected EXPIRY_TOO_FAR.

    Returns:
        Tuple of (is_valid, rejection_reason or None)
    """
    if rate_limiter is not None:
        now = time.time() if now_unix is None else now_unix
        if not rate_limiter.allow(claim.gateway_iid, now):
            # GCP-6.5: exceeding claims MUST be silently dropped; the
            # replay high-water is not advanced by rate-dropped claims.
            return (False, ClaimRejectReason.RATE_LIMITED)

    if claim.signature is None:
        return (False, ClaimRejectReason.MISSING_SIGNATURE)

    if len(claim.signature) != 48:
        return (False, ClaimRejectReason.INVALID_SIGNATURE)

    if len(gateway_pubkey) != 32:
        return (False, ClaimRejectReason.INVALID_SIGNATURE)

    # Bind the (unprotected) kid to the verifying key's derived IID.
    from lichen.crypto.identity import _pubkey_to_iid

    if bytes.fromhex(claim.gateway_iid) != _pubkey_to_iid(gateway_pubkey):
        return (False, ClaimRejectReason.IDENTITY_MISMATCH)

    # GCP-6.5: sig = Schnorr48(privkey, SHA256(CBOR(Sig_structure)))
    from hashlib import sha256

    from lichen.crypto.delegation_tokens import (
        cose_protected_header,
        cose_sig_structure,
    )

    payload = encode_claim_canonical(claim)
    protected = cose_protected_header()
    digest = sha256(cose_sig_structure(protected, payload)).digest()
    if not schnorr48.verify(gateway_pubkey, digest, claim.signature):
        return (False, ClaimRejectReason.INVALID_SIGNATURE)

    # Merged: worker-7's validate_claim_timing() was dropped; its strict
    # `now < expiry` lower bound conflicts with the stale-tolerance
    # semantics HEAD pins via the `timestamp` alias block below. The
    # upper horizon (GCP-6.5 step 7a, MAX_CLAIM_DURATION_SECONDS) is
    # checked inline; the lower bound/stale tolerance follows in the HEAD
    # block. Checked after authentication, never before.
    now = time.time() if now_unix is None else now_unix
    if claim.expiry > now + MAX_CLAIM_DURATION_SECONDS:
        # The upper bound is checked against the worker constant; the
        # tighter HEAD constant below may still reject, matching tests.
        return (False, ClaimRejectReason.EXPIRY_TOO_FAR)

    # GCP-6.3 hardening: bound how far ahead a claim may pre-book slots.
    # The timestamp is covered by the signature, so this rejects a
    # legitimately-signed claim whose horizon exceeds the maximum — after
    # authentication, never before. Claims without a timestamp skip this
    # check (they cannot express a horizon).
    if claim.timestamp is not None:
        now = time.time() if now_unix is None else now_unix
        if claim.timestamp > now + MAX_CLAIM_DURATION_SEC:
            return (False, ClaimRejectReason.EXPIRY_TOO_FAR)
        if claim.timestamp < now - STALE_CLAIM_TOLERANCE_SEC:
            return (False, ClaimRejectReason.STALE_CLAIM)

    # Replay gate (l1qw.20.2, beads-worker-7): consumed only after the
    # horizon check, so a horizon-rejected claim never advances the
    # high-water.
    if replay_cache is not None:
        ok, reason = replay_cache.check_and_update(claim.gateway_iid, claim.superframe_id)
        if not ok:
            return (False, reason)

    return (True, None)


def resolve_slot_conflict(
    claim_a: SlotClaim,
    claim_b: SlotClaim,
    pubkey_a: bytes | None = None,
    pubkey_b: bytes | None = None,
) -> tuple[SlotClaim, SlotClaim]:
    """Resolve conflict when two gateways claim overlapping slots.

    Per GCP-6.3:
    - If two gateways claim overlapping slot: lowest IID MUST win
    - Loser MUST select next available slot and re-claim
    - Overlapping claims where both signatures verify: lowest IID wins
    - Overlapping claims where one signature fails and other succeeds:
      valid claim wins

    Args:
        claim_a: First slot claim
        claim_b: Second slot claim
        pubkey_a: Public key for claim_a (required if signature present)
        pubkey_b: Public key for claim_b (required if signature present)

    Returns:
        Tuple of (winner, loser) claims

    Raises:
        ClaimError: If no overlapping slots or both claims invalid
    """
    # Check for overlap
    slots_a = set(claim_a.slots)
    slots_b = set(claim_b.slots)
    overlap = slots_a & slots_b

    if not overlap:
        raise ClaimError("no overlapping slots to resolve")

    # Verify signatures
    a_valid = pubkey_a is not None and verify_slot_claim(claim_a, pubkey_a)[0]
    b_valid = pubkey_b is not None and verify_slot_claim(claim_b, pubkey_b)[0]

    # Case 1: Both invalid - cannot resolve
    if not a_valid and not b_valid:
        raise ClaimError("both claims have invalid signatures, cannot resolve")

    # Case 2: One valid, one invalid - valid wins
    if a_valid and not b_valid:
        return (claim_a, claim_b)
    if b_valid and not a_valid:
        return (claim_b, claim_a)

    # Case 3: Both valid - lowest IID wins
    iid_a = claim_a.iid_as_int()
    iid_b = claim_b.iid_as_int()

    if iid_a < iid_b:
        return (claim_a, claim_b)
    elif iid_b < iid_a:
        return (claim_b, claim_a)
    else:
        # Same IID - should not happen in practice (same gateway)
        raise ClaimError("claims have identical gateway IID")


def compute_interleaved_slots(
    ordinal: int,
    gateway_count: int,
    max_slots: int,
) -> list[int]:
    """Compute slot indices for interleaved allocation mode.

    Per GCP-6.2:
    - Gateway with ordinal N owns slots N, N+G, N+2G...
    - Where G = gateway_count

    Args:
        ordinal: This gateway's position (0-indexed)
        gateway_count: Total number of gateways
        max_slots: Maximum slot index (exclusive)

    Returns:
        Sorted list of owned slot indices

    Raises:
        ClaimError: If ordinal >= gateway_count
    """
    if ordinal < 0:
        raise ClaimError(f"ordinal must be non-negative: {ordinal}")
    if gateway_count < 1:
        raise ClaimError(f"gateway_count must be >= 1: {gateway_count}")
    if ordinal >= gateway_count:
        raise ClaimError(f"ordinal {ordinal} >= gateway_count {gateway_count}")
    if max_slots < 1:
        raise ClaimError(f"max_slots must be >= 1: {max_slots}")

    return list(range(ordinal, max_slots, gateway_count))


def compute_contiguous_slots(
    start_slot: int,
    slot_count: int,
    max_slots: int,
) -> list[int]:
    """Compute slot indices for contiguous allocation mode.

    Per GCP-6.2:
    - Gateway owns sequential block of slots

    Args:
        start_slot: First slot index (inclusive)
        slot_count: Number of slots to claim
        max_slots: Maximum slot index (exclusive)

    Returns:
        Sorted list of owned slot indices

    Raises:
        ClaimError: If allocation exceeds max_slots
    """
    if start_slot < 0:
        raise ClaimError(f"start_slot must be non-negative: {start_slot}")
    if slot_count < 0:
        raise ClaimError(f"slot_count must be non-negative: {slot_count}")
    if max_slots < 1:
        raise ClaimError(f"max_slots must be >= 1: {max_slots}")
    if start_slot + slot_count > max_slots:
        raise ClaimError(
            f"contiguous block [{start_slot}, {start_slot + slot_count}) "
            f"exceeds max_slots {max_slots}"
        )

    return list(range(start_slot, start_slot + slot_count))


def validate_interleaved_pattern(
    slots: Sequence[int],
    ordinal: int,
    gateway_count: int,
) -> bool:
    """Validate that slots follow interleaved allocation pattern.

    Per test vectors, interleaved pattern requires:
        slots[i] == ordinal + i * gateway_count

    Args:
        slots: List of claimed slot indices
        ordinal: Gateway's ordinal position
        gateway_count: Total number of gateways

    Returns:
        True if pattern is valid, False otherwise
    """
    if not slots:
        return True  # Empty claim is trivially valid

    if gateway_count < 1:
        return False

    if ordinal < 0 or ordinal >= gateway_count:
        return False

    for i, slot in enumerate(slots):
        expected = ordinal + i * gateway_count
        if slot != expected:
            return False

    return True


def sign_slot_claim(
    claim: SlotClaim,
    privkey: bytes,
    pubkey: bytes,
) -> SlotClaim:
    """Sign a slot claim with Schnorr48.

    Args:
        claim: SlotClaim to sign (signature field ignored)
        privkey: 32-byte Ed25519 private key (clamped)
        pubkey: 32-byte Ed25519 public key

    Returns:
        New SlotClaim with signature field populated
    """
    # GCP-6.5: sig = Schnorr48(privkey, SHA256(CBOR(Sig_structure)))
    from hashlib import sha256

    from lichen.crypto.delegation_tokens import (
        cose_protected_header,
        cose_sig_structure,
    )

    payload = encode_claim_canonical(claim)
    protected = cose_protected_header()
    digest = sha256(cose_sig_structure(protected, payload)).digest()
    signature = schnorr48.sign(privkey, pubkey, digest)

    # Create new claim with signature
    new_claim = SlotClaim(
        gateway_iid=claim.gateway_iid,
        slots=claim.slots,
        superframe_id=claim.superframe_id,
        # Merged: HEAD kwargs kept; worker-7's `timestamp` kwarg cannot be
        # passed because `timestamp` is a property alias for `expiry`.
        expiry=claim.expiry,
        claim_seq=claim.claim_seq,
        allocation_mode=claim.allocation_mode,
        gateway_count=claim.gateway_count,
        ordinal=claim.ordinal,
        signature=signature,
    )
    return new_claim
