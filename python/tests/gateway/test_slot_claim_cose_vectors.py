# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Python vector consumer for gcp_slot_claim_cose_sign1.json (GCP-6.5).

Mirrors the Rust consumer rust/lichen-rpl tests (ccp16 parity work):
valid claims decode, verify and are field-asserted; reject cases map to the
expected ClaimRejectReason per spec/08 GCP-6.5 validation steps.
"""

from __future__ import annotations

import json
from pathlib import Path

import cbor2
import pytest

from lichen.gateway.slot_claim import (
    AllocationMode,
    ClaimError,
    ClaimRejectReason,
    SlotClaim,
    SlotClaimReplayCache,
    verify_slot_claim,
)

VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "test"
        / "vectors"
        / "gcp_slot_claim_cose_sign1.json"
    ).read_text()
)

EVAL_TIME = VECTORS["constants"]["evaluation_time"]


def _hex(value: str) -> bytes:
    return bytes.fromhex(value)


def _case(name: str) -> dict:
    return next(c for c in VECTORS["cases"] if c["name"] == name)


def _decode(case: dict) -> SlotClaim:
    return SlotClaim.decode_cose(_hex(case["cose_sign1_hex"]))


def _pubkey(case: dict) -> bytes:
    return _hex(case["signer_public_key_hex"])


def _assert_fields(claim: SlotClaim, case: dict, name: str) -> None:
    slots = list(case["slots"])
    assert claim.slots == tuple(slots), name
    assert claim.superframe_id == case["superframe_epoch"], name
    assert claim.claim_seq == case["claim_seq"], name
    assert claim.expiry == case["expiry"], name
    assert claim.gateway_iid == case["signer_iid_hex"], name
    assert claim.ordinal == case.get("ordinal"), name


def test_valid_claims_verify() -> None:
    for name in (
        "happy_path_n1",
        "happy_path_n4",
        "happy_path_n60",
        "claim_seq_cache_seed",
        "expiry_boundary_future",
    ):
        case = _case(name)
        claim = _decode(case)
        _assert_fields(claim, case, name)
        pubkey = _pubkey(case)
        is_valid, reason = verify_slot_claim(
            claim, pubkey, now_unix=EVAL_TIME
        )
        assert is_valid and reason is None, f"{name}: {reason}"


def test_slots_array_mutation_rejected() -> None:
    case = _case("slots_array_mutation")
    claim = _decode(case)
    pubkey = _pubkey(case)
    is_valid, reason = verify_slot_claim(
        claim, pubkey, now_unix=EVAL_TIME
    )
    assert not is_valid
    assert reason == ClaimRejectReason.INVALID_SIGNATURE


def test_claim_seq_replay_equal_and_lower_rejected() -> None:
    # The receiver cached claim_seq 5 (claim_seq_cache_seed). Replays with
    # equal or lower claim_seq are rejected with REPLAY.
    seed = _decode(_case("claim_seq_cache_seed"))
    cache = SlotClaimReplayCache()
    seed_pubkey = _pubkey(_case("claim_seq_cache_seed"))
    is_valid, _ = verify_slot_claim(
        seed, seed_pubkey, replay_cache=cache, now_unix=EVAL_TIME
    )
    assert is_valid

    for name in ("claim_seq_replay_equal", "claim_seq_replay_lower"):
        claim = _decode(_case(name))
        pubkey = _pubkey(_case(name))
        is_valid, reason = verify_slot_claim(
            claim, pubkey, replay_cache=cache, now_unix=EVAL_TIME
        )
        assert not is_valid
        assert reason == ClaimRejectReason.REPLAY, name


def test_expired_boundary_past_rejected() -> None:
    # PYTHON DIVERGENCE: verify_slot_claim only rejects expiry older than
    # the 5s stale tolerance (STALE_CLAIM); the vector/C reject expiry <=
    # now outright. The strict now < expiry gate is an adjudication item.
    pytest.skip("Python verify lacks the strict now < expiry gate")


def test_expiry_boundary_now_rejected() -> None:
    # Same divergence as above at the exact now boundary.
    pytest.skip("Python verify lacks the strict now < expiry gate")


def test_expiry_boundary_future_passes_verify() -> None:
    case = _case("expiry_boundary_future")
    claim = _decode(case)
    pubkey = _pubkey(case)
    is_valid, _ = verify_slot_claim(
        claim, pubkey, now_unix=EVAL_TIME
    )
    assert is_valid


def test_header_alg_decoy_rejected() -> None:
    case = _case("header_alg_decoy")
    with pytest.raises(ClaimError):
        SlotClaim.decode_cose(_hex(case["cose_sign1_hex"]))


def test_kid_payload_iid_mismatch_rejected() -> None:
    # PYTHON DIVERGENCE (bead b7z9.88.3-adjacent / 16.2.5): decode_cose does
    # not bind the kid to the payload IID yet — the C and Rust decoders
    # reject this case. Skipped until that gap lands.
    pytest.skip("Python decoder lacks kid binding (parity gap, tracked)")


def test_ordinal_absent_rejected() -> None:
    # Keys 1-7 are all required: without the ordinal the receiver cannot
    # register the gateway (parity with the Rust decoder, b7z9.25.1-era
    # ordinal work).
    case = _case("ordinal_absent")
    with pytest.raises(ClaimError):
        SlotClaim.decode_cose(_hex(case["cose_sign1_hex"]))


def test_claim_seq_over_u32_rejected_at_decode() -> None:
    # The Rust decoder bounds claim_seq with u32::try_from (slot.rs:590);
    # Python must reject the same range or a signed claim with
    # claim_seq > 2**32-1 diverges cross-implementation (accepted by
    # Python, MalformedClaim to Rust). Both the u64-width form (major
    # type 0, 8-byte argument) and the tag-2 bignum form must fail.
    case = _case("happy_path_n1")
    elements = cbor2.loads(_hex(case["cose_sign1_hex"]))

    for over in (0x1_0000_0000, 2**64 + 1):  # u64-width and tag-2 bignum
        payload = cbor2.loads(elements[2])
        payload[6] = over
        body = cbor2.dumps([elements[0], elements[1], cbor2.dumps(payload), elements[3]])
        with pytest.raises(ClaimError, match="claim_seq must be a u32 integer"):
            SlotClaim.decode_cose(body)


@pytest.mark.parametrize(
    "key,value",
    [
        (2, 2**64),  # superframe_epoch: above u64 (tag-2 bignum on wire)
        (4, 2**64),  # expiry: above u64
        (7, 2**64),  # ordinal: above u64
        (1, [2**32]),  # slot index above u32
        (1, [-1]),  # negative slot index (Rust uint() never admits)
        (1, [0] * 4097),  # over MAX_SLOTS_PER_SUPERFRAME
        (1, [True]),  # CBOR 0xf5 -> bool is not a u32 slot
    ],
)
def test_oversized_sibling_fields_rejected_at_decode(key: int, value: object) -> None:
    # s61e: the sibling payload fields get the same Rust-parity bounds as
    # claim_seq — a key holder signing oversized values must not produce a
    # claim Python accepts (advancing the replay high-water) while every
    # Rust peer discards the identical bytes as malformed.
    case = _case("happy_path_n1")
    elements = cbor2.loads(_hex(case["cose_sign1_hex"]))
    payload = cbor2.loads(elements[2])
    payload[key] = value
    body = cbor2.dumps([elements[0], elements[1], cbor2.dumps(payload), elements[3]])
    with pytest.raises(ClaimError):
        SlotClaim.decode_cose(body)


@pytest.mark.parametrize("bad_mode", [False, True, 0.0, 1.0, 2, None, "0"])
def test_non_integer_mode_rejected_at_decode(bad_mode: object) -> None:
    # ft5w: value equality admits CBOR false/true (bool) and float 0.0/1.0
    # as modes, which Rust's p.uint() rejects as MalformedClaim — the
    # decode must be type-strict (type(mode) is int, not value == 0/1).
    case = _case("happy_path_n1")
    elements = cbor2.loads(_hex(case["cose_sign1_hex"]))
    payload = cbor2.loads(elements[2])
    payload[3] = bad_mode
    body = cbor2.dumps([elements[0], elements[1], cbor2.dumps(payload), elements[3]])
    with pytest.raises(ClaimError, match="mode must be 0"):
        SlotClaim.decode_cose(body)


@pytest.mark.parametrize(
    "mode,expected",
    [(0, AllocationMode.INTERLEAVED), (1, AllocationMode.CONTIGUOUS)],
)
def test_integer_modes_accepted_at_decode(mode: int, expected: AllocationMode) -> None:
    case = _case("happy_path_n1")
    elements = cbor2.loads(_hex(case["cose_sign1_hex"]))
    payload = cbor2.loads(elements[2])
    payload[3] = mode
    body = cbor2.dumps([elements[0], elements[1], cbor2.dumps(payload), elements[3]])
    assert SlotClaim.decode_cose(body).allocation_mode == expected


def test_oversized_envelope_rejected_before_decode() -> None:
    # prgb: the envelope cap fires before cbor2.loads materializes anything —
    # a max-legit claim is ~21.1 KB; 24 KB bounds pre-rejection decode work.
    from lichen.gateway.slot_claim import MAX_CLAIM_ENVELOPE_BYTES

    with pytest.raises(ClaimError, match="envelope exceeds maximum size"):
        SlotClaim.decode_cose(b"\x84" + b"\x00" * (MAX_CLAIM_ENVELOPE_BYTES + 1))
    # A real envelope is far under the cap.
    case = _case("happy_path_n60")
    assert len(_hex(case["cose_sign1_hex"])) < MAX_CLAIM_ENVELOPE_BYTES
    SlotClaim.decode_cose(_hex(case["cose_sign1_hex"]))


@pytest.mark.parametrize(
    "key,value",
    [
        (2, 2**64 - 1),  # superframe_epoch at u64::MAX
        (4, 2**64 - 1),  # expiry at u64::MAX
        (7, 2**64 - 1),  # ordinal at u64::MAX
        (1, [2**32 - 1]),  # slot index at u32::MAX
    ],
)
def test_boundary_sibling_fields_accepted_at_decode(key: int, value: object) -> None:
    # s61e: values AT the Rust-decodable maximum must still decode — the
    # bound is inclusive, matching u64::try_from/u32::try_from acceptance.
    case = _case("happy_path_n1")
    elements = cbor2.loads(_hex(case["cose_sign1_hex"]))
    payload = cbor2.loads(elements[2])
    payload[key] = value
    body = cbor2.dumps([elements[0], elements[1], cbor2.dumps(payload), elements[3]])
    claim = SlotClaim.decode_cose(body)
    if key == 1:
        assert list(claim.slots) == value
    elif key == 2:
        assert claim.superframe_id == value
    elif key == 4:
        assert claim.expiry == value
    else:
        assert claim.ordinal == value


def _rebuild_envelope(case: dict, payload_bytes: bytes) -> bytes:
    """Reassemble the COSE_Sign1 with *payload_bytes* as the payload bstr."""
    elements = cbor2.loads(_hex(case["cose_sign1_hex"]))
    return b"\x84" + (
        cbor2.dumps(elements[0])
        + cbor2.dumps(elements[1])
        + cbor2.dumps(payload_bytes)
        + cbor2.dumps(elements[3])
    )


def _payload_bytes_with_raw(case: dict, key: int, raw_value: bytes) -> bytes:
    """Encode the canonical payload map, substituting *raw_value* (unparsed
    CBOR) for key *key* — the envelope keeps the signer's original signature."""
    case_envelope = cbor2.loads(_hex(case["cose_sign1_hex"]))
    fields = cbor2.loads(case_envelope[2])
    assert len(fields) == 7
    body = bytearray([0xA7])
    for k in range(1, 8):
        body += cbor2.dumps(k)
        body += raw_value if k == key else cbor2.dumps(fields[k])
    return bytes(body)


@pytest.mark.parametrize(
    "key,raw_value,label",
    [
        (3, b"\xc2\x41\x00", "tag-2 bignum 0 at mode"),
        (3, b"\xc2\x41\x01", "tag-2 bignum 1 at mode"),
        (6, b"\x18\x00", "long-form uint at claim_seq"),
        (6, b"\xc2\x41\x05", "tag-2 bignum at claim_seq"),
        (2, b"\x18\x0c", "long-form uint at superframe_epoch"),
        (1, b"\x81\x18\x07", "long-form uint in slots"),
    ],
)
def test_non_canonical_uint_encodings_rejected_at_decode(
    key: int, raw_value: bytes, label: str
) -> None:
    # 5rfl: cbor2 decodes tag-2 bignums (c2 41 00) and non-minimal long-form
    # uints (18 00) to plain int, so every type gate accepts them — while
    # Rust's p.uint()/head(0) rejects the identical wire bytes as
    # MalformedClaim before any signature check. Three of the six cases
    # (bignum 0 at mode, 18 0c at epoch, 81 18 07 in slots) decode to the
    # signer's own values, so the signature still verifies over the
    # canonical re-encode: without the canonical-form gate, signature-valid
    # wire input splits Python's verdict from every Rust peer. The other
    # three change the signed semantic value (the signature would fail too),
    # but Rust still rejects them at decode — decode must agree. The gate
    # rejects all such forms uniformly.
    case = _case("happy_path_n1")
    payload = _payload_bytes_with_raw(case, key, raw_value)
    with pytest.raises(ClaimError, match="canonically encoded"):
        SlotClaim.decode_cose(_rebuild_envelope(case, payload))


def test_canonical_uint_encodings_accepted_at_decode() -> None:
    # Positive control for the 5rfl gate: the same hand-built map with
    # canonical (minimal) value encodings must still decode — the gate
    # rejects encodings, not the hand-built construction itself.
    case = _case("happy_path_n1")
    envelope_elements = cbor2.loads(_hex(case["cose_sign1_hex"]))
    fields = cbor2.loads(envelope_elements[2])
    payload_bytes = _payload_bytes_with_raw(case, 3, cbor2.dumps(fields[3]))
    claim = SlotClaim.decode_cose(_rebuild_envelope(case, payload_bytes))
    assert claim.allocation_mode == (
        AllocationMode.INTERLEAVED if fields[3] == 0 else AllocationMode.CONTIGUOUS
    )
    assert verify_slot_claim(claim, _pubkey(case), now_unix=EVAL_TIME) == (True, None)
