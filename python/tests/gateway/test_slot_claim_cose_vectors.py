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
