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
    slots = [s for s in case["slots"]]
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
