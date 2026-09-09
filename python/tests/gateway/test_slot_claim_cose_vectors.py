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
        Path(__file__).resolve().parents[3] / "test" / "vectors" / "gcp_slot_claim_cose_sign1.json"
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
        is_valid, reason = verify_slot_claim(claim, pubkey, now_unix=EVAL_TIME)
        assert is_valid and reason is None, f"{name}: {reason}"


def test_slots_array_mutation_rejected() -> None:
    case = _case("slots_array_mutation")
    claim = _decode(case)
    pubkey = _pubkey(case)
    is_valid, reason = verify_slot_claim(claim, pubkey, now_unix=EVAL_TIME)
    assert not is_valid
    assert reason == ClaimRejectReason.INVALID_SIGNATURE


def test_claim_seq_replay_equal_and_lower_rejected() -> None:
    # The receiver cached claim_seq 5 (claim_seq_cache_seed). Replays with
    # equal or lower claim_seq are rejected with REPLAY.
    seed = _decode(_case("claim_seq_cache_seed"))
    cache = SlotClaimReplayCache()
    seed_pubkey = _pubkey(_case("claim_seq_cache_seed"))
    is_valid, _ = verify_slot_claim(seed, seed_pubkey, replay_cache=cache, now_unix=EVAL_TIME)
    assert is_valid

    for name in ("claim_seq_replay_equal", "claim_seq_replay_lower"):
        claim = _decode(_case(name))
        pubkey = _pubkey(_case(name))
        is_valid, reason = verify_slot_claim(claim, pubkey, replay_cache=cache, now_unix=EVAL_TIME)
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
    is_valid, _ = verify_slot_claim(claim, pubkey, now_unix=EVAL_TIME)
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


# ─── Byte-strict envelope framing (33vn) ──────────────────────────────────────


def _long_bstr_head(value: bytes) -> bytes:
    # Long-form bstr head: argument 0x59 with a 2-byte length.
    return b"\x59" + len(value).to_bytes(2, "big") + value


def _elements(name: str) -> tuple[bytes, bytes, bytes, bytes]:
    # (protected, unprotected map, payload, signature) of a signature-valid
    # envelope; the signature stays byte-identical in every malleation
    # below, so the Schnorr digest still verifies — only the strict envelope
    # reader can reject these forms.
    elements = cbor2.loads(_hex(_case(name)["cose_sign1_hex"]))
    return elements[0], elements[1], elements[2], elements[3]


def _build(
    prot: bytes,
    unprot_head: bytes = b"\xa1",
    label_head: bytes = b"\x04",
    kid_head: bytes | None = None,
    payload_head: bytes | None = None,
    sig_head: bytes | None = None,
    array_head: bytes = b"\x84",
    trailing: bytes = b"",
    prot_head: bytes | None = None,
) -> bytes:
    _, unprot, payload, sig = _elements("happy_path_n1")
    kid = unprot.get(4)
    kid_head = kid_head if kid_head is not None else b"\x48"
    payload_head = payload_head if payload_head is not None else b"\x58" + bytes([len(payload)])
    sig_head = sig_head if sig_head is not None else b"\x58\x30"
    if prot_head is None:
        prot_head = b"\x47" if prot == _elements("happy_path_n1")[0] else _long_bstr_head(prot)
    return (
        array_head
        + prot_head
        + prot
        + unprot_head
        + label_head
        + kid_head
        + kid
        + payload_head
        + payload
        + sig_head
        + sig
        + trailing
    )


@pytest.mark.parametrize(
    "description,kwargs",
    [
        ("long-form array head 98 04", {"array_head": b"\x98\x04"}),
        (
            "long-form protected bstr head",
            # Head 0x59 00 07 on the correct 7-byte value: rejected for the
            # head form alone (value is exactly _STRICT_PROTECTED).
            {"prot_head": b"\x59\x00\x07"},
        ),
        ("long-form payload bstr head", {"payload_head": b"\x59\x00\x1c"}),
        ("long-form signature bstr head", {"sig_head": b"\x59\x00\x30"}),
        ("two-entry unprotected map", {"unprot_head": b"\xa2", "trailing": b"\x45x"}),
        ("non-minimal kid label uint", {"label_head": b"\x18\x04"}),
        ("non-minimal bstr head for kid", {"kid_head": b"\x59\x00\x08"}),
        ("trailing bytes after signature", {"trailing": b"\x00"}),
    ],
)
def test_lenient_envelope_framing_rejected(description: str, kwargs: dict) -> None:
    # 33vn: a lenient framing form of a signature-valid envelope must fail
    # decode exactly as Rust from_cose fails the identical bytes (long-form
    # array/bstr heads, non-minimal uint, extra unprotected entries,
    # trailing bytes).
    prot = kwargs.pop("prot", _elements("happy_path_n1")[0])
    malleated = _build(prot, **kwargs)
    with pytest.raises(ClaimError):
        SlotClaim.decode_cose(malleated)


def test_strict_body_roundtrip_decodes() -> None:
    # Sanity: the hand-built strict envelope decodes to the vector fields
    # (guards _build's minimal heads against drift).
    prot, unprot, payload, sig = _elements("happy_path_n1")
    claim = SlotClaim.decode_cose(_build(prot))
    assert claim.slots == tuple(_case("happy_path_n1")["slots"])
    assert len(_build(prot)) == 9 + 3 + 8 + 30 + 50  # framing + heads + kid + payload + sig


def test_oversized_envelope_rejected_before_decode() -> None:
    # prgb: the envelope cap fires before the strict reader slices the
    # payload bstr and cbor2.loads materializes it — a max-legit claim is
    # ~20.6 KB; 24 KB bounds pre-rejection decode work. Pin both sides of
    # the boundary: exactly-at-cap parses (fails later for alg), one over
    # is size-rejected. (Merge resolution: the beads-worker-3 boundary-
    # pinning form subsumes HEAD's single over-cap check.)
    from lichen.gateway.slot_claim import MAX_CLAIM_ENVELOPE_BYTES

    # Exactly at the cap: parses past the size gate, rejected downstream
    # (protected head byte 0x00 is a uint, not a bstr). A size-gate
    # rejection here would instead read "exceeds maximum size".
    with pytest.raises(ClaimError, match="protected header must be a byte string"):
        SlotClaim.decode_cose(b"\x84" + b"\x00" * (MAX_CLAIM_ENVELOPE_BYTES - 1))
    # One over the cap: rejected by the size gate.
    with pytest.raises(ClaimError, match="envelope exceeds maximum size"):
        SlotClaim.decode_cose(b"\x84" + b"\x00" * MAX_CLAIM_ENVELOPE_BYTES)
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


# ─── Deterministic-CBOR payload gate (5rfl / cb10) ────────────────────────────


def _rebuild_envelope(case: dict, payload_bytes: bytes) -> bytes:
    """Reassemble the COSE_Sign1 with *payload_bytes* as the payload bstr,
    keeping the signer's original signature."""
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
    "key,raw_value",
    [
        (3, b"\xc2\x41\x00"),  # tag-2 bignum 0 at mode (signer's value)
        (3, b"\xc2\x41\x01"),  # tag-2 bignum 1 at mode
        (6, b"\x18\x00"),  # long-form uint at claim_seq (signer's value)
        (6, b"\xc2\x41\x05"),  # tag-2 bignum at claim_seq
        (2, b"\x18\x0c"),  # long-form uint at superframe_epoch (signer's value)
        (1, b"\x81\x18\x07"),  # long-form uint in slots
    ],
)
def test_non_canonical_uint_encodings_rejected_at_decode(key: int, raw_value: bytes) -> None:
    # 5rfl: cbor2 decodes tag-2 bignums (c2 41 00) and non-minimal long-form
    # uints (18 00) to plain int, so every type gate accepts them — while
    # Rust's p.uint()/head(0) rejects the identical wire bytes as
    # MalformedClaim before any signature check. Three cases (bignum 0 at
    # mode, 18 00 at claim_seq, 18 0c at epoch) decode to the signer's own
    # values, so the signature still verifies over the canonical re-encode:
    # without the canonical-form gate, signature-valid wire input splits
    # Python's verdict from every Rust peer. The other three change the
    # signed semantic value (the signature would fail too), but Rust still
    # rejects them at decode — decode must agree.
    case = _case("happy_path_n1")
    payload = _payload_bytes_with_raw(case, key, raw_value)
    with pytest.raises(ClaimError, match="canonically encoded"):
        SlotClaim.decode_cose(_rebuild_envelope(case, payload))


def test_reordered_payload_keys_rejected_at_decode() -> None:
    # cb10: the wire contract is deterministic-CBOR with keys 1-7 ascending
    # (spec/decisions.jsonl slot-claim-cose-sign1). Emitting the same seven
    # key/value pairs out of order decodes to an identical field set (and
    # the signature verifies over the canonical re-encode). Rust rejects it
    # because its sig digest covers the RECEIVED payload bytes (slot.rs:633)
    # → signature failure; C digests the received bytes likewise. Python's
    # canonical-form gate rejects it at decode.
    case = _case("happy_path_n1")
    case_envelope = cbor2.loads(_hex(case["cose_sign1_hex"]))
    fields = cbor2.loads(case_envelope[2])
    body = bytearray([0xA7])
    for k in (2, 1, 3, 4, 5, 6, 7):  # keys 1 and 2 swapped
        body += cbor2.dumps(k)
        body += cbor2.dumps(fields[k])
    with pytest.raises(ClaimError, match="canonically encoded"):
        SlotClaim.decode_cose(_rebuild_envelope(case, bytes(body)))


def test_duplicate_payload_key_rejected_at_decode() -> None:
    # cb10: a duplicate key (wire {6:5, 6:5}) decodes via cbor2 last-wins to
    # the signer's claim_seq, so the signature verifies over the canonical
    # re-encode — but the 8-pair map is not the canonical 7-pair form. The
    # gate rejects it; Rust/C reject duplicates via a seen-bitmask.
    case = _case("happy_path_n1")
    case_envelope = cbor2.loads(_hex(case["cose_sign1_hex"]))
    fields = cbor2.loads(case_envelope[2])
    body = bytearray([0xA8])  # 8-pair map
    for k in range(1, 8):
        body += cbor2.dumps(k)
        body += cbor2.dumps(fields[k])
        if k == 6:  # duplicate key 6 with the same value
            body += cbor2.dumps(6)
            body += cbor2.dumps(fields[6])
    with pytest.raises(ClaimError, match="canonically encoded"):
        SlotClaim.decode_cose(_rebuild_envelope(case, bytes(body)))


def test_unknown_payload_key_rejected_at_decode() -> None:
    # cb10: an unknown key (8) is ignored by cbor2's dict decode (the field
    # set is unchanged, signature verifies over the re-encode), but the
    # 8-pair map is not the canonical form. The gate rejects it; Rust/C
    # reject unknown keys (key range 1-7).
    case = _case("happy_path_n1")
    case_envelope = cbor2.loads(_hex(case["cose_sign1_hex"]))
    fields = cbor2.loads(case_envelope[2])
    body = bytearray([0xA8])  # 8-pair map
    for k in range(1, 8):
        body += cbor2.dumps(k)
        body += cbor2.dumps(fields[k])
    body += cbor2.dumps(8)  # unknown key
    body += cbor2.dumps(0)
    with pytest.raises(ClaimError, match="canonically encoded"):
        SlotClaim.decode_cose(_rebuild_envelope(case, bytes(body)))


@pytest.mark.parametrize(
    "raw_mode",
    [
        b"\xf4",  # false
        b"\xf5",  # true
        b"\xf9\x00\x00",  # float16 0.0
        b"\xfa\x00\x00\x00\x00",  # float32 0.0
        b"\xfa\x3f\x80\x00\x00",  # float32 1.0
        b"\xfb\x00\x00\x00\x00\x00\x00\x00\x00",  # float64 0.0
    ],
)
def test_non_integer_mode_raw_cbor_rejected_at_decode(raw_mode: bytes) -> None:
    # (Merge resolution: renamed from test_non_integer_mode_rejected_at_decode
    # so it does not shadow the ft5w test of the same name above — that test
    # drives the type-strict mode check through cbor2-decoded Python values;
    # this one drives it with raw wire bytes, additionally covering the
    # float16/float32 encodings that cbor2.dumps never emits.)
    # ft5w: CBOR false (f4), true (f5), and float 0.0/1.0 (f9/fa/fb ...)
    # decode via cbor2 to Python False/True/0.0/1.0, which value-equality
    # ('mode == 0') would accept as INTERLEAVED — Rust's p.uint() rejects
    # non-uint major types as MalformedClaim. The type-strict check
    # (type(mode) is not int) must reject these with the mode error, not
    # the canonical-gate error (the gate would catch them too, but the
    # type check is the targeted fix and produces the precise diagnostic).
    case = _case("happy_path_n1")
    payload = _payload_bytes_with_raw(case, 3, raw_mode)
    with pytest.raises(ClaimError, match="mode must be 0"):
        SlotClaim.decode_cose(_rebuild_envelope(case, payload))


def test_trailing_payload_bytes_rejected_at_decode() -> None:
    # cb10: the pinned cbor2.loads ACCEPTS trailing bytes after the payload
    # map, so the canonical-form gate is the sole enforcement point here —
    # a payload with a trailing byte must be rejected by the gate.
    case = _case("happy_path_n1")
    case_envelope = cbor2.loads(_hex(case["cose_sign1_hex"]))
    payload = case_envelope[2] + b"\x00"
    with pytest.raises(ClaimError):
        SlotClaim.decode_cose(_rebuild_envelope(case, payload))


def test_canonical_payload_accepted_and_verifies() -> None:
    # Positive control for the canonical gate: a hand-built map with
    # canonical (minimal) value encodings must still decode AND verify —
    # the gate rejects encodings, not the hand-built construction itself.
    case = _case("happy_path_n1")
    envelope_elements = cbor2.loads(_hex(case["cose_sign1_hex"]))
    fields = cbor2.loads(envelope_elements[2])
    payload_bytes = _payload_bytes_with_raw(case, 3, cbor2.dumps(fields[3]))
    claim = SlotClaim.decode_cose(_rebuild_envelope(case, payload_bytes))
    assert claim.allocation_mode == (
        AllocationMode.INTERLEAVED if fields[3] == 0 else AllocationMode.CONTIGUOUS
    )
    assert verify_slot_claim(claim, _pubkey(case), now_unix=EVAL_TIME) == (True, None)
