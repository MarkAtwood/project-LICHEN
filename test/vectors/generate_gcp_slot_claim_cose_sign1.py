#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate independent GCP-6.5 slot-claim COSE_Sign1 test vectors.

Covers the parent bead's deltas over the happy path: signature coverage of
slots/expiry/claim_seq (slots_array_mutation), the claim_seq replay gate,
expiry boundaries (spec: expiry > now), the header algorithm decoy
({1: -65536} per the spec/08 typo), kid/payload IID mismatch, and the
missing-ordinal payload. Complements gcp_handoff_cose_sign1.json (GCP-7.1)
without duplicating it.

Oracle: this generator plus spec/08-gateway-coordination.md GCP-6.5. The
signer is reference_schnorr48.py (independent PyNaCl implementation of
draft-lichen-schnorr-00); no lichen package imports, so vectors are never
derived from the code under test.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import cbor2

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from atomic_json import atomic_write_json_batch, json_bytes, read_bounded_exact  # noqa: E402
from reference_schnorr48 import ReferenceIdentity, sign, verify  # noqa: E402

OUTPUT = HERE / "gcp_slot_claim_cose_sign1.json"
FORMAT_VERSION = 1
ALG = -65537  # Schnorr48-Ed25519
NOW = 1_900_000_000  # fixed evaluation instant for all expiry cases
MAX_CLAIM_DURATION_S = 300  # 5 superframes x 60 s (MAX_CLAIM_DURATION_SUPERFRAMES)
CLOCK_TOLERANCE_S = 5  # spec step 7a clock tolerance

# Deterministic identities for reproducible vectors
GW_A = ReferenceIdentity.from_seed(bytes(range(32)))
GW_B = ReferenceIdentity.from_seed(bytes(range(32, 64)))

# Payload keys (spec GCP-6.5, integer keys 1..7)
K_SLOTS = 1
K_SUPERFRAME_EPOCH = 2
K_MODE = 3
K_EXPIRY = 4
K_GATEWAY_IID = 5
K_CLAIM_SEQ = 6
K_ORDINAL = 7

# Reject reasons (receiver-side validation steps 3-8)
REASON_NONE = "none"
REASON_SIGNATURE = "signature"
REASON_REPLAY = "replay"
REASON_EXPIRED = "expired"
REASON_ALGORITHM = "algorithm"
REASON_KID_MISMATCH = "kid_payload_mismatch"
REASON_MALFORMED = "ordinal_missing"


def _claim_payload(
    *,
    slots: list[int],
    superframe_epoch: int,
    mode: int,
    expiry: int,
    gateway_iid: bytes,
    claim_seq: int,
    include_ordinal: bool = True,
    ordinal: int = 0,
) -> bytes:
    """Canonical CBOR payload map, integer keys 1..7 (RFC 8949 4.2.1 order)."""
    payload: dict[int, object] = {
        K_SLOTS: slots,
        K_SUPERFRAME_EPOCH: superframe_epoch,
        K_MODE: mode,
        K_EXPIRY: expiry,
        K_GATEWAY_IID: gateway_iid,
        K_CLAIM_SEQ: claim_seq,
    }
    if include_ordinal:
        payload[K_ORDINAL] = ordinal
    return cbor2.dumps(payload, canonical=True)


def _build_case(
    name: str,
    description: str,
    *,
    signer: ReferenceIdentity = GW_A,
    kid: bytes | None = None,
    protected: bytes | None = None,
    signed_payload: bytes,
    emitted_payload: bytes | None = None,
    expect_valid: bool,
    reject_reason: str = REASON_NONE,
    slots: list[int],
    superframe_epoch: int = 12,
    mode: int = 0,
    expiry: int = NOW + MAX_CLAIM_DURATION_S,
    claim_seq: int = 1,
    ordinal: int = 0,
    receiver_cached_claim_seq: int | None = None,
) -> dict[str, object]:
    """Build one COSE_Sign1 slot-claim vector case.

    signed_payload is what the signature covers; emitted_payload (default:
    signed_payload) is what ships inside the COSE_Sign1 - they differ only
    for the byte-level slots mutation case, where a valid signature for the
    original payload must fail against the mutated one.
    """
    kid_iid = signer.iid if kid is None else kid
    protected_bytes = cbor2.dumps({1: ALG}, canonical=True) if protected is None else protected
    emitted = signed_payload if emitted_payload is None else emitted_payload

    sig_structure = cbor2.dumps(
        ["Signature1", protected_bytes, b"", signed_payload], canonical=True
    )
    digest = hashlib.sha256(sig_structure).digest()
    signature = sign(signer, digest)
    assert verify(signer.pubkey, digest, signature), "generator self-check failed"
    cose = cbor2.dumps(
        [protected_bytes, {4: kid_iid}, emitted, signature], canonical=True
    )

    case: dict[str, object] = {
        "name": name,
        "description": description,
        "expect_valid": expect_valid,
        "expected_reject_reason": reject_reason,
        "signer_name": "gw_a" if signer is GW_A else "gw_b",
        "signer_seed_hex": signer.seed.hex(),
        "signer_public_key_hex": signer.pubkey.hex(),
        "signer_iid_hex": signer.iid.hex(),
        "kid_iid_hex": kid_iid.hex(),
        "algorithm": cbor2.loads(protected_bytes)[1],
        "protected_hex": protected_bytes.hex(),
        "payload_hex": emitted.hex(),
        "signed_payload_hex": signed_payload.hex(),
        "sig_structure_hex": sig_structure.hex(),
        "digest_hex": digest.hex(),
        "signature_hex": signature.hex(),
        "cose_sign1_hex": cose.hex(),
        "evaluation_time": NOW,
        "slots": slots,
        "superframe_epoch": superframe_epoch,
        "mode": mode,
        "expiry": expiry,
        "claim_seq": claim_seq,
        "ordinal": ordinal,
        "max_claim_duration_s": MAX_CLAIM_DURATION_S,
        "clock_tolerance_s": CLOCK_TOLERANCE_S,
    }
    if receiver_cached_claim_seq is not None:
        case["receiver_cached_claim_seq"] = receiver_cached_claim_seq
    return case


def _cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []

    # 1. Happy paths: 1, 4, and the 60-slot cap; payload keys 1..7 canonical.
    cases.append(
        _build_case(
            "happy_path_n1",
            "Single-slot claim, all seven payload keys, valid signature.",
            signed_payload=_claim_payload(
                slots=[7],
                superframe_epoch=12,
                mode=0,
                expiry=NOW + MAX_CLAIM_DURATION_S,
                gateway_iid=GW_A.iid,
                claim_seq=1,
                ordinal=0,
            ),
            expect_valid=True,
            slots=[7],
            claim_seq=1,
        )
    )
    cases.append(
        _build_case(
            "happy_path_n4",
            "Typical four-slot claim; the ~110-byte on-air shape from the spec.",
            signed_payload=_claim_payload(
                slots=[3, 4, 5, 6],
                superframe_epoch=12,
                mode=0,
                expiry=NOW + MAX_CLAIM_DURATION_S,
                gateway_iid=GW_A.iid,
                claim_seq=2,
                ordinal=0,
            ),
            expect_valid=True,
            slots=[3, 4, 5, 6],
            claim_seq=2,
        )
    )
    cases.append(
        _build_case(
            "happy_path_n60",
            "60-slot claim at CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS (backbone transport).",
            signed_payload=_claim_payload(
                slots=list(range(60)),
                superframe_epoch=12,
                mode=1,
                expiry=NOW + MAX_CLAIM_DURATION_S,
                gateway_iid=GW_A.iid,
                claim_seq=3,
                ordinal=1,
            ),
            expect_valid=True,
            slots=list(range(60)),
            mode=1,
            claim_seq=3,
            ordinal=1,
        )
    )

    # 2. THE parent-bead regression case: valid signature over the original
    #    payload, slots array mutated in the emitted COSE_Sign1. The old
    #    signer covered only ordinal/IID/superframe_id, so this forgery
    #    verified; COSE_Sign1 over the full payload MUST reject it.
    original_slots = [3, 4, 5, 6]
    mutated_slots = [3, 4, 5, 7]
    signed = _claim_payload(
        slots=original_slots,
        superframe_epoch=12,
        mode=0,
        expiry=NOW + MAX_CLAIM_DURATION_S,
        gateway_iid=GW_A.iid,
        claim_seq=4,
        ordinal=0,
    )
    mutated = _claim_payload(
        slots=mutated_slots,
        superframe_epoch=12,
        mode=0,
        expiry=NOW + MAX_CLAIM_DURATION_S,
        gateway_iid=GW_A.iid,
        claim_seq=4,
        ordinal=0,
    )
    cases.append(
        _build_case(
            "slots_array_mutation",
            "Valid envelope signature re-attached to a mutated slots array "
            "(last slot 6 -> 7): MUST fail verification. Regression case for "
            "the old ordinal/IID/superframe_id-only signer.",
            signed_payload=signed,
            emitted_payload=mutated,
            expect_valid=False,
            reject_reason=REASON_SIGNATURE,
            slots=mutated_slots,
            claim_seq=4,
        )
    )

    # 3. claim_seq replay gate (spec step 8, NV high-water per gateway).
    cache_seed_seq = 5
    cases.append(
        _build_case(
            "claim_seq_cache_seed",
            "First claim from GW_A at seq 5: valid and seeds the receiver's "
            "per-gateway claim_seq high-water for the replay cases.",
            signed_payload=_claim_payload(
                slots=[10, 11],
                superframe_epoch=12,
                mode=0,
                expiry=NOW + MAX_CLAIM_DURATION_S,
                gateway_iid=GW_A.iid,
                claim_seq=cache_seed_seq,
                ordinal=0,
            ),
            expect_valid=True,
            slots=[10, 11],
            claim_seq=cache_seed_seq,
        )
    )
    for seq, label in ((cache_seed_seq, "equal"), (cache_seed_seq - 1, "lower")):
        cases.append(
            _build_case(
                f"claim_seq_replay_{label}",
                f"Freshly signed claim with claim_seq {label} to the cached "
                f"high-water ({cache_seed_seq}): step 8 MUST reject "
                "(claim_seq > cached required).",
                signed_payload=_claim_payload(
                    slots=[10, 11],
                    superframe_epoch=12,
                    mode=0,
                    expiry=NOW + MAX_CLAIM_DURATION_S,
                    gateway_iid=GW_A.iid,
                    claim_seq=seq,
                    ordinal=0,
                ),
                expect_valid=False,
                reject_reason=REASON_REPLAY,
                slots=[10, 11],
                claim_seq=seq,
                receiver_cached_claim_seq=cache_seed_seq,
            )
        )

    # 4. Expiry boundaries (spec step 7: expiry > now; 7a: duration cap).
    expiry_notes = {
        "past": "one second before the evaluation instant: step 7 rejects.",
        "now": "exactly the evaluation instant: spec requires expiry > now, "
        "so 'now' itself rejects.",
        "future": "one second after the evaluation instant: strictly greater "
        "than now and within the max-claim duration, so it accepts.",
    }
    for label, expiry, valid in (
        ("past", NOW - 1, False),
        ("now", NOW, False),
        ("future", NOW + 1, True),
    ):
        cases.append(
            _build_case(
                f"expiry_boundary_{label}",
                f"expiry = {expiry} is {expiry_notes[label]}",
                signed_payload=_claim_payload(
                    slots=[1],
                    superframe_epoch=12,
                    mode=0,
                    expiry=expiry,
                    gateway_iid=GW_A.iid,
                    claim_seq=6,
                    ordinal=0,
                ),
                expect_valid=valid,
                reject_reason=REASON_NONE if valid else REASON_EXPIRED,
                slots=[1],
                expiry=expiry,
                claim_seq=6,
            )
        )

    # 5. Header algorithm decoy: spec/08 typo encodes {1: -65536}; step 4
    #    requires -65537. Signature is valid over the decoy header - the
    #    reject must come from the algorithm check, not verification.
    decoy_protected = bytes.fromhex("a10139ffff")  # {1: -65536}
    cases.append(
        _build_case(
            "header_alg_decoy",
            "Protected header {1: -65536} (the spec typo's decoy value) with "
            "a signature correctly computed over it: step 4 MUST reject on "
            "the algorithm before signature evaluation.",
            protected=decoy_protected,
            signed_payload=_claim_payload(
                slots=[2],
                superframe_epoch=12,
                mode=0,
                expiry=NOW + MAX_CLAIM_DURATION_S,
                gateway_iid=GW_A.iid,
                claim_seq=7,
                ordinal=0,
            ),
            expect_valid=False,
            reject_reason=REASON_ALGORITHM,
            slots=[2],
            claim_seq=7,
        )
    )

    # 6. kid / payload gateway_iid mismatch (spec steps 3+6).
    cases.append(
        _build_case(
            "kid_payload_iid_mismatch",
            "Unprotected kid names GW_B (a known gateway, so step 3 passes) "
            "while the signed payload binds GW_A's IID: step 6 MUST reject.",
            signer=GW_A,
            kid=GW_B.iid,
            signed_payload=_claim_payload(
                slots=[8],
                superframe_epoch=12,
                mode=0,
                expiry=NOW + MAX_CLAIM_DURATION_S,
                gateway_iid=GW_A.iid,
                claim_seq=8,
                ordinal=0,
            ),
            expect_valid=False,
            reject_reason=REASON_KID_MISMATCH,
            slots=[8],
            claim_seq=8,
        )
    )

    # 7. Ordinal absent: 6-key payload; the receiver needs ordinal for
    #    register_gateway (interleaved assignment).
    cases.append(
        _build_case(
            "ordinal_absent",
            "Payload carries keys 1..6 but omits ordinal (key 7): MUST "
            "reject as malformed - the receiver cannot register the gateway.",
            signed_payload=_claim_payload(
                slots=[9],
                superframe_epoch=12,
                mode=0,
                expiry=NOW + MAX_CLAIM_DURATION_S,
                gateway_iid=GW_A.iid,
                claim_seq=9,
                include_ordinal=False,
            ),
            expect_valid=False,
            reject_reason=REASON_MALFORMED,
            slots=[9],
            claim_seq=9,
        )
    )

    return cases


def document() -> dict[str, object]:
    cases = _cases()
    return {
        "$schema": "./schema.json",
        "vector_type": "gcp_slot_claim_cose_sign1",
        "format_version": FORMAT_VERSION,
        "description": (
            "GCP-6.5 slot-claim COSE_Sign1 test vectors for "
            "spec/08-gateway-coordination.md. Covers signature coverage of "
            "slots/expiry/claim_seq, the claim_seq replay gate, expiry "
            "boundaries, the header algorithm decoy ({1: -65536}), kid/"
            "payload IID mismatch, and the missing-ordinal payload. "
            "Schnorr48-Ed25519 (alg -65537), RFC 9052 Sig_structure, "
            "integer-keyed payload map 1..7."
        ),
        "oracle": {
            "basis": "RFC 9052 Sig_structure plus LICHEN spec GCP-6.5",
            "implementation": (
                "independent PyNaCl reference_schnorr48.py; no lichen package imports"
            ),
            "generator_command": "python3 test/vectors/generate_gcp_slot_claim_cose_sign1.py",
            "freshness_command": (
                "python3 test/vectors/generate_gcp_slot_claim_cose_sign1.py --check"
            ),
        },
        "constants": {
            "algorithm": ALG,
            "protected_hex": "a1013a00010000",  # {1: -65537}
            "evaluation_time": NOW,
            "max_claim_duration_s": MAX_CLAIM_DURATION_S,
            "clock_tolerance_s": CLOCK_TOLERANCE_S,
            "payload_keys": [
                K_SLOTS,
                K_SUPERFRAME_EPOCH,
                K_MODE,
                K_EXPIRY,
                K_GATEWAY_IID,
                K_CLAIM_SEQ,
                K_ORDINAL,
            ],
            "reject_reasons": [
                REASON_NONE,
                REASON_SIGNATURE,
                REASON_REPLAY,
                REASON_EXPIRED,
                REASON_ALGORITHM,
                REASON_KID_MISMATCH,
                REASON_MALFORMED,
            ],
        },
        "identities": [
            {
                "name": "gw_a",
                "seed_hex": GW_A.seed.hex(),
                "public_key_hex": GW_A.pubkey.hex(),
                "iid_hex": GW_A.iid.hex(),
            },
            {
                "name": "gw_b",
                "seed_hex": GW_B.seed.hex(),
                "public_key_hex": GW_B.pubkey.hex(),
                "iid_hex": GW_B.iid.hex(),
            },
        ],
        "cases": cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    generated = document()
    if args.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    print(f"Wrote {len(generated['cases'])} slot-claim COSE_Sign1 cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
