#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate GCP-6.5 slot-claim COSE_Sign1 admission vectors.

Independent-oracle construction for spec/08 9.8 (GCP-6.5): the CBOR claim
payload map (keys 1-7 canonical order), the COSE_Sign1 envelope
[protected {1: -65537}, {4: gateway_iid}, payload, sig], and the
Schnorr48-Ed25519 signature over SHA-256(Sig_structure).

The CBOR/COSE construction here is written from the spec text; the only
lichen import is the sanctioned reference crypto implementation
(python/src/lichen/crypto/schnorr48.py), the same oracle behind
test/vectors/schnorr48.json.

Vector cases: valid baseline, same-claim_seq replay pair, expired, payload
mutation, signature mutation, and the decoy protected-alg {1: -65536}.

Usage: python3 test/vectors/generate_gcp_slot_claim_cose_sign1.py \
           test/vectors/gcp_slot_claim_cose_sign1.json
"""

import hashlib
import json
import sys

sys.path.insert(0, "python/src")
from lichen.crypto.schnorr48 import derive_keypair, sign, verify  # noqa: E402

# Protected header: bstr-wrapped {1: -65537} (alg Schnorr48-Ed25519).
PROTECTED_ALG = bytes.fromhex("A1013A00010000")
# Spec decoy: {1: -65536} (A1 01 39 FF FF) — must be rejected.
DECOY_ALG = bytes.fromhex("A10139FFFF")


def cbor_uint(v: int) -> bytes:
    if v < 24:
        return bytes([v])
    if v < 0x100:
        return bytes([0x18, v])
    if v < 0x10000:
        return bytes([0x19]) + v.to_bytes(2, "big")
    if v < 0x100000000:
        return bytes([0x1A]) + v.to_bytes(4, "big")
    return bytes([0x1B]) + v.to_bytes(8, "big")


def cbor_bstr(b: bytes) -> bytes:
    """Major-2 byte string with canonical length header."""
    l = len(b)
    if l < 24:
        return bytes([0x40 | l]) + b
    if l < 0x100:
        return bytes([0x58, l]) + b
    return bytes([0x59]) + l.to_bytes(2, "big") + b


def cbor_array_header(n: int) -> bytes:
    if n < 24:
        return bytes([0x80 | n])
    return bytes([0x98, n])


def cbor_map_header(n: int) -> bytes:
    if n < 24:
        return bytes([0xA0 | n])
    return bytes([0xB8, n])


def claim_payload(slots, superframe_epoch, mode, expiry, gateway_iid, claim_seq, ordinal) -> bytes:
    """Spec 08 GCP-6.5 payload map: keys 1-7 in canonical order."""
    out = cbor_map_header(7)
    out += cbor_uint(1) + cbor_array_header(len(slots))
    for slot in slots:
        out += cbor_uint(slot)
    out += cbor_uint(2) + cbor_uint(superframe_epoch)
    out += cbor_uint(3) + cbor_uint(mode)
    out += cbor_uint(4) + cbor_uint(expiry)
    out += cbor_uint(5) + cbor_bstr(gateway_iid)
    out += cbor_uint(6) + cbor_uint(claim_seq)
    out += cbor_uint(7) + cbor_uint(ordinal)
    return out


def sig_structure(payload: bytes, protected: bytes) -> bytes:
    out = cbor_array_header(4)
    out += cbor_bstr(b"Signature1")
    out += cbor_bstr(protected)
    out += cbor_bstr(b"")
    out += cbor_bstr(payload)
    return out


def cose_sign1(payload: bytes, signature: bytes, gateway_iid: bytes, protected: bytes) -> bytes:
    out = cbor_array_header(4)
    out += cbor_bstr(protected)
    out += cbor_map_header(1) + cbor_uint(4) + cbor_bstr(gateway_iid)
    out += cbor_bstr(payload)
    out += cbor_bstr(signature)
    return out


def sign_claim(seed: bytes, payload: bytes) -> tuple[bytes, bytes]:
    priv, pub = derive_keypair(seed)
    digest = hashlib.sha256(sig_structure(payload, PROTECTED_ALG)).digest()
    sig = sign(priv, pub, digest)
    assert verify(pub, digest, sig), "self-check: reference verify must accept"
    return pub, sig


def iid_of(pubkey: bytes) -> bytes:
    """Spec 6.2 canonical IID: SHA-512(pubkey)[0:8] with U/L cleared."""
    iid = bytearray(hashlib.sha512(pubkey).digest()[:8])
    iid[0] &= ~0x02 & 0xFF
    return bytes(iid)


def main() -> None:
    out_path = sys.argv[1] if len(sys.argv) > 1 else \
        "test/vectors/gcp_slot_claim_cose_sign1.json"

    gateway_seed = bytes(range(0x41, 0x61))  # deterministic test seed
    gateway_pub, _ = derive_keypair(gateway_seed)
    _p2, _q2 = derive_keypair(gateway_seed)
    gateway_iid = iid_of(gateway_pub)

    now_unix = 1500
    claims = []

    baseline_payload = claim_payload([1, 2], 3, 1, 2000, gateway_iid, 5, 0)
    baseline_pub, baseline_sig = sign_claim(gateway_seed, baseline_payload)
    claims.append({
        "name": "valid_baseline",
        "description": "well-formed claim: seq=5, expiry=2000, now=1500",
        "gateway_seed_hex": gateway_seed.hex(),
        "gateway_public_key_hex": gateway_pub.hex(),
        "gateway_iid_hex": gateway_iid.hex(),
        "claim_seq": 5,
        "expiry": 2000,
        "now_unix": now_unix,
        "clock_valid": True,
        "payload_hex": baseline_payload.hex(),
        "signature_hex": baseline_sig.hex(),
        "protected_alg_hex": PROTECTED_ALG.hex(),
        "cose_sign1_hex": cose_sign1(
            baseline_payload, baseline_sig, gateway_iid, PROTECTED_ALG).hex(),
        "expect": "admit",
    })

    # Replay: the identical claim ingested a second time (seq already seen).
    claims.append({
        "name": "replay_same_claim_seq",
        "description": "duplicate of valid_baseline: claim_seq=5 already consumed",
        "gateway_seed_hex": gateway_seed.hex(),
        "gateway_public_key_hex": gateway_pub.hex(),
        "gateway_iid_hex": gateway_iid.hex(),
        "claim_seq": 5,
        "expiry": 2000,
        "now_unix": now_unix,
        "clock_valid": True,
        "payload_hex": baseline_payload.hex(),
        "signature_hex": baseline_sig.hex(),
        "protected_alg_hex": PROTECTED_ALG.hex(),
        "cose_sign1_hex": cose_sign1(
            baseline_payload, baseline_sig, gateway_iid, PROTECTED_ALG).hex(),
        "expect": "reject_replay",
    })

    # Expired: expiry (1000) before the synced clock (1500).
    expired_payload = claim_payload([4], 3, 1, 1000, gateway_iid, 6, 0)
    expired_pub, expired_sig = sign_claim(gateway_seed, expired_payload)
    claims.append({
        "name": "expired",
        "description": "expiry=1000 < now=1500 with a valid clock",
        "gateway_seed_hex": gateway_seed.hex(),
        "gateway_public_key_hex": expired_pub.hex(),
        "gateway_iid_hex": gateway_iid.hex(),
        "claim_seq": 6,
        "expiry": 1000,
        "now_unix": now_unix,
        "clock_valid": True,
        "payload_hex": expired_payload.hex(),
        "signature_hex": expired_sig.hex(),
        "protected_alg_hex": PROTECTED_ALG.hex(),
        "cose_sign1_hex": cose_sign1(
            expired_payload, expired_sig, gateway_iid, PROTECTED_ALG).hex(),
        "expect": "reject_expired",
    })

    # Payload mutation: flip one bit inside the signed payload.
    mutated = bytearray(baseline_payload)
    mutated[3] ^= 0x01
    mutated_payload = bytes(mutated)
    _, mutated_sig = sign_claim(gateway_seed, baseline_payload)  # sig from ORIGINAL
    claims.append({
        "name": "payload_mutation",
        "description": "one payload bit flipped: signature must fail",
        "gateway_seed_hex": gateway_seed.hex(),
        "gateway_public_key_hex": gateway_pub.hex(),
        "gateway_iid_hex": gateway_iid.hex(),
        "claim_seq": 5,
        "expiry": 2000,
        "now_unix": now_unix,
        "clock_valid": True,
        "payload_hex": mutated_payload.hex(),
        "signature_hex": mutated_sig.hex(),
        "protected_alg_hex": PROTECTED_ALG.hex(),
        "cose_sign1_hex": cose_sign1(
            mutated_payload, mutated_sig, gateway_iid, PROTECTED_ALG).hex(),
        "expect": "reject_signature",
    })

    # Signature mutation: flip the last signature byte.
    bad_sig = bytearray(baseline_sig)
    bad_sig[-1] ^= 0x01
    claims.append({
        "name": "signature_mutation",
        "description": "one signature byte flipped: schnorr48_verify must fail",
        "gateway_seed_hex": gateway_seed.hex(),
        "gateway_public_key_hex": gateway_pub.hex(),
        "gateway_iid_hex": gateway_iid.hex(),
        "claim_seq": 5,
        "expiry": 2000,
        "now_unix": now_unix,
        "clock_valid": True,
        "payload_hex": baseline_payload.hex(),
        "signature_hex": bytes(bad_sig).hex(),
        "protected_alg_hex": PROTECTED_ALG.hex(),
        "cose_sign1_hex": cose_sign1(
            baseline_payload, bytes(bad_sig), gateway_iid, PROTECTED_ALG).hex(),
        "expect": "reject_signature",
    })

    # Decoy protected alg {1: -65536} (A1 01 39 FF FF) — must be rejected.
    decoy_payload = claim_payload([7], 3, 1, 2000, gateway_iid, 8, 0)
    decoy_pub, decoy_sig = sign_claim(gateway_seed, decoy_payload)
    claims.append({
        "name": "decoy_protected_alg",
        "description": "protected alg {1:-65536} is the spec decoy — reject",
        "gateway_seed_hex": gateway_seed.hex(),
        "gateway_public_key_hex": decoy_pub.hex(),
        "gateway_iid_hex": gateway_iid.hex(),
        "claim_seq": 8,
        "expiry": 2000,
        "now_unix": now_unix,
        "clock_valid": True,
        "payload_hex": decoy_payload.hex(),
        "signature_hex": decoy_sig.hex(),
        "protected_alg_hex": DECOY_ALG.hex(),
        "cose_sign1_hex": cose_sign1(
            decoy_payload, decoy_sig, gateway_iid, DECOY_ALG).hex(),
        "expect": "reject_alg",
    })

    corpus = {
        "vector_type": "gcp_slot_claim_cose_sign1",
        "format_version": 1,
        "description": (
            "GCP-6.5 slot-claim COSE_Sign1 admission corpus (spec/08 9.8): "
            "canonical CBOR claim payload (keys 1-7), protected header "
            "{1:-65537}, Schnorr48-Ed25519 over SHA-256(Sig_structure). "
            "Admission contract: signature verify, then expiry/claim_seq/ "
            "conflict resolution."
        ),
        "oracle": {
            "basis": "spec/08 9.8 GCP-6.5 + RFC 9052 COSE_Sign1",
            "implementation": (
                "independent CBOR/COSE construction; signatures from the "
                "sanctioned reference python/src/lichen/crypto/schnorr48.py "
                "(same oracle as schnorr48.json)"
            ),
            "generator_command": (
                "python3 test/vectors/generate_gcp_slot_claim_cose_sign1.py "
                "test/vectors/gcp_slot_claim_cose_sign1.json"
            ),
        },
        "constants": {
            "protected_alg_hex": PROTECTED_ALG.hex(),
            "decoy_alg_hex": DECOY_ALG.hex(),
            "cose_key_kid": 4,
            "signature_len": 48,
        },
        "claims": claims,
    }

    # Self-check (before writing): every signature verifies or fails as
    # expected against the reference implementation.
    for c in claims:
        digest = hashlib.sha256(
            sig_structure(bytes.fromhex(c["payload_hex"]),
                          bytes.fromhex(c["protected_alg_hex"]))).digest()
        print("DIGEST selfcheck:", digest.hex(), "pub:", c["gateway_public_key_hex"][:16], "payload:", c["payload_hex"][:32], file=sys.stderr)
        ok = verify(bytes.fromhex(c["gateway_public_key_hex"]), digest,
                    bytes.fromhex(c["signature_hex"]))
        expected_ok = c["expect"] in ("admit", "reject_replay", "reject_expired")
        assert ok == expected_ok, f"{c['name']}: verify={ok}"

    with open(out_path, "w") as handle:
        json.dump(corpus, handle, indent=2)
        handle.write("\n")
    print(f"wrote {out_path}: {len(claims)} claim vectors "
          f"(signature self-check passed)")


if __name__ == "__main__":
    main()
