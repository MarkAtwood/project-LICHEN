#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate COSE_Sign1 Capability Announcement test vectors.

Per spec/06-security.md Section 8.12, Capability Announcements use COSE_Sign1
with Schnorr48-Ed25519 (algorithm -65537) and integer-keyed payloads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import cbor2

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json_batch,
    json_bytes,
    read_bounded_exact,
)
from reference_schnorr48 import ReferenceIdentity, sign  # noqa: E402

# Algorithm ID for Schnorr48-Ed25519 per spec
ALG_SCHNORR48 = -65537

# COSE header parameter labels
COSE_ALG = 1
COSE_KID = 4

# Capability announcement payload keys (integer-keyed per spec)
CAP_KEY_CAPABILITIES = 1
CAP_KEY_PREFIX = 2
CAP_KEY_PREFIX_LEN = 3
CAP_KEY_EXPIRY = 4
CAP_KEY_SEQ = 5
CAP_KEY_ANNOUNCER_IID = 6

# Capability bits
CAP_BIT_EGRESS = 0x01
CAP_BIT_PREFIX_DELEGATION = 0x02

FORMAT_VERSION = 1
OUTPUT = VECTORS_DIR / "capability_announcements.json"
SEED = bytes.fromhex("0123456789abcdef" * 4)


def _upstream_addr_for_key(pubkey: bytes) -> bytes:
    """Upstream yggdrasil-go AddrForKey (bit-invert, count leading 1s, bit-pack).

    The announcer_iid is the low 8 bytes of the routable address, matching
    Rust lichen-core ygg_addr_from_pubkey. Anchored below against the pinned
    upstream vector in yggdrasil_address.json so this reimplementation cannot
    silently diverge from the external oracle.
    """
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
    buf = bytes(b ^ 0xFF for b in pubkey)
    # Count leading 1 bits, wrapping at 256 (Go byte overflow semantics).
    ones = 0
    first_zero = 256
    for idx in range(256):
        if (buf[idx // 8] >> (7 - idx % 8)) & 1:
            ones = (ones + 1) & 0xFF
        else:
            first_zero = idx
            break
    # Whole bytes only; a trailing partial byte is discarded (upstream).
    packed = bytearray(14)
    start = first_zero + 1
    whole_bits = max(0, 256 - start) & ~7
    for out_bit in range(min(whole_bits, 112)):
        src = start + out_bit
        if (buf[src // 8] >> (7 - src % 8)) & 1:
            packed[out_bit // 8] |= 1 << (7 - out_bit % 8)
    return bytes((0x02, ones)) + bytes(packed)


def _upstream_anchor_check() -> None:
    """Pin _upstream_addr_for_key to the upstream conformance vector."""
    doc = json.loads((VECTORS_DIR / "yggdrasil_address.json").read_text())
    anchor = next(v for v in doc["vectors"] if v["name"] == "upstream_addr_for_key")
    derived = _upstream_addr_for_key(bytes.fromhex(anchor["public_key"]))
    if derived.hex() != anchor["address"]:
        raise SystemExit(
            f"upstream AddrForKey anchor mismatch: {derived.hex()} != {anchor['address']}"
        )


_upstream_anchor_check()


def _build_protected_header() -> bytes:
    """Encode protected header {1: -65537} as CBOR bytes."""
    return cbor2.dumps({COSE_ALG: ALG_SCHNORR48})


def _build_unprotected_header(iid: bytes) -> dict[int, bytes]:
    """Build unprotected header {4: <iid>}."""
    return {COSE_KID: iid}


def _build_payload(
    capabilities: int,
    prefix: bytes,
    prefix_len: int,
    expiry: int,
    seq: int,
    announcer_iid: bytes,
) -> bytes:
    """Encode capability announcement payload as CBOR."""
    payload_map = {
        CAP_KEY_CAPABILITIES: capabilities,
        CAP_KEY_PREFIX: prefix,
        CAP_KEY_PREFIX_LEN: prefix_len,
        CAP_KEY_EXPIRY: expiry,
        CAP_KEY_SEQ: seq,
        CAP_KEY_ANNOUNCER_IID: announcer_iid,
    }
    return cbor2.dumps(payload_map)


def _build_sig_structure(protected: bytes, payload: bytes) -> bytes:
    """Build COSE Sig_structure per RFC 9052.

    Sig_structure = [
        "Signature1",     ; context string
        protected,        ; protected header bytes
        h'',              ; external_aad (empty)
        payload           ; payload bytes
    ]
    """
    sig_structure = ["Signature1", protected, b"", payload]
    return cbor2.dumps(sig_structure)


def _build_cose_sign1(
    protected: bytes,
    unprotected: dict[int, bytes],
    payload: bytes,
    signature: bytes,
) -> bytes:
    """Encode COSE_Sign1 structure as CBOR array."""
    # COSE_Sign1 = [protected, unprotected, payload, signature]
    cose_sign1 = [protected, unprotected, payload, signature]
    return cbor2.dumps(cbor2.CBORTag(18, cose_sign1))


def _vector(
    name: str,
    description: str,
    *,
    capabilities: int,
    prefix: bytes,
    prefix_len: int,
    expiry: int,
    seq: int,
    seed: bytes = SEED,
    expected_valid: bool = True,
) -> dict[str, object]:
    """Generate a single capability announcement vector."""
    identity = ReferenceIdentity.from_seed(seed)
    # announcer_iid/kid = low 8 bytes of upstream AddrForKey(pubkey), matching
    # Rust lichen-core ygg_addr_from_pubkey (kd0p; the reference identity's
    # SHA-512 IID is the rejected native profile).
    announcer_iid = _upstream_addr_for_key(identity.pubkey)[8:]

    # Build COSE components
    protected = _build_protected_header()
    unprotected = _build_unprotected_header(announcer_iid)
    payload = _build_payload(
        capabilities, prefix, prefix_len, expiry, seq, announcer_iid
    )

    # Compute signature per RFC 9052
    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    signature = sign(identity, sig_structure_hash)

    # Build complete COSE_Sign1
    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, signature)

    return {
        "name": name,
        "description": description,
        "coverage": "capability_announcement_cose_sign1",
        # Identity inputs
        "signing_seed": seed.hex(),
        "public_key": identity.pubkey.hex(),
        "announcer_iid": announcer_iid.hex(),
        # Payload fields
        "capabilities": capabilities,
        "capabilities_bits": {
            "egress": bool(capabilities & CAP_BIT_EGRESS),
            "prefix_delegation": bool(capabilities & CAP_BIT_PREFIX_DELEGATION),
        },
        "prefix": prefix.hex() if prefix else "",
        "prefix_len": prefix_len,
        "expiry": expiry,
        "seq": seq,
        # COSE structure
        "protected_header": protected.hex(),
        "protected_header_decoded": {
            "alg": ALG_SCHNORR48,
            "alg_name": "Schnorr48-Ed25519",
        },
        "unprotected_header_decoded": {
            "kid": announcer_iid.hex(),
        },
        "payload_cbor": payload.hex(),
        "payload_decoded": {
            "1_capabilities": capabilities,
            "2_prefix": prefix.hex() if prefix else "",
            "3_prefix_len": prefix_len,
            "4_expiry": expiry,
            "5_seq": seq,
            "6_announcer_iid": announcer_iid.hex(),
        },
        # Signature computation
        "sig_structure": sig_structure.hex(),
        "sig_structure_layout": {
            "context": "Signature1",
            "protected": protected.hex(),
            "external_aad": "",
            "payload": payload.hex(),
        },
        "sig_structure_hash": sig_structure_hash.hex(),
        "signature": signature.hex(),
        # Complete COSE_Sign1
        "cose_sign1": cose_sign1.hex(),
        # Verification
        "expected": {
            "signature_valid": expected_valid,
            "algorithm_valid": True,
            "reserved_bits_zero": (capabilities & 0xFC) == 0,
        },
    }


def _invalid_reserved_bits_vector() -> dict[str, object]:
    """Generate vector with reserved capability bits set (invalid)."""
    return _vector(
        "capability_invalid_reserved_bits",
        "Capability announcement with reserved bits 2-7 set (MUST fail validation).",
        capabilities=0xFF,  # All bits set, including reserved 2-7
        prefix=b"",
        prefix_len=0,
        expiry=1735689600,
        seq=1,
        expected_valid=True,  # Signature is valid, but reserved bits check fails
    )


def _different_signer_vector() -> dict[str, object]:
    """Generate vector with mismatched announcer_iid and signer."""
    identity = ReferenceIdentity.from_seed(SEED)
    different_seed = bytes.fromhex("fedcba9876543210" * 4)
    different_identity = ReferenceIdentity.from_seed(different_seed)
    kid_iid = _upstream_addr_for_key(identity.pubkey)[8:]
    payload_iid = _upstream_addr_for_key(different_identity.pubkey)[8:]

    # Build with different_identity's IID in payload but sign with identity
    protected = _build_protected_header()
    unprotected = _build_unprotected_header(kid_iid)
    # Payload claims to be from different_identity
    payload = _build_payload(
        CAP_BIT_EGRESS,
        b"",
        0,
        1735689600,
        1,
        payload_iid,  # Mismatched!
    )

    sig_structure = _build_sig_structure(protected, payload)
    sig_structure_hash = hashlib.sha256(sig_structure).digest()
    signature = sign(identity, sig_structure_hash)
    cose_sign1 = _build_cose_sign1(protected, unprotected, payload, signature)

    return {
        "name": "capability_iid_mismatch",
        "description": "Announcer IID in payload differs from kid in header (MUST fail).",
        "coverage": "capability_announcement_validation",
        "signing_seed": SEED.hex(),
        "public_key": identity.pubkey.hex(),
        "kid_iid": kid_iid.hex(),
        "payload_iid": payload_iid.hex(),
        "protected_header": protected.hex(),
        "payload_cbor": payload.hex(),
        "sig_structure": sig_structure.hex(),
        "sig_structure_hash": sig_structure_hash.hex(),
        "signature": signature.hex(),
        "cose_sign1": cose_sign1.hex(),
        "expected": {
            "signature_valid": True,
            "iid_match": False,
            "overall_valid": False,
        },
    }


def document() -> dict[str, object]:
    """Return the complete vector document."""
    return {
        "$schema": "./schema.json",
        "vector_type": "capability_announcements",
        "format_version": FORMAT_VERSION,
        "description": (
            "COSE_Sign1 Capability Announcement vectors per spec/06-security.md "
            "Section 8.12. Uses Schnorr48-Ed25519 (alg -65537) with RFC 9052 "
            "Sig_structure and integer-keyed payloads."
        ),
        "oracle": {
            "basis": "LICHEN spec/06-security.md Section 8.12",
            "sig_structure": (
                '["Signature1", protected, h"", payload] per RFC 9052'
            ),
            "signature_input": "SHA256(CBOR(Sig_structure))",
            "generator_command": (
                "python3 test/vectors/generate_capability_announcements.py"
            ),
            "cross_check": "independent PyNaCl-backed reference_schnorr48.py",
            "announcer_iid": (
                "low 8 bytes of upstream yggdrasil-go AddrForKey(pubkey); "
                "generator reimplementation anchored at runtime to the pinned "
                "upstream_addr_for_key vector in yggdrasil_address.json"
            ),
        },
        "constants": {
            "algorithm": {
                "id": ALG_SCHNORR48,
                "name": "Schnorr48-Ed25519",
                "signature_length": 48,
            },
            "capability_bits": {
                "0": "egress",
                "1": "prefix_delegation",
                "2-7": "reserved (MUST be zero)",
            },
            "payload_keys": {
                "1": "capabilities",
                "2": "prefix",
                "3": "prefix_len",
                "4": "expiry",
                "5": "seq",
                "6": "announcer_iid",
            },
        },
        "vectors": [
            _vector(
                "capability_egress_only",
                "Node announces egress capability with no prefix delegation.",
                capabilities=CAP_BIT_EGRESS,
                prefix=b"",
                prefix_len=0,
                expiry=1735689600,  # 2025-01-01 00:00:00 UTC
                seq=1,
            ),
            _vector(
                "capability_prefix_delegation",
                "Node announces prefix delegation capability.",
                capabilities=CAP_BIT_PREFIX_DELEGATION,
                prefix=bytes.fromhex("fd000000000000000000000000000000"),
                prefix_len=64,
                expiry=1735689600,
                seq=1,
            ),
            _vector(
                "capability_both",
                "Node announces both egress and prefix delegation.",
                capabilities=CAP_BIT_EGRESS | CAP_BIT_PREFIX_DELEGATION,
                prefix=bytes.fromhex("fd000000000000000000000000000000"),
                prefix_len=48,
                expiry=1735689600,
                seq=1,
            ),
            _vector(
                "capability_no_caps",
                "Node announces zero capabilities (revocation/withdrawal).",
                capabilities=0,
                prefix=b"",
                prefix_len=0,
                expiry=1735689600,
                seq=1,
            ),
            _vector(
                "capability_seq_max",
                "Maximum 32-bit sequence number.",
                capabilities=CAP_BIT_EGRESS,
                prefix=b"",
                prefix_len=0,
                expiry=1735689600,
                seq=0xFFFFFFFF,
            ),
            _vector(
                "capability_prefix_128",
                "Full /128 prefix (single host).",
                capabilities=CAP_BIT_PREFIX_DELEGATION,
                prefix=bytes.fromhex("fd001234567890abcdef1234567890ab"),
                prefix_len=128,
                expiry=1735689600,
                seq=1,
            ),
            _vector(
                "capability_expiry_far_future",
                "Far future expiry timestamp.",
                capabilities=CAP_BIT_EGRESS,
                prefix=b"",
                prefix_len=0,
                expiry=4102444800,  # 2100-01-01 00:00:00 UTC
                seq=1,
            ),
            _invalid_reserved_bits_vector(),
            _different_signer_vector(),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    generated = document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except FileNotFoundError:
            current = None
        except (OSError, RuntimeError) as error:
            # Unsafe directory / unreadable vector: report the real
            # problem instead of masquerading as a stale file.
            print(f"cannot safely read {OUTPUT.name}: {error}", file=sys.stderr)
            return 2
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    vectors = generated["vectors"]
    assert isinstance(vectors, list)
    print(f"Wrote {len(vectors)} vectors in {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
