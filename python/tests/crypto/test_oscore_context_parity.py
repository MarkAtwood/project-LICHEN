# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Derived OSCORE context parity: EDHOC export -> RFC 8613 context.

The Python oracle is the source of truth for
test/vectors/oscore_context_parity.json (regenerate via
test/vectors/generate_oscore_context_parity.py). These tests guard the
oracle against drift: a live deterministic EDHOC handshake must reproduce
the committed master material, the derived RFC 8613 keys, and the protected
request byte-for-byte. The consuming Rust assertions live in
rust/lichen-oscore/tests/context_parity.rs.
"""

from __future__ import annotations

import cbor2
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

from lichen.crypto.edhoc import EdhocInitiator, EdhocResponder
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext

REPO_ROOT = Path(__file__).parents[3]
with open(REPO_ROOT / "test" / "vectors" / "oscore_context_parity.json") as f:
    FIXTURE: dict[str, Any] = json.load(f)
with open(REPO_ROOT / "test" / "vectors" / "edhoc.json") as f:
    EDHOC_VECTORS: dict[str, Any] = json.load(f)

SOURCE_VECTOR = FIXTURE["source_vector"].split("#")[1]
EDHOC_VECTOR = next(
    v for v in EDHOC_VECTORS["vectors"] if v["name"] == SOURCE_VECTOR
)


def _run_handshake() -> tuple[Any, Any]:
    """Run the fixture's EDHOC handshake, returning (initiator, responder) exports."""
    seeds = FIXTURE["determinism"]
    identity_i = Identity.from_seed(bytes.fromhex(seeds["seed_i"]))
    identity_r = Identity.from_seed(bytes.fromhex(seeds["seed_r"]))

    def fake_urandom(n: int) -> bytes:
        return bytes([int(seeds["rng_fill_byte"], 16)]) * n

    with patch.object(os, "urandom", fake_urandom):
        initiator = EdhocInitiator.create(identity_i, c_i=bytes.fromhex(seeds["c_i"]))
        responder = EdhocResponder.create(identity_r, c_r=bytes.fromhex(seeds["c_r"]))
        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, identity_i.pubkey)
        msg3 = initiator.process_message_2(msg2, identity_r.pubkey)
        responder.process_message_3(msg3, identity_i.pubkey)
        ctx_i = initiator.export_oscore()
        ctx_r = responder.export_oscore()
    return ctx_i, ctx_r


class TestEdhocExportMatchesFixture:
    """Live EDHOC handshake reproduces the committed master material."""

    def test_initiator_export_matches_fixture(self) -> None:
        ctx_i, _ = _run_handshake()
        expected = FIXTURE["context"]
        assert ctx_i.master_secret.hex() == expected["master_secret"]
        assert ctx_i.master_salt.hex() == expected["master_salt"]
        assert ctx_i.sender_id.hex() == expected["sender_id"]
        assert ctx_i.recipient_id.hex() == expected["recipient_id"]

    def test_export_matches_edhoc_source_vector(self) -> None:
        """Fixture context is pinned to the committed edhoc.json vector."""
        expected = FIXTURE["context"]
        assert expected["master_secret"] == EDHOC_VECTOR["oscore_master_secret"]
        assert expected["master_salt"] == EDHOC_VECTOR["oscore_master_salt"]
        assert expected["sender_id"] == EDHOC_VECTOR["oscore_sender_id"]
        assert expected["recipient_id"] == EDHOC_VECTOR["oscore_recipient_id"]


class TestDerivedContextParity:
    """Both roles derive compatible RFC 8613 contexts from the export."""

    def test_derived_keys_match_fixture(self) -> None:
        ctx_i_export, ctx_r_export = _run_handshake()
        ctx_i = MemorySecurityContext.from_edhoc(ctx_i_export)
        ctx_r = MemorySecurityContext.from_edhoc(ctx_r_export)

        expected = FIXTURE["derived_keys"]
        assert ctx_i.sender_key.hex() == expected["sender_key"]
        assert ctx_i.recipient_key.hex() == expected["recipient_key"]
        assert ctx_i.common_iv.hex() == expected["common_iv"]

        # Responder derives the mirrored context from identical master material.
        params_i = ctx_i.export_parameters()
        params_r = ctx_r.export_parameters()
        assert params_r.master_secret == params_i.master_secret
        assert params_r.master_salt == params_i.master_salt
        assert ctx_r.sender_key == ctx_i.recipient_key
        assert ctx_r.recipient_key == ctx_i.sender_key
        assert ctx_r.common_iv == ctx_i.common_iv
        assert ctx_r.sender_id == ctx_i.recipient_id
        assert ctx_r.recipient_id == ctx_i.sender_id

    def test_protected_request_reproduces_fixture(self) -> None:
        """Oracle re-protects the fixture request byte-for-byte (drift guard)."""
        ctx_i_export, _ = _run_handshake()
        ctx = MemorySecurityContext.from_edhoc(ctx_i_export)

        req = FIXTURE["request_protection"]
        seq: int = req["sequence"]
        piv = seq.to_bytes(5, "big").lstrip(b"\x00") or b"\x00"
        sender_id = ctx.sender_id

        nonce = ctx._construct_nonce(piv, sender_id, ctx.alg_aead)
        assert nonce.hex() == req["expected"]["nonce"]

        plaintext = bytes([req["code"]]) + bytes.fromhex(req["options"])
        payload = bytes.fromhex(req["payload"])
        if payload:
            plaintext += b"\xff" + payload

        ext_aad = cbor2.dumps([1, [10], sender_id, piv, b""])
        enc_structure = cbor2.dumps(["Encrypt0", b"", ext_aad])
        ciphertext = ctx.alg_aead.encrypt(plaintext, enc_structure, ctx.sender_key, nonce)
        assert ciphertext.hex() == req["expected"]["ciphertext"]

        flags = len(piv) | 0x08  # n bits + k bit (KID always present for requests)
        oscore_option = bytes([flags]) + piv + sender_id
        assert oscore_option.hex() == req["expected"]["oscore_option"]
