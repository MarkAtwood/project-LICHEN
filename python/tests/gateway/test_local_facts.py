# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Tests for the local-fact credential model (spec 8.13.1)."""

from __future__ import annotations

from hashlib import sha256

import cbor2
import pytest

from lichen.crypto import schnorr48
from lichen.crypto.delegation_tokens import SCHNORR48_ED25519_ALG
from lichen.crypto.identity import Identity
from lichen.gateway.local_facts import (
    CLAIM_EMERGENCY,
    CLAIM_PRIORITY,
    LocalFact,
    LocalFactClaims,
    LocalFactError,
    issue_local_fact,
    verify_local_fact,
)


def _gateway() -> Identity:
    return Identity.from_seed(bytes(range(32)))


def _other() -> Identity:
    return Identity.from_seed(bytes([0xFF - i for i in range(32)]))


# ─── Claims validation ────────────────────────────────────────────────────────


def test_claims_roundtrip_all_fields() -> None:
    claims = LocalFactClaims(
        emergency=True,
        emergency_callback="+12065550191",
        relay=True,
        priority=3,
        channel=("ops", "team"),
        quota=1024,
        sponsored="Traffic sponsored by Example Corp",
    )
    decoded = LocalFactClaims.from_cbor(claims.to_cbor())
    assert decoded == claims


def test_claims_roundtrip_subset() -> None:
    claims = LocalFactClaims(relay=True)
    decoded = LocalFactClaims.from_cbor(claims.to_cbor())
    assert decoded.relay is True
    assert decoded.emergency is None
    assert decoded.priority is None
    assert decoded.channel is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"emergency": 1},  # bool claim given int
        {"relay": "yes"},  # bool claim given str
        {"priority": -1},  # below range
        {"priority": 4},  # above range (max 3)
        {"priority": True},  # bool is not a valid uint here
        {"quota": -5},  # negative
        {"channel": ["ok", 7]},  # non-tstr element
        {"channel": "ops"},  # bare str, not a sequence of tstr
        {"channel": 5},  # non-iterable
        {"emergency_callback": 123},  # tstr given int
    ],
)
def test_invalid_claim_values_rejected(kwargs: dict) -> None:
    with pytest.raises(LocalFactError):
        LocalFactClaims(**kwargs)


def test_unknown_claim_rejected_at_decode() -> None:
    body = cbor2.dumps({"lichen:unknown_future_claim": True})
    with pytest.raises(LocalFactError, match="unknown local-fact claim"):
        LocalFactClaims.from_cbor(body)


def test_bool_claim_rejects_int_on_decode() -> None:
    # CBOR true/false are bools; a uint 1 for a bool claim must not coerce.
    body = cbor2.dumps({CLAIM_EMERGENCY: 1})
    with pytest.raises(LocalFactError, match="must be a bool"):
        LocalFactClaims.from_cbor(body)


def test_priority_rejects_bool_on_decode() -> None:
    body = cbor2.dumps({CLAIM_PRIORITY: True})
    with pytest.raises(LocalFactError, match="must be a uint"):
        LocalFactClaims.from_cbor(body)


# ─── Issuance and verification ────────────────────────────────────────────────


def test_issue_and_verify_roundtrip() -> None:
    gw = _gateway()
    claims = LocalFactClaims(emergency=True, relay=True, priority=3)
    fact = issue_local_fact(gw, claims)
    assert fact.issuer_iid == gw.iid
    assert len(fact.signature) == 48
    assert verify_local_fact(fact, gw.pubkey) is True


def test_cose_envelope_roundtrip() -> None:
    gw = _gateway()
    claims = LocalFactClaims(relay=True, channel=("ops",), quota=0)
    fact = issue_local_fact(gw, claims)
    decoded = LocalFact.from_cose_sign1(fact.to_cose_sign1())
    assert decoded.claims == claims
    assert decoded.issuer_iid == gw.iid
    assert verify_local_fact(decoded, gw.pubkey) is True


def test_verify_rejects_wrong_key() -> None:
    fact = issue_local_fact(_gateway(), LocalFactClaims(relay=True))
    assert verify_local_fact(fact, _other().pubkey) is False


def test_verify_rejects_tampered_claims() -> None:
    gw = _gateway()
    fact = issue_local_fact(gw, LocalFactClaims(relay=True, priority=0))
    # Re-issue claims with elevated priority but keep the original signature.
    tampered = LocalFact(
        claims=LocalFactClaims(relay=True, priority=3),
        issuer_iid=fact.issuer_iid,
        signature=fact.signature,
    )
    assert verify_local_fact(tampered, gw.pubkey) is False


def test_replace_on_decoded_fact_desync_rejected() -> None:
    """dataclasses.replace(fact, claims=...) on a decoded fact keeps the old
    wire bstrs; the resulting desync must be rejected at construction, or
    verify would pass over the OLD signed payload while .claims carries
    unverified attacker-relevant fields (2vp1)."""
    import dataclasses

    gw = _gateway()
    fact = LocalFact.from_cose_sign1(
        issue_local_fact(gw, LocalFactClaims(relay=True, priority=0)).to_cose_sign1()
    )
    # The decoded fact retains wire bstrs; replace() keeps them while swapping
    # claims to an elevated grant. Construction must now fail closed.
    with pytest.raises(LocalFactError, match="do not match the retained payload_bytes"):
        dataclasses.replace(fact, claims=LocalFactClaims(relay=True, priority=3))


def test_construct_with_matching_wire_bstrs_accepted() -> None:
    """The desync guard must not reject a fact whose wire bstrs genuinely
    agree with claims (from_cose_sign1 / issue_local_fact normal path)."""
    gw = _gateway()
    fact = issue_local_fact(gw, LocalFactClaims(relay=True, priority=1))
    decoded = LocalFact.from_cose_sign1(fact.to_cose_sign1())
    assert verify_local_fact(decoded, gw.pubkey) is True
    # Rebuilding with the same claims + retained bstrs (encoding-agnostic
    # equality) is also accepted.
    rebuilt = LocalFact(
        claims=decoded.claims,
        issuer_iid=decoded.issuer_iid,
        signature=decoded.signature,
        protected_bytes=decoded.protected_bytes,
        payload_bytes=decoded.payload_bytes,
    )
    assert verify_local_fact(rebuilt, gw.pubkey) is True


def test_issue_with_list_channel_accepted() -> None:
    """channel given as a list (most natural literal) must not trip the
    wire-bstr agreement guard on the issuance path (review finding 1)."""
    gw = _gateway()
    fact = issue_local_fact(gw, LocalFactClaims(channel=["ops", "team"]))
    decoded = LocalFact.from_cose_sign1(fact.to_cose_sign1())
    assert verify_local_fact(decoded, gw.pubkey) is True
    assert decoded.claims.channel == ("ops", "team")


def test_direct_construction_non_bytes_payload_bstr_raises_local_fact_error() -> None:
    """A non-bytes wire bstr in direct construction must fail with
    LocalFactError (module contract), not leak a TypeError (review finding 2)."""
    with pytest.raises(LocalFactError, match="wire bstrs must be bytes"):
        LocalFact(
            claims=LocalFactClaims(relay=True),
            issuer_iid=b"\x01" * 8,
            signature=b"\x00" * 48,
            protected_bytes=b"p",
            payload_bytes="not-bytes",  # type: ignore[arg-type]
        )


# ─── Envelope decode robustness ───────────────────────────────────────────────


def test_from_cose_rejects_wrong_alg() -> None:
    gw = _gateway()
    fact = issue_local_fact(gw, LocalFactClaims(relay=True))
    elements = cbor2.loads(fact.to_cose_sign1())
    elements[0] = cbor2.dumps({1: -7})  # ES256, not Schnorr48
    with pytest.raises(LocalFactError, match="alg must be"):
        LocalFact.from_cose_sign1(cbor2.dumps(elements))


def test_from_cose_rejects_short_signature() -> None:
    gw = _gateway()
    fact = issue_local_fact(gw, LocalFactClaims(relay=True))
    elements = cbor2.loads(fact.to_cose_sign1())
    elements[3] = elements[3][:47]
    with pytest.raises(LocalFactError, match="48 bytes"):
        LocalFact.from_cose_sign1(cbor2.dumps(elements))


def test_from_cose_rejects_bad_kid() -> None:
    gw = _gateway()
    fact = issue_local_fact(gw, LocalFactClaims(relay=True))
    elements = cbor2.loads(fact.to_cose_sign1())
    elements[1] = {4: b"\x00" * 7}  # 7-byte kid
    with pytest.raises(LocalFactError, match="8-byte gateway IID"):
        LocalFact.from_cose_sign1(cbor2.dumps(elements))


@pytest.mark.parametrize("index", [0, 2])  # protected, payload
def test_from_cose_rejects_non_bstr_elements(index: int) -> None:
    # A non-bytes protected header or payload fed to cbor2.loads must surface
    # as LocalFactError, not an uncaught TypeError.
    gw = _gateway()
    fact = issue_local_fact(gw, LocalFactClaims(relay=True))
    elements = cbor2.loads(fact.to_cose_sign1())
    elements[index] = 5  # int where a bstr belongs
    with pytest.raises(LocalFactError, match="must be bstr"):
        LocalFact.from_cose_sign1(cbor2.dumps(elements))


def test_from_cose_rejects_trailing_bytes() -> None:
    # cbor2.loads ignores trailing bytes; the strict decoder must not.
    gw = _gateway()
    fact = issue_local_fact(gw, LocalFactClaims(relay=True))
    with pytest.raises(LocalFactError, match="trailing bytes"):
        LocalFact.from_cose_sign1(fact.to_cose_sign1() + b"\x00")


def test_from_cbor_rejects_trailing_bytes() -> None:
    body = LocalFactClaims(relay=True).to_cbor() + b"\x00"
    with pytest.raises(LocalFactError, match="trailing bytes"):
        LocalFactClaims.from_cbor(body)


def test_signature_error_contract_for_non_bytes() -> None:
    # A non-bytes signature must raise LocalFactError, not TypeError (len()).
    with pytest.raises(LocalFactError, match="signature must be bytes"):
        LocalFact(claims=LocalFactClaims(relay=True), issuer_iid=b"\x00" * 8, signature=None)


def test_unpaired_wire_bytes_rejected() -> None:
    fact = issue_local_fact(_gateway(), LocalFactClaims(relay=True))
    with pytest.raises(LocalFactError, match="retained as a pair"):
        LocalFact(
            claims=fact.claims,
            issuer_iid=fact.issuer_iid,
            signature=fact.signature,
            protected_bytes=fact.protected_bytes,
            payload_bytes=None,
        )


# ─── Wire-bytes verification (RFC 9052 4.4, C/Rust interop) ──────────────────


def _foreign_encoded_fact(gw: Identity) -> tuple[bytes, bytes, bytes]:
    """Build a COSE_Sign1 envelope as a non-Python encoder might: claims map
    in an order this module never emits, plus an extra protected-header entry.
    Signed over the transported bstrs with schnorr48 directly (independent of
    the module's own encoding helpers). Returns (envelope, protected, payload).
    """
    payload = cbor2.dumps({"lichen:quota": 7, "lichen:priority": 2, "lichen:relay": True})
    protected = cbor2.dumps({1: SCHNORR48_ED25519_ALG, 99: b"extra"})
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = schnorr48.sign(gw.privkey, gw.pubkey, sha256(sig_structure).digest())
    envelope = cbor2.dumps([protected, {4: gw.iid}, payload, signature])
    return envelope, protected, payload


def test_verify_over_received_wire_bytes() -> None:
    gw = _gateway()
    envelope, protected, payload = _foreign_encoded_fact(gw)
    # Guard the differential: this module's own encoding really would differ,
    # so re-encode verification (the old behavior) could never pass here.
    assert payload != LocalFactClaims(relay=True, priority=2, quota=7).to_cbor()
    fact = LocalFact.from_cose_sign1(envelope)
    assert fact.claims == LocalFactClaims(relay=True, priority=2, quota=7)
    assert fact.protected_bytes == protected
    assert fact.payload_bytes == payload
    assert verify_local_fact(fact, gw.pubkey) is True


def test_decoded_fact_reserializes_byte_stably() -> None:
    # A fact forwarded or stored after decode must keep its signed bstrs:
    # re-encoding would silently invalidate it for the next verifier.
    gw = _gateway()
    envelope, protected, payload = _foreign_encoded_fact(gw)
    fact = LocalFact.from_cose_sign1(envelope)
    reencoded = cbor2.loads(fact.to_cose_sign1())
    assert reencoded[0] == protected
    assert reencoded[2] == payload
    relayed = LocalFact.from_cose_sign1(fact.to_cose_sign1())
    assert verify_local_fact(relayed, gw.pubkey) is True
