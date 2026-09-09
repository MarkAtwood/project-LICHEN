# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Tests for the local-fact credential model (spec 8.13.1)."""

from __future__ import annotations

import cbor2
import pytest

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
