# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Trust-anchor store + /.well-known/trust-anchors resource tests (viku.2).

X.509 fixtures are generated with pyca/cryptography (the vetted oracle);
expected Ed25519 keys are known independently of the parsing code under
test.
"""

from __future__ import annotations

import datetime

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from lichen.coap.resources.trust_anchors import TrustAnchorsResource
from lichen.crypto.identity import _pubkey_to_iid
from lichen.crypto.trust_anchors import (
    KIND_RAW_ED25519,
    KIND_X509,
    MAX_ANCHORS,
    MAX_CERT_DER_BYTES,
    MAX_CERTS_PER_ANCHOR,
    MAX_METADATA_ENTRIES,
    DuplicateAnchorError,
    ProvisionedAnchorError,
    StoreFullError,
    TrustAnchor,
    TrustAnchorStore,
    UnknownAnchorError,
    pubkey_from_der_cert,
)


def _raw_pubkey(seed: int) -> bytes:
    return bytes([seed]) * 32


def _ca_cert_der(subject_key: Ed25519PrivateKey, issuer_key: Ed25519PrivateKey, name: str) -> bytes:
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"issuer-{name}")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, algorithm=None)
    )
    return cert.public_bytes(Encoding.DER)


def _non_ca_cert_der(key: Ed25519PrivateKey) -> bytes:
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, algorithm=None)
    )
    return cert.public_bytes(Encoding.DER)


def _ed_key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _raw_of(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# ─── Store-level ─────────────────────────────────────────────────────────────


def test_raw_anchor_add_get_remove() -> None:
    store = TrustAnchorStore()
    anchor = TrustAnchor(pubkey=_raw_pubkey(0x01))
    store.add(anchor)
    iid = _pubkey_to_iid(_raw_pubkey(0x01))
    assert store.get(iid) == anchor
    assert store.issuer_pubkey(iid) == _raw_pubkey(0x01)
    assert iid in store
    assert len(store) == 1
    removed = store.remove(iid)
    assert removed == anchor
    assert len(store) == 0
    assert store.issuer_pubkey(iid) is None


def test_duplicate_anchor_rejected() -> None:
    store = TrustAnchorStore()
    store.add(TrustAnchor(pubkey=_raw_pubkey(0x02)))
    with pytest.raises(DuplicateAnchorError):
        store.add(TrustAnchor(pubkey=_raw_pubkey(0x02)))


def test_provisioned_anchor_not_removable() -> None:
    provisioned = TrustAnchor(pubkey=_raw_pubkey(0x03), provisioned=True)
    store = TrustAnchorStore(provisioned=(provisioned,))
    with pytest.raises(ProvisionedAnchorError):
        store.remove(provisioned.issuer_iid)
    assert provisioned.issuer_iid in store


def test_provisioned_constructor_requires_flag() -> None:
    with pytest.raises(ValueError, match="provisioned=True"):
        TrustAnchorStore(provisioned=(TrustAnchor(pubkey=_raw_pubkey(0x04)),))


def test_runtime_add_refuses_provisioned_anchor() -> None:
    store = TrustAnchorStore()
    with pytest.raises(ValueError, match="refuses provisioned"):
        store.add(TrustAnchor(pubkey=_raw_pubkey(0x05), provisioned=True))


def test_anchor_is_explicitly_unhashable() -> None:
    with pytest.raises(TypeError):
        hash(TrustAnchor(pubkey=_raw_pubkey(0x06)))


def test_provisioned_anchor_may_gain_cross_signed_cert() -> None:
    ca_key = _ed_key(0x19)
    der_self = _ca_cert_der(ca_key, ca_key, "root-p")
    der_cross = _ca_cert_der(ca_key, _ed_key(0x1A), "root-p-cross")
    provisioned = TrustAnchor(
        pubkey=_raw_of(ca_key), kind=KIND_X509, certs=(der_self,), provisioned=True
    )
    store = TrustAnchorStore(provisioned=(provisioned,))
    updated = store.add_cross_signed_cert(provisioned.issuer_iid, der_cross)
    assert updated.certs == (der_self, der_cross)
    assert updated.provisioned is True
    # The trusted key set is unchanged: still the same single IID.
    assert len(store) == 1
    assert store.issuer_pubkey(provisioned.issuer_iid) == _raw_of(ca_key)


def test_certs_per_anchor_bounded() -> None:
    ca_key = _ed_key(0x1B)
    ders = [
        _ca_cert_der(ca_key, _ed_key(0x40 + i), f"root-q-{i}") for i in range(MAX_CERTS_PER_ANCHOR)
    ]
    store = TrustAnchorStore()
    store.add(TrustAnchor(pubkey=_raw_of(ca_key), kind=KIND_X509, certs=(ders[0],)))
    iid = _pubkey_to_iid(_raw_of(ca_key))
    for der in ders[1:]:
        store.add_cross_signed_cert(iid, der)
    overflow = _ca_cert_der(ca_key, _ed_key(0x7F), "root-q-overflow")
    with pytest.raises(ValueError, match="at most"):
        store.add_cross_signed_cert(iid, overflow)


def test_anchor_store_bounded() -> None:
    store = TrustAnchorStore()
    for i in range(MAX_ANCHORS):
        store.add(TrustAnchor(pubkey=_raw_pubkey(i % 256)[:30] + i.to_bytes(2, "big")))
    with pytest.raises(StoreFullError):
        store.add(TrustAnchor(pubkey=_raw_pubkey(0xFE)))


def test_cert_der_byte_bound() -> None:
    with pytest.raises(ValueError, match="bytes"):
        pubkey_from_der_cert(b"\x30" * (MAX_CERT_DER_BYTES + 1))
    with pytest.raises(ValueError, match="bytes"):
        pubkey_from_der_cert(b"")


def test_raw_anchor_kind_flips_to_x509_on_cross_signed_cert() -> None:
    ca_key = _ed_key(0x1C)
    der = _ca_cert_der(ca_key, ca_key, "root-r")
    store = TrustAnchorStore()
    store.add(TrustAnchor(pubkey=_raw_of(ca_key)))
    iid = _pubkey_to_iid(_raw_of(ca_key))
    updated = store.add_cross_signed_cert(iid, der)
    assert updated.kind == KIND_X509
    assert updated.certs == (der,)
    assert updated.pubkey == _raw_of(ca_key)


def test_metadata_bounded() -> None:
    with pytest.raises(ValueError, match="metadata entries"):
        TrustAnchor(
            pubkey=_raw_pubkey(0x50),
            metadata={f"k{i}": "v" for i in range(MAX_METADATA_ENTRIES + 1)},
        )
    with pytest.raises(ValueError, match="metadata exceeds"):
        TrustAnchor(pubkey=_raw_pubkey(0x51), metadata={"k": "v" * 300})


def test_remove_unknown_anchor() -> None:
    with pytest.raises(UnknownAnchorError):
        TrustAnchorStore().remove(b"\x00" * 8)


def test_x509_anchor_pubkey_extracted_from_cert() -> None:
    ca_key = _ed_key(0x11)
    der = _ca_cert_der(ca_key, ca_key, "root-a")
    anchor = TrustAnchor(pubkey=_raw_of(ca_key), kind=KIND_X509, certs=(der,))
    assert anchor.pubkey == _raw_of(ca_key)
    assert pubkey_from_der_cert(der) == _raw_of(ca_key)


def test_x509_anchor_rejects_key_mismatch() -> None:
    ca_key = _ed_key(0x12)
    der = _ca_cert_der(ca_key, ca_key, "root-b")
    with pytest.raises(ValueError, match="does not match"):
        TrustAnchor(pubkey=_raw_pubkey(0x99), kind=KIND_X509, certs=(der,))


def test_non_ca_cert_rejected() -> None:
    key = _ed_key(0x13)
    with pytest.raises(ValueError, match="not a CA"):
        pubkey_from_der_cert(_non_ca_cert_der(key))


def test_garbage_der_rejected() -> None:
    with pytest.raises(ValueError, match="does not parse"):
        pubkey_from_der_cert(b"\x30\x03\x01\x01\xff")


def test_cross_signed_cert_attaches_to_same_key_anchor() -> None:
    ca_key = _ed_key(0x14)
    other_root = _ed_key(0x15)
    der_self = _ca_cert_der(ca_key, ca_key, "root-c")
    der_cross = _ca_cert_der(ca_key, other_root, "root-c-cross")
    store = TrustAnchorStore()
    store.add(TrustAnchor(pubkey=_raw_of(ca_key), kind=KIND_X509, certs=(der_self,)))
    iid = _pubkey_to_iid(_raw_of(ca_key))
    updated = store.add_cross_signed_cert(iid, der_cross)
    assert updated.certs == (der_self, der_cross)
    assert store.get(iid).certs == (der_self, der_cross)


def test_cross_signed_cert_rejects_different_key() -> None:
    ca_key = _ed_key(0x16)
    other_key = _ed_key(0x17)
    der = _ca_cert_der(ca_key, ca_key, "root-d")
    der_other = _ca_cert_der(other_key, other_key, "root-e")
    store = TrustAnchorStore()
    store.add(TrustAnchor(pubkey=_raw_of(ca_key), kind=KIND_X509, certs=(der,)))
    with pytest.raises(ValueError, match="does not match"):
        store.add_cross_signed_cert(_pubkey_to_iid(_raw_of(ca_key)), der_other)


def test_cross_signed_unknown_anchor() -> None:
    der = _ca_cert_der(_ed_key(0x18), _ed_key(0x18), "root-f")
    with pytest.raises(UnknownAnchorError):
        TrustAnchorStore().add_cross_signed_cert(b"\x01" * 8, der)


def test_anchor_validation_rejects_bad_shapes() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        TrustAnchor(pubkey=b"\x01" * 31)
    with pytest.raises(ValueError, match="kind"):
        TrustAnchor(pubkey=_raw_pubkey(0x20), kind="derp")
    with pytest.raises(ValueError, match="requires at least one cert"):
        TrustAnchor(pubkey=_raw_pubkey(0x21), kind=KIND_X509)
    with pytest.raises(ValueError, match="must not carry certs"):
        TrustAnchor(pubkey=_raw_pubkey(0x22), certs=(b"\x30",))
    with pytest.raises(TypeError):
        TrustAnchor(pubkey=_raw_pubkey(0x23), metadata={1: "x"})  # type: ignore[dict-item]


# ─── Resource-level ──────────────────────────────────────────────────────────


class _FakeSecurityContext:
    recipient_id = b"admin-ctx"

    def durable_context_id(self):
        return b"admin-ctx"


class _FakeRemote:
    security_context = _FakeSecurityContext()


def _request(payload: bytes | None, authenticated: bool = True) -> Message:
    msg = Message(payload=payload or b"")
    if authenticated:
        msg.remote = _FakeRemote()  # type: ignore[attr-defined]
    return msg


def _resource(
    store: TrustAnchorStore | None = None, authorized: bool = True
) -> TrustAnchorsResource:
    return TrustAnchorsResource(
        store if store is not None else TrustAnchorStore(),
        authorize=(lambda _ctx: authorized),
    )


async def test_get_empty_store_returns_empty_array() -> None:
    response = await _resource().render_get(_request(None, authenticated=False))
    assert response.code == aiocoap.CONTENT
    assert cbor2.loads(response.payload) == []


async def test_get_lists_anchors() -> None:
    store = TrustAnchorStore()
    store.add(TrustAnchor(pubkey=_raw_pubkey(0x30), metadata={"name": "root"}))
    response = await _resource(store).render_get(_request(None, authenticated=False))
    assert response.code == aiocoap.CONTENT
    (entry,) = cbor2.loads(response.payload)
    assert entry["id"] == _pubkey_to_iid(_raw_pubkey(0x30))
    assert entry["kind"] == KIND_RAW_ED25519
    assert entry["pubkey"] == _raw_pubkey(0x30)
    assert entry["provisioned"] is False
    assert entry["metadata"] == {"name": "root"}


async def test_post_raw_anchor_authorized() -> None:
    store = TrustAnchorStore()
    body = cbor2.dumps({"kind": KIND_RAW_ED25519, "pubkey": _raw_pubkey(0x31)})
    response = await _resource(store).render_post(_request(body))
    assert response.code == aiocoap.CREATED
    assert cbor2.loads(response.payload)["id"] == _pubkey_to_iid(_raw_pubkey(0x31))
    assert len(store) == 1


async def test_post_unauthenticated_rejected() -> None:
    body = cbor2.dumps({"kind": KIND_RAW_ED25519, "pubkey": _raw_pubkey(0x32)})
    response = await _resource().render_post(_request(body, authenticated=False))
    assert response.code == aiocoap.FORBIDDEN


async def test_post_unauthorized_identity_rejected() -> None:
    body = cbor2.dumps({"kind": KIND_RAW_ED25519, "pubkey": _raw_pubkey(0x33)})
    response = await _resource(authorized=False).render_post(_request(body))
    assert response.code == aiocoap.FORBIDDEN


async def test_post_no_authorize_callback_fails_closed() -> None:
    resource = TrustAnchorsResource(TrustAnchorStore(), authorize=None)
    body = cbor2.dumps({"kind": KIND_RAW_ED25519, "pubkey": _raw_pubkey(0x34)})
    response = await resource.render_post(_request(body))
    assert response.code == aiocoap.FORBIDDEN


async def test_post_malformed_cbor_rejected() -> None:
    response = await _resource().render_post(_request(b"\xff"))
    assert response.code == aiocoap.BAD_REQUEST


async def test_post_unknown_fields_rejected() -> None:
    body = cbor2.dumps({"kind": KIND_RAW_ED25519, "pubkey": _raw_pubkey(0x35), "x": 1})
    response = await _resource().render_post(_request(body))
    assert response.code == aiocoap.BAD_REQUEST


async def test_post_id_field_on_create_rejected() -> None:
    body = cbor2.dumps({"kind": KIND_RAW_ED25519, "pubkey": _raw_pubkey(0x52), "id": b"\x01" * 8})
    response = await _resource().render_post(_request(body))
    assert response.code == aiocoap.BAD_REQUEST


async def test_post_cross_signed_with_stray_fields_rejected() -> None:
    der = _ca_cert_der(_ed_key(0x53), _ed_key(0x53), "root-s")
    body = cbor2.dumps(
        {
            "cross_signed": True,
            "id": b"\x02" * 8,
            "certs": [der],
            "kind": KIND_X509,
        }
    )
    response = await _resource().render_post(_request(body))
    assert response.code == aiocoap.BAD_REQUEST


async def test_post_raw_anchor_wrong_type_certs_rejected() -> None:
    body = cbor2.dumps({"kind": KIND_RAW_ED25519, "pubkey": _raw_pubkey(0x54), "certs": b""})
    response = await _resource().render_post(_request(body))
    assert response.code == aiocoap.BAD_REQUEST


async def test_post_duplicate_conflict() -> None:
    store = TrustAnchorStore()
    store.add(TrustAnchor(pubkey=_raw_pubkey(0x36)))
    body = cbor2.dumps({"kind": KIND_RAW_ED25519, "pubkey": _raw_pubkey(0x36)})
    response = await _resource(store).render_post(_request(body))
    assert response.code == aiocoap.CONFLICT


async def test_post_x509_anchor() -> None:
    ca_key = _ed_key(0x37)
    der = _ca_cert_der(ca_key, ca_key, "root-g")
    store = TrustAnchorStore()
    body = cbor2.dumps({"kind": KIND_X509, "certs": [der]})
    response = await _resource(store).render_post(_request(body))
    assert response.code == aiocoap.CREATED
    assert cbor2.loads(response.payload)["id"] == _pubkey_to_iid(_raw_of(ca_key))
    assert store.issuer_pubkey(_pubkey_to_iid(_raw_of(ca_key))) == _raw_of(ca_key)


async def test_post_x509_matching_explicit_pubkey_accepted() -> None:
    ca_key = _ed_key(0x3B)
    der = _ca_cert_der(ca_key, ca_key, "root-j")
    store = TrustAnchorStore()
    body = cbor2.dumps({"kind": KIND_X509, "certs": [der], "pubkey": _raw_of(ca_key)})
    response = await _resource(store).render_post(_request(body))
    assert response.code == aiocoap.CREATED


async def test_post_x509_mismatched_explicit_pubkey_rejected() -> None:
    ca_key = _ed_key(0x3C)
    der = _ca_cert_der(ca_key, ca_key, "root-k")
    store = TrustAnchorStore()
    body = cbor2.dumps({"kind": KIND_X509, "certs": [der], "pubkey": _raw_pubkey(0x3D)})
    response = await _resource(store).render_post(_request(body))
    assert response.code == aiocoap.BAD_REQUEST
    assert len(store) == 0


async def test_post_cross_signed_cert() -> None:
    ca_key = _ed_key(0x38)
    der_self = _ca_cert_der(ca_key, ca_key, "root-h")
    der_cross = _ca_cert_der(ca_key, _ed_key(0x39), "root-h-cross")
    store = TrustAnchorStore()
    store.add(TrustAnchor(pubkey=_raw_of(ca_key), kind=KIND_X509, certs=(der_self,)))
    iid = _pubkey_to_iid(_raw_of(ca_key))
    body = cbor2.dumps({"cross_signed": True, "id": iid, "certs": [der_cross]})
    response = await _resource(store).render_post(_request(body))
    assert response.code == aiocoap.CHANGED
    assert store.get(iid).certs == (der_self, der_cross)


async def test_post_cross_signed_unknown_anchor() -> None:
    der = _ca_cert_der(_ed_key(0x3A), _ed_key(0x3A), "root-i")
    body = cbor2.dumps({"cross_signed": True, "id": b"\x07" * 8, "certs": [der]})
    response = await _resource().render_post(_request(body))
    assert response.code == aiocoap.NOT_FOUND


async def test_delete_runtime_anchor() -> None:
    store = TrustAnchorStore()
    anchor = TrustAnchor(pubkey=_raw_pubkey(0x40))
    store.add(anchor)
    body = cbor2.dumps({"id": anchor.issuer_iid})
    response = await _resource(store).render_delete(_request(body))
    assert response.code == aiocoap.DELETED
    assert len(store) == 0


async def test_delete_provisioned_anchor_forbidden() -> None:
    provisioned = TrustAnchor(pubkey=_raw_pubkey(0x41), provisioned=True)
    store = TrustAnchorStore(provisioned=(provisioned,))
    body = cbor2.dumps({"id": provisioned.issuer_iid})
    response = await _resource(store).render_delete(_request(body))
    assert response.code == aiocoap.FORBIDDEN
    assert len(store) == 1


async def test_delete_unknown_anchor() -> None:
    body = cbor2.dumps({"id": b"\x09" * 8})
    response = await _resource().render_delete(_request(body))
    assert response.code == aiocoap.NOT_FOUND


async def test_delete_unauthenticated_rejected() -> None:
    body = cbor2.dumps({"id": b"\x0a" * 8})
    response = await _resource().render_delete(_request(body, authenticated=False))
    assert response.code == aiocoap.FORBIDDEN
