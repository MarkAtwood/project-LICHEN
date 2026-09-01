# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /.well-known/capability-announce resource tests (b7z9.36(a))."""

from __future__ import annotations

import time

import aiocoap
import cbor2
import pytest
from aiocoap import Message

from lichen.coap.resources.capability_announce import (
    CapabilityAnnounceResource,
    CapabilityTable,
)
from lichen.crypto import Identity
from lichen.crypto.capability_announcements import (
    Capability,
    create_capability_announcement,
)


def _announcement(identity: Identity, seq: int = 1, expiry_delta: int = 3600):
    return create_capability_announcement(
        identity=identity,
        capabilities=Capability.EGRESS,
        prefix=bytes(16),
        prefix_len=128,
        expiry=int(time.time()) + expiry_delta,
        seq=seq,
    )


def _resolver(pubkey: bytes | None):
    def resolve(context_id: str) -> bytes | None:
        return pubkey

    return resolve


class _FakeSecurityContext:
    recipient_id = b"ctx-1"

    def durable_context_id(self):
        return b"ctx-1"


class _FakeRemote:
    security_context = _FakeSecurityContext()


def _post(resource: CapabilityAnnounceResource, cose: bytes):
    msg = Message(code=aiocoap.POST, payload=cose)
    # Simulate a post-unprotect OSCORE identity binding (deaddrop pattern):
    # remote.security_context.durable_context_id() yields the peer context.
    msg.remote = _FakeRemote()  # type: ignore[attr-defined]
    return resource.render_post(msg)


@pytest.mark.asyncio
async def test_valid_announcement_is_accepted() -> None:
    identity = Identity.generate()
    table = CapabilityTable()
    resolver_pubkey: list[bytes | None] = [identity.pubkey]

    def resolve(context_id: str) -> bytes | None:
        return resolver_pubkey[0]

    resource = CapabilityAnnounceResource(table, resolve)
    ann = _announcement(identity, seq=1)
    resp = await _post(resource, ann.to_cose_sign1())
    assert resp.code == aiocoap.CHANGED
    assert len(table) == 1
    assert table.cached_seq(ann.payload.announcer_iid) == 1
    del resolver_pubkey[0]


@pytest.mark.asyncio
async def test_replay_is_rejected() -> None:
    identity = Identity.generate()
    table = CapabilityTable()
    resource = CapabilityAnnounceResource(table, _resolver(identity.pubkey))
    ann = _announcement(identity, seq=1)
    cose = ann.to_cose_sign1()
    first = await _post(resource, cose)
    assert first.code == aiocoap.CHANGED
    replay = await _post(resource, cose)
    assert replay.code == aiocoap.FORBIDDEN
    assert len(table) == 1


@pytest.mark.asyncio
async def test_expired_announcement_is_rejected() -> None:
    identity = Identity.generate()
    table = CapabilityTable()
    resource = CapabilityAnnounceResource(table, _resolver(identity.pubkey))
    ann = _announcement(identity, seq=1, expiry_delta=-10)
    resp = await _post(resource, ann.to_cose_sign1())
    assert resp.code == aiocoap.FORBIDDEN
    assert len(table) == 0


@pytest.mark.asyncio
async def test_kid_mismatch_is_rejected() -> None:
    identity = Identity.generate()
    other = Identity.generate()
    table = CapabilityTable()
    resource = CapabilityAnnounceResource(table, _resolver(other.pubkey))
    ann = _announcement(identity, seq=1)
    resp = await _post(resource, ann.to_cose_sign1())
    assert resp.code == aiocoap.FORBIDDEN
    assert len(table) == 0


@pytest.mark.asyncio
async def test_missing_pubkey_is_rejected() -> None:
    identity = Identity.generate()
    table = CapabilityTable()
    resource = CapabilityAnnounceResource(table, _resolver(None))
    ann = _announcement(identity, seq=1)
    resp = await _post(resource, ann.to_cose_sign1())
    assert resp.code == aiocoap.FORBIDDEN
    assert len(table) == 0


@pytest.mark.asyncio
async def test_unprotected_request_is_rejected() -> None:
    identity = Identity.generate()
    table = CapabilityTable()
    resource = CapabilityAnnounceResource(table, _resolver(identity.pubkey))
    ann = _announcement(identity, seq=1)
    msg = Message(code=aiocoap.POST, payload=ann.to_cose_sign1())
    resp = await resource.render_post(msg)
    assert resp.code == aiocoap.UNAUTHORIZED
    assert cbor2.loads(resp.payload) == {"error": "oscore_required"}


@pytest.mark.asyncio
async def test_lru_reservation_refuses_non_egress_beyond_effective_capacity() -> None:
    table = CapabilityTable(capacity=4, egress_reservation=1)
    # Non-egress inserts may fill only capacity - reservation = 3 slots.
    for peer in range(3):
        peer_id = Identity.from_seed(bytes([peer + 1]) * 32)
        ann = _announcement(peer_id, seq=1)
        resource = CapabilityAnnounceResource(table, _resolver(peer_id.pubkey))
        resp = await _post(resource, ann.to_cose_sign1())
        assert resp.code == aiocoap.CHANGED
    assert len(table) == 3
    # A 4th distinct announcer would consume the reserved tail: refused.
    fourth = Identity.from_seed(bytes([99]) * 32)
    ann4 = _announcement(fourth, seq=1)
    resource4 = CapabilityAnnounceResource(table, _resolver(fourth.pubkey))
    resp4 = await _post(resource4, ann4.to_cose_sign1())
    assert resp4.code == aiocoap.SERVICE_UNAVAILABLE
    assert len(table) == 3
    # Egress-sourced inserts may use the reserved tail (direct table API).
    assert table.record(bytes([99]) * 8, seq=1, expiry=2**31, capabilities=1, egress=True)
    assert len(table) == 4


@pytest.mark.asyncio
async def test_seq_must_increase_per_announcer() -> None:
    identity = Identity.generate()
    table = CapabilityTable()
    resource = CapabilityAnnounceResource(table, _resolver(identity.pubkey))
    ann1 = _announcement(identity, seq=5)
    resp1 = await _post(resource, ann1.to_cose_sign1())
    assert resp1.code == aiocoap.CHANGED
    ann2 = _announcement(identity, seq=4)
    resp2 = await _post(resource, ann2.to_cose_sign1())
    assert resp2.code == aiocoap.FORBIDDEN
    ann3 = _announcement(identity, seq=6)
    resp3 = await _post(resource, ann3.to_cose_sign1())
    assert resp3.code == aiocoap.CHANGED
