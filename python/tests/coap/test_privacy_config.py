# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for /config/privacy resources (spec 18.2.4)."""

from __future__ import annotations

import aiocoap
import cbor2
from aiocoap import GET, PUT, Message

from lichen.coap.position_privacy import (
    PositionPrivacyMode,
    PositionPrivacyPolicy,
)
from lichen.coap.resources import StaticNodeInfo
from lichen.coap.resources.site import build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _setup(*, allow_writes: bool = False):
    policy = PositionPrivacyPolicy(mode=PositionPrivacyMode.PRIVATE)
    net = InMemoryNetwork()
    site = build_site(
        node_info=StaticNodeInfo(status={"rank": 256}),
        privacy_policy=policy,
        privacy_allow_writes=allow_writes,
    )
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, policy


# ---------------------------------------------------------------------------
# oscore_required body helper
# ---------------------------------------------------------------------------


def test_allowed_peer_iid_seeds_whitelist() -> None:
    policy = PositionPrivacyPolicy(
        allowed_peer_iid="0200:legacy:1", allowed_peers={"0200:seeded:2"}
    )
    assert policy.allowed_peers == frozenset({"0200:legacy:1", "0200:seeded:2"})


def test_whitelist_generalization_gates_reads() -> None:
    policy = PositionPrivacyPolicy(
        mode=PositionPrivacyMode.PRIVATE, allowed_peers={"peer-a", "peer-b"}
    )
    ok, _ = policy.check_read(oscore=True, requester_iid="peer-a")
    assert ok is True
    ok, code = policy.check_read(oscore=True, requester_iid="stranger")
    assert ok is False
    assert code == "4.03 Forbidden"


# ---------------------------------------------------------------------------
# /config/privacy resources
# ---------------------------------------------------------------------------


class TestPrivacyConfigResources:
    async def test_get_config_privacy_reports_mode_and_whitelist(self) -> None:
        client, server, policy = await _setup()
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/config/privacy")
            ).response
            body = cbor2.loads(resp.payload)
            assert body["mode"] == "private"
            # SECURITY: the individual peer identities are not disclosed
            # without the management gate — count only.
            assert body["allowed_peer_count"] == 0
            assert "allowed_peers" not in body
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_allowed_peers_requires_writes_enabled(self) -> None:
        client, server, policy = await _setup(allow_writes=False)
        try:
            payload = cbor2.dumps({"peers": ["0200:aa:1"]})
            resp = await client.request(
                Message(
                    code=PUT, uri="coap://srv/config/privacy/allowed", payload=payload
                )
            ).response
            assert resp.code == aiocoap.UNAUTHORIZED
            # Unauthenticated GET of the full list is likewise gated.
            resp = await client.request(
                Message(code=GET, uri="coap://srv/config/privacy/allowed")
            ).response
            assert resp.code == aiocoap.UNAUTHORIZED
            assert policy.allowed_peers == frozenset()
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_allowed_peers_replaces_whitelist(self) -> None:
        client, server, policy = await _setup(allow_writes=True)
        try:
            payload = cbor2.dumps({"peers": ["0200:aa:1", "0200:bb:2"]})
            resp = await client.request(
                Message(
                    code=PUT, uri="coap://srv/config/privacy/allowed", payload=payload
                )
            ).response
            assert resp.code == aiocoap.CHANGED
            assert policy.allowed_peers == frozenset({"0200:aa:1", "0200:bb:2"})

            resp = await client.request(
                Message(code=GET, uri="coap://srv/config/privacy/allowed")
            ).response
            assert cbor2.loads(resp.payload) == {"peers": ["0200:aa:1", "0200:bb:2"]}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_allowed_peers_rejects_malformed(self) -> None:
        client, server, policy = await _setup(allow_writes=True)
        try:
            # Non-dict body.
            resp = await client.request(
                Message(
                    code=PUT,
                    uri="coap://srv/config/privacy/allowed",
                    payload=cbor2.dumps(["peers"]),
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            # peers not a list.
            resp = await client.request(
                Message(
                    code=PUT,
                    uri="coap://srv/config/privacy/allowed",
                    payload=cbor2.dumps({"peers": "0200:aa:1"}),
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            # Non-tstr member.
            resp = await client.request(
                Message(
                    code=PUT,
                    uri="coap://srv/config/privacy/allowed",
                    payload=cbor2.dumps({"peers": ["ok", 7]}),
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            # Empty-string member.
            resp = await client.request(
                Message(
                    code=PUT,
                    uri="coap://srv/config/privacy/allowed",
                    payload=cbor2.dumps({"peers": [""]}),
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert policy.allowed_peers == frozenset()
        finally:
            await client.shutdown()
            await server.shutdown()
