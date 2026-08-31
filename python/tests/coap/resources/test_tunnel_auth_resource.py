# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the /.well-known/tunnel-auth CoAP resource (spec/06 727-807)."""

from __future__ import annotations

import time
from ipaddress import IPv6Address, IPv6Network

import aiocoap
import pytest
from aiocoap import CHANGED, FORBIDDEN, METHOD_NOT_ALLOWED, Message

from lichen.coap.resources.tunnel_auth import TUNNEL_AUTH_PATH, TunnelAuthResource
from lichen.crypto.identity import Identity
from lichen.gateway.tunnel_auth import (
    TunnelAuthorization,
    TunnelAuthorizationTable,
    create_tunnel_authorization,
)

ROOT = Identity.from_seed(bytes(range(32)))
EGRESS = Identity.from_seed(bytes(range(32, 64)))
TARGET = IPv6Network("0200:1234:5600::/40")
ROUTE = (
    IPv6Address("0200::0102:0304:0506:0708"),
    IPv6Address(bytes(EGRESS.ygg_addr)),
)
NOW = int(time.time())


def _authorization() -> TunnelAuthorization:
    return create_tunnel_authorization(
        ROOT, TARGET, ROUTE, 7, NOW + 300, EGRESS.iid
    )


def _table() -> TunnelAuthorizationTable:
    return TunnelAuthorizationTable(
        egress_iid=EGRESS.iid,
        root_iid=ROOT.iid,
        root_pubkey=ROOT.pubkey,
    )


class _FakeRemote:
    """Transport-bound remote exposing the root's address."""

    def __init__(self, hostinfo: str) -> None:
        self.hostinfo = hostinfo


def _post_request(payload: bytes, *, oscore: bool = True) -> Message:
    """Build a POST as aiocoap's OSCORE layer would present it post-unprotect."""
    request = Message(code=aiocoap.POST, payload=payload)
    if oscore:
        object.__setattr__(request, "oscore_context_id", b"root-session")
        root_host = IPv6Address(bytes(ROOT.ygg_addr))
        object.__setattr__(request, "remote", _FakeRemote(f"[{root_host}]:5683"))
    return request


@pytest.fixture
def resource() -> TunnelAuthResource:
    return TunnelAuthResource(_table())


async def test_valid_authorization_post_returns_changed(resource: TunnelAuthResource) -> None:
    response = await resource.render_post(
        _post_request(_authorization().to_cose_sign1())
    )
    assert response.code == CHANGED
    assert resource._authorizations.size == 1


async def test_denied_authorization_is_uniform_403(resource: TunnelAuthResource) -> None:
    # Wrong-egress authorization: signed by the real root but its route
    # terminates at a different egress, so the table denies WRONG_EGRESS.
    other_egress = Identity.from_seed(bytes(range(64, 96)))
    wrong_egress = create_tunnel_authorization(
        ROOT, TARGET, ROUTE[:-1] + (IPv6Address(bytes(other_egress.ygg_addr)),),
        7, NOW + 300, other_egress.iid
    )
    response = await resource.render_post(_post_request(wrong_egress.to_cose_sign1()))
    assert response.code == FORBIDDEN
    assert resource._authorizations.size == 0


async def test_non_oscore_post_is_denied(resource: TunnelAuthResource) -> None:
    payload = _authorization().to_cose_sign1()
    response = await resource.render_post(_post_request(payload, oscore=False))
    assert response.code == FORBIDDEN
    assert resource._authorizations.size == 0


async def test_empty_payload_is_denied(resource: TunnelAuthResource) -> None:
    response = await resource.render_post(_post_request(b""))
    assert response.code == FORBIDDEN


async def test_replay_is_denied_and_table_grows_once(resource: TunnelAuthResource) -> None:
    payload = _authorization().to_cose_sign1()
    first = await resource.render_post(_post_request(payload))
    second = await resource.render_post(_post_request(payload))
    assert first.code == CHANGED
    assert second.code == FORBIDDEN
    assert resource._authorizations.size == 1


async def test_other_methods_are_not_allowed(resource: TunnelAuthResource) -> None:
    for render in (resource.render_get, resource.render_put, resource.render_delete):
        response = await render(Message(code=aiocoap.GET))
        assert response.code == METHOD_NOT_ALLOWED


def test_path_segments_match_well_known_resource() -> None:
    assert TUNNEL_AUTH_PATH == (".well-known", "tunnel-auth")


async def test_build_site_mount_serves_the_full_well_known_path() -> None:
    """build_site mounts the resource at /.well-known/tunnel-auth."""
    from lichen.coap.resources import StaticNodeInfo
    from lichen.coap.resources.site import build_site

    table = _table()
    site = build_site(StaticNodeInfo(), tunnel_authorizations=table)
    # aiocoap dispatches through the site's internal path-keyed map; the
    # mounted resource must appear under the FULL .well-known/tunnel-auth
    # path (a truncated mount would only be reachable at /.well-known).
    found = site._resources.get((".well-known", "tunnel-auth"))
    assert isinstance(found, TunnelAuthResource)
    assert found._authorizations is table
