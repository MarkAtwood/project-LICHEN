# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /groups/{id}/admins -- 18.8.2 Admin Delegation (bead l1qw.39)."""

from __future__ import annotations

import cbor2
import pytest
from aiocoap import Message

from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    GroupsItemResource,
)

OWNER = "0200::1111"
MEMBER = "0200::3333"
SECOND = "0200::4444"
OUTSIDER = "0200::9999"

CREATED_CODE = 2 * 32 + 1
CHANGED_CODE = 2 * 32 + 4
FORBIDDEN_CODE = 4 * 32 + 3
BAD_REQUEST_CODE = 4 * 32 + 0
NOT_FOUND_CODE = 4 * 32 + 4
OSCORE_REQUIRED_CODE = 4 * 32 + 1


def _admins_request(
    *,
    action: str | None = "promote",
    node: str | None = MEMBER,
    context: str | None = OWNER,
    group_id: str = "gid",
    payload: bytes | None = None,
) -> Message:
    body = cbor2.dumps({"action": action, "node": node}) if payload is None else payload
    request = Message(code=1, payload=body)
    request.opt.uri_path = ("groups", group_id, "admins")
    if context is not None:
        request.oscore_context_id = context
    return request


async def _setup(
    *, members: list[str] | None = None
) -> tuple[GroupsCollectionResource, GroupsItemResource, str]:
    resource = GroupsCollectionResource(owner=OWNER, clock=lambda: 1716742800)
    item = GroupsItemResource(resource)
    request = Message(
        code=1, payload=cbor2.dumps({"name": "Team Alpha", "encrypted": False})
    )
    request.oscore_context_id = OWNER
    created = await resource.render_post(request)
    assert created.code == CREATED_CODE
    group_id = cbor2.loads(created.payload)["id"]
    if members:
        resource.groups[group_id]["members"] = list(members)
    return resource, item, group_id


@pytest.mark.asyncio
async def test_owner_promotes_member() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    response = await item.render_post(
        _admins_request(action="promote", node=MEMBER, group_id=gid)
    )
    assert response.code == CHANGED_CODE
    assert resource.groups[gid]["admins"] == [MEMBER]


@pytest.mark.asyncio
async def test_owner_demotes_admin() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    resource.groups[gid]["admins"] = [MEMBER]
    response = await item.render_post(
        _admins_request(action="demote", node=MEMBER, group_id=gid)
    )
    assert response.code == CHANGED_CODE
    assert resource.groups[gid]["admins"] == []


@pytest.mark.asyncio
async def test_promote_is_idempotent() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    for _ in range(2):
        response = await item.render_post(
            _admins_request(action="promote", node=MEMBER, group_id=gid)
        )
        assert response.code == CHANGED_CODE
    assert resource.groups[gid]["admins"] == [MEMBER]


@pytest.mark.asyncio
async def test_demote_is_idempotent_for_non_admin() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    response = await item.render_post(
        _admins_request(action="demote", node=MEMBER, group_id=gid)
    )
    assert response.code == CHANGED_CODE
    assert resource.groups[gid]["admins"] == []


@pytest.mark.asyncio
async def test_only_owner_can_admin() -> None:
    resource, item, gid = await _setup(members=[MEMBER, SECOND])
    for context in (MEMBER, SECOND, OUTSIDER):
        response = await item.render_post(
            _admins_request(action="promote", node=SECOND, group_id=gid, context=context)
        )
        assert response.code == FORBIDDEN_CODE
    assert resource.groups[gid]["admins"] == []


@pytest.mark.asyncio
async def test_demote_owner_is_forbidden() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    resource.groups[gid]["admins"] = [OWNER]
    response = await item.render_post(
        _admins_request(action="demote", node=OWNER, group_id=gid)
    )
    assert response.code == FORBIDDEN_CODE


@pytest.mark.asyncio
async def test_promote_non_member_is_rejected() -> None:
    """requester_role fails closed for orphaned admin entries (admins are
    always members), so promoting a non-member is a client error."""
    resource, item, gid = await _setup(members=[MEMBER])
    response = await item.render_post(
        _admins_request(action="promote", node=OUTSIDER, group_id=gid)
    )
    assert response.code == BAD_REQUEST_CODE


@pytest.mark.asyncio
async def test_malformed_requests_are_rejected() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    cases = [
        _admins_request(action="kick", node=MEMBER, group_id=gid),
        _admins_request(action=None, node=MEMBER, group_id=gid),
        _admins_request(action="promote", node=None, group_id=gid),
        _admins_request(action="promote", node="", group_id=gid),
        _admins_request(payload=cbor2.dumps({"action": "promote"}), group_id=gid),
        _admins_request(payload=cbor2.dumps([1, 2]), group_id=gid),
        _admins_request(payload=b"not-cbor", group_id=gid),
        _admins_request(payload=b"", group_id=gid),
        _admins_request(
            action="promote",
            node=MEMBER,
            group_id=gid,
            payload=cbor2.dumps({"action": "promote", "node": MEMBER, "x": 1}),
        ),
    ]
    for request in cases:
        response = await item.render_post(request)
        assert response.code == BAD_REQUEST_CODE


@pytest.mark.asyncio
async def test_unknown_group_is_not_found() -> None:
    resource, item, _gid = await _setup(members=[MEMBER])
    response = await item.render_post(
        _admins_request(action="promote", node=MEMBER, group_id="nope")
    )
    assert response.code == NOT_FOUND_CODE


@pytest.mark.asyncio
async def test_missing_oscore_is_unauthorized() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    response = await item.render_post(
        _admins_request(action="promote", node=MEMBER, group_id=gid, context=None)
    )
    assert response.code == OSCORE_REQUIRED_CODE
