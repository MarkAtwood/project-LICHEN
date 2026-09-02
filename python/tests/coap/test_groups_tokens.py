# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /groups/{id}/tokens -- delegation-token issuance (18.8.6, l1qw.40)."""

from __future__ import annotations

import cbor2
import pytest
from aiocoap import Message

from lichen.coap.resources.delegation_tokens_resource import (
    _handle_tokens_post,
    register,
)
from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    GroupsItemResource,
)
from lichen.crypto.identity import Identity

OWNER = "0200::1111"
ADMIN = "0200::2222"
MEMBER = "0200::3333"

FORBIDDEN_CODE = 4 * 32 + 3
BAD_REQUEST_CODE = 4 * 32 + 0
NOT_FOUND_CODE = 4 * 32 + 4
CREATED_CODE = 2 * 32 + 1
CHANGED_CODE = 2 * 32 + 4


def _admins_request(
    *,
    action: str,
    node: str,
    context: str = OWNER,
    group_id: str = "gid",
) -> Message:
    request = Message(code=1, payload=cbor2.dumps({"action": action, "node": node}))
    request.opt.uri_path = ("groups", group_id, "admins")
    request.oscore_context_id = context
    return request


def _tokens_request(
    *,
    delegate: str = MEMBER,
    scope: int = 0x01,
    expiry: int = 1716746800,
    seq: int | None = None,
    context: str = OWNER,
    group_id: str = "gid",
    payload: bytes | None = None,
) -> Message:
    body: dict = {"delegate": delegate, "scope": scope, "expiry": expiry}
    if seq is not None:
        body["seq"] = seq
    request = Message(
        code=1, payload=payload if payload is not None else cbor2.dumps(body)
    )
    request.opt.uri_path = ("groups", group_id, "tokens")
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
    register(item)
    return resource, item, group_id


def _promote_admin(
    item: GroupsItemResource, gid: str, admin: str
) -> None:
    item.collection.groups[gid]["admins"] = [admin]


@pytest.mark.asyncio
async def test_owner_issues_token_seq_increments() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    first = await _handle_tokens_post(
        item, gid, _tokens_request(delegate=MEMBER, group_id=gid)
    )
    assert first.code == CHANGED_CODE
    assert cbor2.loads(first.payload) == {"seq": 1}
    second = await _handle_tokens_post(
        item, gid, _tokens_request(delegate=MEMBER, group_id=gid)
    )
    assert cbor2.loads(second.payload) == {"seq": 2}


@pytest.mark.asyncio
async def test_seq_cache_is_per_group_per_delegator() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    await _handle_tokens_post(item, gid, _tokens_request(group_id=gid))
    # Same delegator, different group: independent counter.
    other = await _setup(members=[MEMBER])
    other_gid = other[2]
    other_item = other[1]
    response = await _handle_tokens_post(
        other_item, other_gid, _tokens_request(group_id=other_gid)
    )
    assert cbor2.loads(response.payload) == {"seq": 1}


@pytest.mark.asyncio
async def test_member_cannot_issue() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    response = await _handle_tokens_post(
        item, gid, _tokens_request(delegate=MEMBER, group_id=gid, context=MEMBER)
    )
    assert response.code == FORBIDDEN_CODE


@pytest.mark.asyncio
async def test_admin_cannot_delegate_owner_only_scope() -> None:
    """18.8.6 step 8: admins cannot delegate bits 2, 3 (scope 0x0C)."""
    resource, item, gid = await _setup(members=[ADMIN, MEMBER])
    _promote_admin(item, gid, ADMIN)
    response = await _handle_tokens_post(
        item,
        gid,
        _tokens_request(delegate=MEMBER, scope=0x18, group_id=gid, context=ADMIN),
    )
    assert response.code == FORBIDDEN_CODE


@pytest.mark.asyncio
async def test_admin_can_delegate_owner_scopes() -> None:
    """Admins delegate bits 0, 1, 4 (0x13 subset)."""
    resource, item, gid = await _setup(members=[ADMIN, MEMBER])
    _promote_admin(item, gid, ADMIN)
    response = await _handle_tokens_post(
        item,
        gid,
        _tokens_request(delegate=MEMBER, scope=0x13, group_id=gid, context=ADMIN),
    )
    assert response.code == CHANGED_CODE


@pytest.mark.asyncio
async def test_invalid_scope_rejected() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    response = await _handle_tokens_post(
        item, gid, _tokens_request(scope=0x3F, group_id=gid)
    )
    assert response.code == BAD_REQUEST_CODE


@pytest.mark.asyncio
async def test_malformed_bodies_rejected() -> None:
    resource, item, gid = await _setup(members=[MEMBER])
    cases = [
        _tokens_request(delegate="", group_id=gid),
        _tokens_request(scope=0, group_id=gid),
        _tokens_request(expiry=0, group_id=gid),
        _tokens_request(payload=cbor2.dumps({"delegate": MEMBER}), group_id=gid),
        _tokens_request(payload=cbor2.dumps([1]), group_id=gid),
        _tokens_request(payload=b"nope", group_id=gid),
        _tokens_request(payload=b"", group_id=gid),
    ]
    for request in cases:
        response = await _handle_tokens_post(item, gid, request)
        assert response.code == BAD_REQUEST_CODE


@pytest.mark.asyncio
async def test_unknown_group_not_found() -> None:
    resource, item, _gid = await _setup(members=[MEMBER])
    response = await _handle_tokens_post(
        item, "nope", _tokens_request(group_id="nope")
    )
    assert response.code == NOT_FOUND_CODE


@pytest.mark.asyncio
async def test_identity_object_delegation() -> None:
    """create_delegation_token round-trip via Identity (crypto-layer parity)."""
    from lichen.crypto.delegation_tokens import create_delegation_token

    resource, item, gid = await _setup(members=[MEMBER])
    identity = Identity.from_seed(bytes([7]) * 32)
    token = create_delegation_token(
        identity, bytes.fromhex("0200000000000001"), 0x01, gid, 1716746800, 1
    )
    assert token.delegator_iid == identity.iid
    assert len(token.signature) == 48
