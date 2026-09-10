# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Delegation-token presentation at POST /groups/invite (spec 18.8.6, l1qw.40).

The inviter holds no direct invite authority; the document carries a
``delegation`` COSE_Sign1 signed by the group owner or an admin. Oracle split:
acceptance honors a genuinely signed token end-to-end, rejection refuses
foreign/expired/replayed/mis-scoped tokens without burning replay state.
"""

from __future__ import annotations

import cbor2
import pytest
from aiocoap import BAD_REQUEST, CHANGED, FORBIDDEN, Message

from lichen.coap.resources.groups_collection import GroupsCollectionResource
from lichen.coap.resources.groups_invite import GroupsInviteResource
from lichen.crypto.delegation_tokens import DelegationScope, create_delegation_token
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign
from lichen.group_membership import (
    GroupRoster,
    invitation_preimage,
    parse_invitation,
)

OWNER = "0200::1111"
ADMIN = "0200::2222"
MEMBER = "0200::3333"
OUTSIDER = "0200::5555"
INVITEE = "0200::4444"
FIXED_CLOCK = 1716742800


def _identity(seed_byte: int) -> Identity:
    return Identity.from_seed(bytes([seed_byte]) * 32)


def _sign(delegate_identity: Identity, document: dict) -> dict:
    """Return *document* carrying a genuine 48-byte Schnorr signature."""
    draft = parse_invitation({**document, "signature": b"\x00" * 48})
    signature = sign(
        delegate_identity.privkey, delegate_identity.pubkey, invitation_preimage(draft)
    )
    return {**document, "signature": signature}


def _invite_document(group_id: str, role: str = "member") -> dict:
    return {
        "group_id": group_id,
        "group_name": "Team Alpha",
        "mcast": "ff35:0040::1",
        "inviter": MEMBER,
        "role": role,
        "expires": FIXED_CLOCK + 600,
    }


async def _invite_resource(
    collection: GroupsCollectionResource,
) -> GroupsInviteResource:
    return GroupsInviteResource(
        roster=GroupRoster(owner=OWNER, admins=frozenset({ADMIN}), members=frozenset({MEMBER})),
        pubkeys={
            OWNER: _identity(0x21).pubkey,
            ADMIN: _identity(0x22).pubkey,
            MEMBER: _identity(0x23).pubkey,
            OUTSIDER: _identity(0x24).pubkey,
        },
        collection=collection,
        invitee=INVITEE,
    )


async def _created_group(collection: GroupsCollectionResource) -> str:
    request = Message(code=1, payload=cbor2.dumps({"name": "Team Alpha", "encrypted": False}))
    request.oscore_context_id = OWNER
    created = await collection.render_post(request)
    assert created.code == 2 * 32 + 1  # CREATED
    return cbor2.loads(created.payload)["id"]


def _token(
    delegator: Identity,
    group_id: str,
    *,
    scope: int = int(DelegationScope.INVITE),
    seq: int = 1,
    expiry: int = FIXED_CLOCK + 600,
    delegate_iid: bytes | None = None,
) -> bytes:
    return create_delegation_token(
        delegator,
        delegate_iid if delegate_iid is not None else _identity(0x23).iid,
        scope,
        group_id,
        expiry,
        seq,
    ).to_cose_sign1()


async def _post_invite(
    invites: GroupsInviteResource, group_id: str, token: bytes, role: str = "member"
) -> Message:
    document = _sign(_identity(0x23), _invite_document(group_id, role))
    document["delegation"] = token
    return await invites.render_post(Message(code=1, payload=cbor2.dumps(document)))


@pytest.mark.asyncio
async def test_delegated_invite_accepted_and_seq_burned() -> None:
    """A member with an owner-signed token invites; the seq cache records it."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    invites = await _invite_resource(collection)
    response = await _post_invite(invites, group_id, _token(_identity(0x21), group_id))
    assert response.code == CHANGED
    assert len(invites.accepted) == 1
    assert collection.invitation_role(group_id, INVITEE) == "member"
    cache_key = (_identity(0x21).iid, _identity(0x23).iid, group_id)
    assert invites.delegation_seq_cache[cache_key] == 1


@pytest.mark.asyncio
async def test_replayed_token_rejected_then_higher_seq_accepted() -> None:
    """Spec step 7: seq must strictly exceed the cached value per tuple."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    invites = await _invite_resource(collection)
    owner = _identity(0x21)
    token = _token(owner, group_id, seq=1)
    assert (await _post_invite(invites, group_id, token)).code == CHANGED
    replayed = await _post_invite(invites, group_id, token)
    assert replayed.code == FORBIDDEN
    assert len(invites.accepted) == 1
    fresh = await _post_invite(invites, group_id, _token(owner, group_id, seq=2))
    assert fresh.code == CHANGED
    assert len(invites.accepted) == 2


@pytest.mark.asyncio
async def test_delegator_must_be_known_owner_or_admin() -> None:
    """Spec step 2: kid must identify a rostered owner or admin."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    invites = await _invite_resource(collection)
    # Key pinned but not an owner/admin of this roster.
    outsider = await _post_invite(invites, group_id, _token(_identity(0x24), group_id))
    assert outsider.code == FORBIDDEN
    # Key not pinned at all (unresolvable kid).
    unknown = await _post_invite(invites, group_id, _token(_identity(0x31), group_id))
    assert unknown.code == FORBIDDEN
    assert invites.accepted == []
    assert invites.delegation_seq_cache == {}


@pytest.mark.asyncio
async def test_admin_token_scope_limits() -> None:
    """Admins delegate only bits 0/1/4; exercised scope must include invite."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    invites = await _invite_resource(collection)
    admin = _identity(0x22)
    # Owner-only scope from an admin: step 9 rejects (SCOPE_EXCEEDED).
    exceeded = await _post_invite(
        invites, group_id, _token(admin, group_id, scope=int(DelegationScope.DISTRIBUTE_KEY))
    )
    assert exceeded.code == FORBIDDEN
    # Valid admin token but lacking the exercised invite bit: step 8 rejects.
    wrong_scope = await _post_invite(
        invites, group_id, _token(admin, group_id, scope=int(DelegationScope.READ_MEMBERS))
    )
    assert wrong_scope.code == FORBIDDEN
    # Admin-delegable invite scope is honored.
    granted = await _post_invite(invites, group_id, _token(admin, group_id, seq=1))
    assert granted.code == CHANGED


@pytest.mark.asyncio
async def test_delegated_admin_role_minting_refused() -> None:
    """Delegated authority mints member invitations only (18.8.2 promotion rule)."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    invites = await _invite_resource(collection)
    response = await _post_invite(
        invites, group_id, _token(_identity(0x21), group_id), role="admin"
    )
    assert response.code == FORBIDDEN
    assert invites.accepted == []


@pytest.mark.asyncio
async def test_malformed_delegation_field_rejected() -> None:
    """Structural garbage in the delegation field is BAD_REQUEST, not accepted."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    invites = await _invite_resource(collection)
    document = _sign(_identity(0x23), _invite_document(group_id))
    document["delegation"] = "not-bytes"
    wrong_type = await invites.render_post(Message(code=1, payload=cbor2.dumps(document)))
    assert wrong_type.code == BAD_REQUEST
    document["delegation"] = b"\xff" * 32
    garbage = await invites.render_post(Message(code=1, payload=cbor2.dumps(document)))
    assert garbage.code == BAD_REQUEST
    assert invites.accepted == []


@pytest.mark.asyncio
async def test_expired_wrong_group_and_wrong_delegate_tokens_rejected() -> None:
    """Steps 4/5/6: resource binding, expiry, and delegate binding hold."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    invites = await _invite_resource(collection)
    owner = _identity(0x21)
    expired = await _post_invite(invites, group_id, _token(owner, group_id, expiry=FIXED_CLOCK - 1))
    assert expired.code == FORBIDDEN
    other_group = await _post_invite(invites, group_id, _token(owner, "some-other-group"))
    assert other_group.code == FORBIDDEN
    impostor = await _post_invite(
        invites,
        group_id,
        _token(owner, group_id, delegate_iid=_identity(0x24).iid),
    )
    assert impostor.code == FORBIDDEN
    assert invites.accepted == []


@pytest.mark.asyncio
async def test_failed_presentation_does_not_burn_seq() -> None:
    """Fail-closed economics: only fully verified tokens consume a seq."""
    collection = GroupsCollectionResource(owner=OWNER, clock=lambda: FIXED_CLOCK)
    group_id = await _created_group(collection)
    invites = await _invite_resource(collection)
    owner = _identity(0x21)
    expired = await _post_invite(invites, group_id, _token(owner, group_id, expiry=FIXED_CLOCK - 1))
    assert expired.code == FORBIDDEN
    # The same seq is still spendable by a valid token.
    valid = await _post_invite(invites, group_id, _token(owner, group_id, seq=1))
    assert valid.code == CHANGED
    assert invites.delegation_seq_cache == {(owner.iid, _identity(0x23).iid, group_id): 1}
