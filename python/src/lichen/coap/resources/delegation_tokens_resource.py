# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /groups/{id}/tokens -- delegation-token issuance (spec 18.8.6).

Owner and admins may mint delegation tokens for their group. The owner
may delegate any valid scope; admins only the ADMIN_DELEGATABLE_SCOPE
subset (bits 0, 1, 4). Sequence numbers come from a per-(group,
delegator) strictly increasing counter kept in RAM -- process-lifetime
state per 18.8.2 (restart resets it).
"""

from __future__ import annotations

from typing import Any

import cbor2
from aiocoap import BAD_REQUEST, CHANGED, FORBIDDEN, NOT_FOUND, Message

from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.coap.resources.groups_collection import (
    GroupsItemResource,
)
from lichen.coap.resources.groups_collection import (
    _pairwise_oscore_identity as _pairwise_identity,
)
from lichen.crypto.delegation_tokens import (
    ADMIN_DELEGATABLE_SCOPE,
    VALID_SCOPE_MASK,
)

_UNKNOWN_FIELDS = {"delegate", "scope", "expiry", "seq"}


class GroupDelegationIssuer:
    """Per-group delegation-token issuance with an in-RAM seq cache."""

    def __init__(self, item: GroupsItemResource) -> None:
        self.item = item
        # (group_id, delegator identity) -> last issued seq
        self._seq_counters: dict[tuple[str, str], int] = {}

    def next_seq(self, group_id: str, delegator: str) -> int:
        """Next strictly increasing seq for this (group, delegator)."""
        key = (group_id, delegator)
        self._seq_counters[key] = self._seq_counters.get(key, 0) + 1
        return self._seq_counters[key]


def register(item: GroupsItemResource) -> None:
    """Attach the delegation issuer to a group item resource (idempotent)."""
    if not hasattr(item, "delegation_issuer"):
        item.delegation_issuer = GroupDelegationIssuer(item)


async def _handle_tokens_post(
    item: GroupsItemResource, group_id: str, request: Message
) -> Message:
    """Owner/admin token issuance for group_id (spec 18.8.6)."""
    issuer: GroupDelegationIssuer | None = getattr(item, "delegation_issuer", None)
    if issuer is None:
        register(item)
        issuer = item.delegation_issuer
    assert issuer is not None  # noqa: S101 - narrowed above

    peer = _pairwise_identity(request)
    if peer is None:
        return Message(code=FORBIDDEN)
    with item.collection._mutation_lock:
        item_state = item.collection.groups.get(group_id)
        if item_state is None:
            return Message(code=NOT_FOUND)
        role = item.collection.requester_role(group_id, peer)
        if role not in ("owner", "admin"):
            return Message(code=FORBIDDEN)
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body: Any = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if type(body) is not dict:
            return Message(code=BAD_REQUEST)
        unknown = set(body) - _UNKNOWN_FIELDS
        if unknown:
            return Message(code=BAD_REQUEST)
        delegate = body.get("delegate")
        scope = body.get("scope")
        expiry = body.get("expiry")
        if type(delegate) is not str or delegate == "":
            return Message(code=BAD_REQUEST)
        if type(scope) is not int or scope <= 0 or scope > VALID_SCOPE_MASK:
            return Message(code=BAD_REQUEST)
        if type(expiry) is not int or expiry <= 0:
            return Message(code=BAD_REQUEST)
        # 18.8.6 step 8: admins cannot delegate bits 2, 3 (0x0C mask).
        if role == "admin" and scope & ~ADMIN_DELEGATABLE_SCOPE:
            return Message(code=FORBIDDEN)
        seq = issuer.next_seq(group_id, peer)
    return Message(code=CHANGED, payload=cbor2.dumps({"seq": seq}))
