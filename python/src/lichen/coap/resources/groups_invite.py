# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``POST /groups/invite`` (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

import time
from collections import deque
from typing import Any

import cbor2
from aiocoap import BAD_REQUEST, CHANGED, FORBIDDEN, Message, resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    _origin_locally_trusted,
)
from lichen.crypto.delegation_tokens import (
    DelegationScope,
    DelegationToken,
    check_delegation_scope,
    verify_delegation_token,
)
from lichen.crypto.identity import _pubkey_to_iid
from lichen.group_membership import (
    GroupInvitation,
    GroupRoster,
    MembershipError,
    parse_invitation,
    verify_invitation_cose,
    verify_invitation_signature,
)


class GroupsInviteResource(resource.Resource):
    """Accept a signed invitation document (spec 12-apps.md 18.8.2)."""

    rt = "groups.invite"

    def __init__(
        self,
        *,
        roster: GroupRoster | None = None,
        pubkeys: dict[str, bytes] | None = None,
        node_id: str | None = None,
        collection: GroupsCollectionResource | None = None,
        invitee: str | None = None,
        node_pubkey: bytes | None = None,
        delegation_seq_cache: dict[tuple[bytes, bytes, str], int] | None = None,
    ) -> None:
        super().__init__()
        self.accepted: list[GroupInvitation] = []
        self.roster = roster
        self.pubkeys = dict(pubkeys) if pubkeys else {}
        # Identity of the local node: invitations authored by the local node
        # itself are accepted without remote crypto ONLY from a locally
        # trusted origin; every other inviter and every wire delivery MUST
        # carry a verifiable signature.
        self.node_id = node_id
        self.collection = collection
        self.invitee = invitee
        # Delegation-token replay cache (spec 18.8.6 validation step 7):
        # highest accepted seq per (delegator_iid, delegate_iid, resource).
        # In-RAM by policy, like the invitation nonce ring.
        self.delegation_seq_cache = delegation_seq_cache if delegation_seq_cache is not None else {}
        if node_pubkey is not None:
            if type(node_pubkey) is not bytes or len(node_pubkey) != 32:
                raise ValueError("node_pubkey must be a 32-byte Ed25519 public key")
            if self.node_id is None:
                raise ValueError("node_pubkey requires node_id")
            # SECURITY: pin this node's own public key under its id in the
            # same registry used for foreign inviters, so a wire delivery
            # claiming inviter==node_id verifies exactly like any foreign
            # document instead of relying on the trusted-origin carve-out.
            # An entry already present wins: callers may have provisioned a
            # deliberate trust decision that must not be silently clobbered.
            self.pubkeys.setdefault(self.node_id, node_pubkey)
        self.node_pubkey = node_pubkey

    async def _render_cose_invitation(self, envelope: bytes) -> Message:
        """Validate a COSE_Sign1 invitation (spec 18.8.2, R-12-062..064).

        The codec (verify_invitation_cose) enforces alg/kid/invitee/nonce
        shape and the signature; this resource owns the clock (expiry), the
        per-inviter 32-entry RAM-only nonce ring (R-12-064), and roster
        authority. Fail-closed: unknown inviter key or missing own key.
        """
        if self.node_pubkey is None or self.collection is None:
            return Message(code=FORBIDDEN)
        try:
            probe = cbor2.loads(envelope)
            kid = probe[1][4]
        except Exception:
            return Message(code=BAD_REQUEST)
        inviter = None
        for addr, pubkey in self.pubkeys.items():
            if _pubkey_to_iid(pubkey) == kid:
                inviter = addr
                break
        if inviter is None:
            # Unknown inviter key: cannot authenticate, fail closed.
            return Message(code=FORBIDDEN)
        if self.roster is not None and not self.roster.can_invite(
            inviter, requested_role="member"
        ):
            # Coarse precheck: the exact role gate re-runs on the decoded
            # payload via can_invite when the role is known.
            return Message(code=FORBIDDEN)
        own_iid = _pubkey_to_iid(self.node_pubkey)
        try:
            invitation = verify_invitation_cose(envelope, self.pubkeys[inviter], own_iid)
        except MembershipError:
            return Message(code=FORBIDDEN)
        if invitation.expires <= int(self.collection._clock()):
            return Message(code=FORBIDDEN)
        ring = self.collection.invitation_nonce_ring.setdefault(
            invitation.inviter_iid, deque(maxlen=32)
        )
        if invitation.nonce in ring:
            return Message(code=FORBIDDEN)
        if self.roster is not None and not self.roster.can_invite(
            inviter, requested_role=invitation.role
        ):
            return Message(code=FORBIDDEN)
        ring.append(invitation.nonce)
        recorded = self.collection.record_invitation(
            invitation.group_id,
            self.invitee,
            expires=invitation.expires,
            role=invitation.role,
            inviter=inviter,
        )
        if not recorded:
            return Message(code=FORBIDDEN)
        self.accepted.append(invitation)
        return Message(code=CHANGED)

    def _admit_via_delegation(
        self, body: dict[str, Any], invitation: GroupInvitation
    ) -> Message | None:
        """Delegated-authority admission (spec 18.8.6 token presentation).

        The inviter could not mint this invitation directly; accept it only
        when the document carries a ``delegation`` COSE_Sign1 token signed by
        a roster owner or admin for this exact group. Returns None when
        delegated authority is proven (the seq cache is burned), otherwise
        the rejection response: BAD_REQUEST for a malformed field, FORBIDDEN
        for any failed validation step.
        """
        delegation = body.get("delegation")
        if type(delegation) is not bytes:
            return Message(code=BAD_REQUEST)
        try:
            token = DelegationToken.from_cose_sign1(delegation)
        except Exception:
            return Message(code=BAD_REQUEST)
        if self.roster is None:
            # No roster means no owner/admin authority to delegate from;
            # this path is unreachable via render_post (can_invite is only
            # consulted when a roster exists) -- fail closed regardless.
            return Message(code=FORBIDDEN)
        delegator_addr: str | None = None
        for addr, pubkey in self.pubkeys.items():
            if _pubkey_to_iid(pubkey) == token.delegator_iid:
                delegator_addr = addr
                break
        if delegator_addr is None or not (
            delegator_addr == self.roster.owner or delegator_addr in self.roster.admins
        ):
            # spec 18.8.6 step 2: kid must identify a known owner or admin.
            return Message(code=FORBIDDEN)
        inviter_pubkey = self.pubkeys.get(invitation.inviter)
        if inviter_pubkey is None:
            return Message(code=FORBIDDEN)
        delegate_iid = _pubkey_to_iid(inviter_pubkey)
        # Delegated invitations mint member-role only: the scope bitmap has
        # no role distinction, and promotion is owner-reserved (18.8.2).
        if invitation.role != "member":
            return Message(code=FORBIDDEN)
        if self.collection is not None:
            current_time = int(self.collection._clock())
        else:
            current_time = int(time.time())
        cache_key = (token.delegator_iid, delegate_iid, invitation.group_id)
        valid, _error = verify_delegation_token(
            token,
            self.pubkeys[delegator_addr],
            delegate_iid,
            invitation.group_id,
            current_time,
            cached_seq=self.delegation_seq_cache.get(cache_key),
            is_delegator_owner=delegator_addr == self.roster.owner,
        )
        if not valid:
            return Message(code=FORBIDDEN)
        if not check_delegation_scope(token, DelegationScope.INVITE):
            # spec 18.8.6 step 8: the exercised capability must be granted.
            return Message(code=FORBIDDEN)
        # Burn the seq after every validation step passes: a presented token
        # is one-shot regardless of what the downstream ledger does with the
        # invitation (fail-closed; the delegator re-issues seq+1 on retry).
        self.delegation_seq_cache[cache_key] = token.payload.seq
        return None

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if type(body) is bytes:
            # COSE_Sign1 envelope (spec 18.8.2 canonical form).
            return await self._render_cose_invitation(body)
        try:
            invitation = parse_invitation(body)
        except MembershipError:
            return Message(code=BAD_REQUEST)
        if self.roster is not None and not self.roster.can_invite(
            invitation.inviter, requested_role=invitation.role
        ):
            if "delegation" in body:
                rejection = self._admit_via_delegation(body, invitation)
                if rejection is not None:
                    return rejection
                # Delegated authority proven (seq burned); fall through to
                # the invitation signature check and the invitation ledger.
            else:
                return Message(code=FORBIDDEN)
        verified: bool | None = None
        if invitation.inviter == self.node_id and _origin_locally_trusted(request, self.node_id):
            # Provisioning carve-out: locally authored invitations skip
            # remote crypto only when the origin is locally trusted (LCI
            # loopback admin, or a pairwise OSCORE identity bound to this
            # node). SECURITY: no unauthenticated, non-local, unverifiable
            # delivery may reach acceptance -- see the fail-closed branch.
            pass
        else:
            # SECURITY: fail closed -- an inviter whose public key is unknown
            # cannot be authenticated (a forged inviter='owner' document would
            # otherwise unlock join_key), and inviter==node_id deliveries from
            # a non-local origin must verify against the node's own pinned
            # public key exactly like foreign inviters.
            pubkey = self.pubkeys.get(invitation.inviter)
            if pubkey is None:
                return Message(code=FORBIDDEN)
            verified = verify_invitation_signature(invitation, pubkey)
        if verified is False:
            return Message(code=FORBIDDEN)
        recorded = True
        if self.collection is not None and self.invitee is not None:
            recorded = self.collection.record_invitation(
                invitation.group_id,
                self.invitee,
                expires=invitation.expires,
                role=invitation.role,
                inviter=invitation.inviter,
            )
        if not recorded:
            # spec 18.8.2 response semantics: an expired, replayed, or revoked
            # document is declined now rather than accepted into a ledger that
            # join_key later refuses as an opaque failure.
            return Message(code=FORBIDDEN)
        self.accepted.append(invitation)
        return Message(code=CHANGED)

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}
