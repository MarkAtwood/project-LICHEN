# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group invitation and removal domain types (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import cbor2

GroupRoleName = Literal["member", "admin"]
ALLOWED_INVITE_ROLES: frozenset[str] = frozenset({"member", "admin"})
# spec 18.8.2 payload role wire values (uint)
_ROLE_TO_UINT: dict[str, int] = {"member": 0, "admin": 1}
_ROLE_FROM_UINT: dict[int, str] = {0: "member", 1: "admin"}


class MembershipError(ValueError):
    """Malformed invitation or removal document."""


def _loads_strict(data: bytes) -> Any:
    """CBOR decode that rejects trailing bytes (wire-malleability guard)."""
    import io

    fp = io.BytesIO(data)
    value = cbor2.CBORDecoder(fp).decode()
    if fp.tell() != len(data):
        raise MembershipError("trailing bytes after CBOR document")
    return value


@dataclass(frozen=True)
class GroupInvitation:
    group_id: str
    group_name: str
    mcast: str
    inviter: str
    role: GroupRoleName
    expires: int
    signature: bytes

    def to_map(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "mcast": self.mcast,
            "inviter": self.inviter,
            "role": self.role,
            "expires": self.expires,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class GroupRemoval:
    group_id: str
    removed_by: str
    signature: bytes
    reason: str | None = None

    def to_map(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "group_id": self.group_id,
            "removed_by": self.removed_by,
            "signature": self.signature,
        }
        if self.reason is not None:
            document["reason"] = self.reason
        return document


def _require_str(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if type(value) is not str or value == "":
        raise MembershipError(f"{key} must be a non-empty string")
    return value


def parse_invitation(document: dict[str, Any]) -> GroupInvitation:
    if type(document) is not dict:
        raise MembershipError("invitation must be a map")
    role = _require_str(document, "role")
    if role not in ALLOWED_INVITE_ROLES:
        raise MembershipError("role must be member or admin")
    expires = document.get("expires")
    if type(expires) is not int or isinstance(expires, bool) or expires < 0:
        raise MembershipError("expires must be a non-negative integer")
    signature = document.get("signature")
    if type(signature) is not bytes:
        raise MembershipError("signature must be bytes")
    return GroupInvitation(
        group_id=_require_str(document, "group_id"),
        group_name=_require_str(document, "group_name"),
        mcast=_require_str(document, "mcast"),
        inviter=_require_str(document, "inviter"),
        role=role,  # type: ignore[arg-type]
        expires=expires,
        signature=signature,
    )


def invitation_preimage(invitation: GroupInvitation) -> bytes:
    """Canonical CBOR of invitation fields excluding the signature."""
    return cbor2.dumps(
        {
            "expires": invitation.expires,
            "group_id": invitation.group_id,
            "group_name": invitation.group_name,
            "inviter": invitation.inviter,
            "mcast": invitation.mcast,
            "role": invitation.role,
        },
        canonical=True,
    )


def removal_preimage(removal: GroupRemoval) -> bytes:
    """Canonical CBOR of removal fields excluding the signature."""
    document: dict[str, Any] = {
        "group_id": removal.group_id,
        "removed_by": removal.removed_by,
    }
    if removal.reason is not None:
        document["reason"] = removal.reason
    return cbor2.dumps(document, canonical=True)


def verify_invitation_signature(invitation: GroupInvitation, pubkey: bytes) -> bool:
    from lichen.crypto.schnorr48 import verify

    if type(pubkey) is not bytes:
        raise MembershipError("pubkey must be bytes")
    return verify(pubkey, invitation_preimage(invitation), invitation.signature)


def verify_removal_signature(removal: GroupRemoval, pubkey: bytes) -> bool:
    from lichen.crypto.schnorr48 import verify

    if type(pubkey) is not bytes:
        raise MembershipError("pubkey must be bytes")
    return verify(pubkey, removal_preimage(removal), removal.signature)


# ─── COSE_Sign1 invitation envelope (spec/12-apps.md 18.8.2, R-12-062..064) ──

_INVITATION_KEY_GROUP_ID = 1
_INVITATION_KEY_GROUP_NAME = 2
_INVITATION_KEY_MCAST = 3
_INVITATION_KEY_ROLE = 4
_INVITATION_KEY_EXPIRY = 5
_INVITATION_KEY_INVITEE_IID = 6
_INVITATION_KEY_NONCE = 7
_COSE_KID_LABEL = 4


@dataclass(frozen=True)
class GroupInvitationCose:
    """Invitation carried in a COSE_Sign1 envelope (spec 18.8.2).

    Attributes:
        group_id: Group being joined.
        group_name: Human-readable group name.
        mcast: Group multicast address.
        role: Role granted to the invitee.
        expires: Expiry as a non-negative epoch-seconds integer.
        invitee_iid: 8-byte IID of the invitee; must equal the consuming
            node's own IID at validation time.
        nonce: Per-invitation anti-replay value (32-entry per-inviter ring).
        inviter_iid: 8-byte IID of the inviter (COSE kid, unprotected).
        signature: 48-byte Schnorr48 signature.
    """

    group_id: str
    group_name: str
    mcast: str
    role: GroupRoleName
    expires: int
    invitee_iid: bytes
    nonce: bytes
    inviter_iid: bytes
    signature: bytes


def encode_invitation_cose(invitation: GroupInvitationCose, identity: Identity) -> bytes:
    """Encode a signed COSE_Sign1 invitation envelope.

    Payload wire types per spec/12-apps.md 18.8.2: group_id is bstr or tstr,
    group_name tstr, mcast bstr(16) (packed IPv6), role uint (0=member,
    1=admin), expiry uint, invitee_iid bstr(8), nonce bstr(8).
    Signature covers SHA256(CBOR(Sig_structure)) per RFC 9052 section 4.4
    with the Schnorr48-Ed25519 algorithm (alg -65537).
    """
    from hashlib import sha256
    from ipaddress import IPv6Address

    from lichen.crypto.schnorr48 import sign
    from lichen.crypto.delegation_tokens import (
        cose_protected_header,
        cose_sig_structure,
    )

    if invitation.inviter_iid != identity.iid:
        raise MembershipError("inviter_iid must match the signing identity")
    payload = cbor2.dumps(
        {
            _INVITATION_KEY_GROUP_ID: invitation.group_id,
            _INVITATION_KEY_GROUP_NAME: invitation.group_name,
            _INVITATION_KEY_MCAST: IPv6Address(invitation.mcast).packed,
            _INVITATION_KEY_ROLE: _ROLE_TO_UINT[invitation.role],
            _INVITATION_KEY_EXPIRY: invitation.expires,
            _INVITATION_KEY_INVITEE_IID: invitation.invitee_iid,
            _INVITATION_KEY_NONCE: invitation.nonce,
        },
        canonical=True,
    )
    protected = cose_protected_header()
    sig_structure = cose_sig_structure(protected, payload)
    to_sign = sha256(sig_structure).digest()
    signature = sign(identity.privkey, identity.pubkey, to_sign)
    return cbor2.dumps(
        [protected, {_COSE_KID_LABEL: invitation.inviter_iid}, payload, signature]
    )


def verify_invitation_cose(
    envelope: bytes, inviter_pubkey: bytes, own_iid: bytes
) -> GroupInvitationCose:
    """Validate a COSE_Sign1 invitation envelope (spec 18.8.2).

    Checks: envelope shape, alg -65537 in the protected header, kid present
    and bound to the inviter key's IID, payload key/type conformance,
    Schnorr48 signature over SHA256(CBOR(Sig_structure)), and
    invitee_iid == own_iid.

    CALLER CONTRACT: this codec layer has no clock and no ledger. The caller
    MUST additionally enforce expiry (expires > now) and the per-inviter
    32-entry nonce replay ledger (R-12-064) before acting on the invitation.
    """
    from hashlib import sha256
    from ipaddress import IPv6Address

    from lichen.crypto.schnorr48 import verify
    from lichen.crypto.delegation_tokens import (
        COSE_ALG_LABEL,
        SCHNORR48_ED25519_ALG,
        cose_sig_structure,
    )
    from lichen.crypto.identity import _pubkey_to_iid

    if type(envelope) is not bytes:
        raise MembershipError("invitation envelope must be bytes")
    if type(inviter_pubkey) is not bytes:
        raise MembershipError("pubkey must be bytes")
    try:
        document = _loads_strict(envelope)
    except MembershipError:
        raise
    except Exception as error:
        raise MembershipError("invitation envelope is not valid CBOR") from error
    if type(document) is not list or len(document) != 4:
        raise MembershipError("COSE_Sign1 must be a 4-element array")
    protected, unprotected, payload, signature = document
    if type(protected) is not bytes or type(payload) is not bytes:
        raise MembershipError("COSE protected header and payload must be bytes")
    if type(unprotected) is not dict:
        raise MembershipError("COSE unprotected header must be a map")
    if type(signature) is not bytes:
        raise MembershipError("COSE signature must be bytes")
    try:
        header = _loads_strict(protected)
    except MembershipError:
        raise
    except Exception as error:
        raise MembershipError("COSE protected header is not valid CBOR") from error
    if type(header) is not dict or header.get(COSE_ALG_LABEL) != SCHNORR48_ED25519_ALG:
        raise MembershipError("invitation alg must be Schnorr48-Ed25519 (-65537)")
    kid = unprotected.get(_COSE_KID_LABEL)
    if type(kid) is not bytes or len(kid) != 8:
        raise MembershipError("invitation kid must be an 8-byte inviter IID")
    # Bind the (unprotected) kid to the verifying key's derived IID so a
    # validly-signed envelope cannot be replayed under a mismatched kid.
    if kid != _pubkey_to_iid(inviter_pubkey):
        raise MembershipError("invitation kid does not match the inviter key IID")
    try:
        fields = _loads_strict(payload)
    except MembershipError:
        raise
    except Exception as error:
        raise MembershipError("invitation payload is not valid CBOR") from error
    if type(fields) is not dict:
        raise MembershipError("invitation payload must be a map")
    group_id = fields.get(_INVITATION_KEY_GROUP_ID)
    group_name = fields.get(_INVITATION_KEY_GROUP_NAME)
    mcast = fields.get(_INVITATION_KEY_MCAST)
    role = fields.get(_INVITATION_KEY_ROLE)
    expires = fields.get(_INVITATION_KEY_EXPIRY)
    invitee_iid = fields.get(_INVITATION_KEY_INVITEE_IID)
    nonce = fields.get(_INVITATION_KEY_NONCE)
    if type(group_id) is not str and type(group_id) is not bytes:
        raise MembershipError("invitation group_id must be a string or bytes")
    if isinstance(group_id, bytes):
        group_id = group_id.decode()
    if type(group_id) is not str or group_id == "":
        raise MembershipError("invitation group_id must be a non-empty string")
    if type(group_name) is not str or group_name == "":
        raise MembershipError("invitation group_name must be a non-empty string")
    if type(mcast) is not bytes or len(mcast) != 16:
        raise MembershipError("invitation mcast must be a 16-byte IPv6 address")
    if role not in _ROLE_FROM_UINT:
        raise MembershipError("invitation role must be 0 (member) or 1 (admin)")
    if type(expires) is not int or isinstance(expires, bool) or expires < 0:
        raise MembershipError("invitation expires must be a non-negative integer")
    if type(invitee_iid) is not bytes or len(invitee_iid) != 8:
        raise MembershipError("invitation invitee_iid must be 8 bytes")
    if type(nonce) is not bytes or len(nonce) != 8:
        raise MembershipError("invitation nonce must be 8 bytes")
    if invitee_iid != own_iid:
        raise MembershipError("invitation invitee_iid does not match this node")
    to_sign = sha256(cose_sig_structure(protected, payload)).digest()
    if not verify(inviter_pubkey, to_sign, signature):
        raise MembershipError("invitation signature verification failed")
    return GroupInvitationCose(
        group_id=group_id,
        group_name=group_name,
        mcast=str(IPv6Address(mcast)),
        role=_ROLE_FROM_UINT[role],  # type: ignore[arg-type]
        expires=expires,
        invitee_iid=invitee_iid,
        nonce=nonce,
        inviter_iid=kid,
        signature=signature,
    )


@dataclass(frozen=True)
class GroupRoster:
    """Authoritative membership used to check invite/remove authority."""

    owner: str
    admins: frozenset[str] = frozenset()
    members: frozenset[str] = frozenset()

    def can_invite(self, inviter: str, *, requested_role: str = "member") -> bool:
        """spec 18.8.2 roles table (L1129-1143): promotion/demotion of
        membership level is reserved to the owner, so an admin may mint only
        member-role invitations; admin-role invitations are owner-only."""
        if inviter == self.owner:
            return True
        if inviter in self.admins:
            return requested_role == "member"
        return False

    def can_remove(self, remover: str, *, target: str) -> bool:
        if remover == self.owner:
            return target != self.owner
        if remover in self.admins:
            return target != self.owner and target not in self.admins
        return False


def parse_removal(document: dict[str, Any]) -> GroupRemoval:
    if type(document) is not dict:
        raise MembershipError("removal must be a map")
    signature = document.get("signature")
    if type(signature) is not bytes:
        raise MembershipError("signature must be bytes")
    reason = document.get("reason")
    if reason is not None and type(reason) is not str:
        raise MembershipError("reason must be a string when present")
    return GroupRemoval(
        group_id=_require_str(document, "group_id"),
        removed_by=_require_str(document, "removed_by"),
        signature=signature,
        reason=reason,
    )
