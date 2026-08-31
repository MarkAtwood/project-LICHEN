# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""COSE_Sign1 invitation envelope codec (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

import cbor2
import pytest
from hashlib import sha256

from lichen.crypto.delegation_tokens import cose_sig_structure
from lichen.crypto.identity import Identity
from lichen.group_membership import (
    GroupInvitationCose,
    MembershipError,
    encode_invitation_cose,
    verify_invitation_cose,
)

INVITER = Identity.from_seed(b"\x26" * 32)
INVITEE_IID = bytes(range(0x40, 0x48))


def _envelope(
    *,
    invitee_iid: bytes = INVITEE_IID,
    inviter: Identity = INVITER,
    nonce: bytes = bytes(8),
) -> bytes:
    invitation = GroupInvitationCose(
        group_id="0200::abcd",
        group_name="Rescue Team",
        mcast="ff15::20",
        role="member",
        expires=600,
        invitee_iid=invitee_iid,
        nonce=nonce,
        inviter_iid=inviter.iid,
        signature=b"",
    )
    return encode_invitation_cose(invitation, inviter)


def test_round_trip_encodes_and_verifies() -> None:
    decoded = verify_invitation_cose(_envelope(), INVITER.pubkey, INVITEE_IID)
    assert decoded.group_id == "0200::abcd"
    assert decoded.group_name == "Rescue Team"
    assert decoded.mcast == "ff15::20"
    assert decoded.role == "member"
    assert decoded.expires == 600
    assert decoded.invitee_iid == INVITEE_IID
    assert decoded.nonce == bytes(8)
    assert decoded.inviter_iid == INVITER.iid


def test_protected_header_is_bstr_wrapped_alg_65537() -> None:
    envelope = _envelope()
    document = cbor2.loads(envelope)
    assert isinstance(document, list) and len(document) == 4
    protected = document[0]
    # canonical {1: -65537} = a1013a00010000; on the wire the COSE_Sign1
    # array carries it as a bstr, so the envelope hex contains 47a1013a00010000
    assert protected == bytes.fromhex("a1013a00010000")
    assert bytes.fromhex("47a1013a00010000") in envelope
    # kid is in the unprotected header (COSE label 4)
    assert document[1] == {4: INVITER.iid}


def test_signature_binds_sha256_of_sig_structure() -> None:
    from lichen.crypto.schnorr48 import verify

    document = cbor2.loads(_envelope())
    protected, _, payload, signature = document
    to_sign = sha256(cose_sig_structure(protected, payload)).digest()
    assert verify(INVITER.pubkey, to_sign, signature)


def test_wrong_alg_is_rejected() -> None:
    document = cbor2.loads(_envelope())
    document[0] = cbor2.dumps({1: -7}, canonical=True)
    with pytest.raises(MembershipError, match="alg"):
        verify_invitation_cose(cbor2.dumps(document), INVITER.pubkey, INVITEE_IID)


def test_payload_tamper_breaks_signature() -> None:
    document = cbor2.loads(_envelope())
    payload = cbor2.loads(document[2])
    payload[1] = "0200::evil"
    document[2] = cbor2.dumps(payload, canonical=True)
    with pytest.raises(MembershipError, match="signature"):
        verify_invitation_cose(cbor2.dumps(document), INVITER.pubkey, INVITEE_IID)


def test_trailing_bytes_after_envelope_are_rejected() -> None:
    envelope = _envelope()
    with pytest.raises(MembershipError, match="trailing"):
        verify_invitation_cose(envelope + b"\xde\xad\xbe\xef", INVITER.pubkey, INVITEE_IID)


def test_wrong_nonce_length_is_rejected() -> None:
    document = cbor2.loads(_envelope())
    payload = cbor2.loads(document[2])
    payload[7] = b"N"
    document[2] = cbor2.dumps(payload, canonical=True)
    with pytest.raises(MembershipError, match="nonce must be 8 bytes"):
        verify_invitation_cose(cbor2.dumps(document), INVITER.pubkey, INVITEE_IID)


def test_wire_types_follow_spec_table() -> None:
    # mcast is bstr(16), role is uint 0/1, group_id is tstr-or-bstr on the wire.
    document = cbor2.loads(_envelope())
    payload = cbor2.loads(document[2])
    from ipaddress import IPv6Address

    assert payload[3] == IPv6Address("ff15::20").packed
    assert payload[4] == 0
    assert payload[1] == "0200::abcd"


def test_role_uint_boundary_values_round_trip() -> None:
    decoded = verify_invitation_cose(_envelope(), INVITER.pubkey, INVITEE_IID)
    assert decoded.role == "member"
    admin = GroupInvitationCose(
        group_id="0200::abcd",
        group_name="Rescue Team",
        mcast="ff15::20",
        role="admin",
        expires=600,
        invitee_iid=INVITEE_IID,
        nonce=bytes(8),
        inviter_iid=INVITER.iid,
        signature=b"",
    )
    assert (
        verify_invitation_cose(encode_invitation_cose(admin, INVITER), INVITER.pubkey, INVITEE_IID).role
        == "admin"
    )


def test_invalid_role_uint_is_rejected() -> None:
    document = cbor2.loads(_envelope())
    payload = cbor2.loads(document[2])
    payload[4] = 2
    document[2] = cbor2.dumps(payload, canonical=True)
    with pytest.raises(MembershipError, match="role must be 0"):
        verify_invitation_cose(cbor2.dumps(document), INVITER.pubkey, INVITEE_IID)


def test_wrong_kid_is_rejected() -> None:
    document = cbor2.loads(_envelope())
    document[1] = {4: b"\x00" * 8}
    with pytest.raises(MembershipError, match="kid"):
        verify_invitation_cose(cbor2.dumps(document), INVITER.pubkey, INVITEE_IID)


def test_foreign_invitee_iid_is_rejected() -> None:
    document = cbor2.loads(_envelope())
    payload = cbor2.loads(document[2])
    payload[6] = b"\xee" * 8
    document[2] = cbor2.dumps(payload, canonical=True)
    with pytest.raises(MembershipError, match="invitee_iid"):
        verify_invitation_cose(cbor2.dumps(document), INVITER.pubkey, INVITEE_IID)


def test_verify_against_wrong_pubkey_fails() -> None:
    # kid binding rejects first: the wrong key's IID cannot match the kid.
    other = Identity.from_seed(b"\x27" * 32)
    with pytest.raises(MembershipError, match="kid does not match"):
        verify_invitation_cose(_envelope(), other.pubkey, INVITEE_IID)

    # If the envelope's kid is rewritten to the wrong key's IID, the
    # signature check rejects (the signature no longer verifies).
    document = cbor2.loads(_envelope())
    document[1] = {4: other.iid}
    with pytest.raises(MembershipError, match="signature"):
        verify_invitation_cose(cbor2.dumps(document), other.pubkey, INVITEE_IID)


def test_malformed_envelopes_are_rejected() -> None:
    with pytest.raises(MembershipError):
        verify_invitation_cose(b"", INVITER.pubkey, INVITEE_IID)
    with pytest.raises(MembershipError):
        verify_invitation_cose(cbor2.dumps([1, 2, 3]), INVITER.pubkey, INVITEE_IID)
    with pytest.raises(MembershipError):
        verify_invitation_cose("not bytes", INVITER.pubkey, INVITEE_IID)  # type: ignore[arg-type]
