# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Delegation Tokens COSE_Sign1 implementation (spec 18.8.6)."""

from __future__ import annotations

import dataclasses

import time

import cbor2
import pytest

from lichen.crypto import Identity
from lichen.crypto.delegation_tokens import (
    ADMIN_DELEGATABLE_SCOPE,
    COSE_ALG_LABEL,
    COSE_KID_LABEL,
    SCHNORR48_ED25519_ALG,
    VALID_SCOPE_MASK,
    DelegationScope,
    DelegationToken,
    DelegationTokenPayload,
    check_delegation_scope,
    cose_protected_header,
    create_delegation_token,
    decode_delegation_token,
    verify_delegation_token,
)


class TestDelegationScope:
    """Tests for DelegationScope enum."""

    def test_scope_values(self) -> None:
        """Test that scope bit values match spec."""
        assert int(DelegationScope.INVITE) == 0x01
        assert int(DelegationScope.REMOVE) == 0x02
        assert int(DelegationScope.DISTRIBUTE_KEY) == 0x04
        assert int(DelegationScope.REKEY) == 0x08
        assert int(DelegationScope.READ_MEMBERS) == 0x10

    def test_admin_delegatable_scope(self) -> None:
        """Test that admin delegatable scope is bits 0, 1, 4 (0x13)."""
        assert int(ADMIN_DELEGATABLE_SCOPE) == 0x13
        assert DelegationScope.INVITE in ADMIN_DELEGATABLE_SCOPE
        assert DelegationScope.REMOVE in ADMIN_DELEGATABLE_SCOPE
        assert DelegationScope.READ_MEMBERS in ADMIN_DELEGATABLE_SCOPE
        assert DelegationScope.DISTRIBUTE_KEY not in ADMIN_DELEGATABLE_SCOPE
        assert DelegationScope.REKEY not in ADMIN_DELEGATABLE_SCOPE

    def test_valid_scope_mask(self) -> None:
        """Test valid scope mask covers bits 0-4."""
        assert VALID_SCOPE_MASK == 0x1F


class TestDelegationTokenPayload:
    """Tests for DelegationTokenPayload dataclass."""

    def test_valid_payload(self) -> None:
        """Test creating a valid payload."""
        delegate = bytes(8)
        payload = DelegationTokenPayload(
            delegate=delegate,
            scope=int(DelegationScope.INVITE | DelegationScope.REMOVE),
            resource="team-alpha",
            expiry=int(time.time()) + 3600,
            seq=1,
        )
        assert payload.delegate == delegate
        assert payload.scope == 0x03
        assert payload.resource == "team-alpha"

    def test_invalid_delegate_length(self) -> None:
        """Test that short delegate IID is rejected."""
        with pytest.raises(ValueError, match="delegate must be 8 bytes"):
            DelegationTokenPayload(
                delegate=bytes(4),
                scope=int(DelegationScope.INVITE),
                resource="test",
                expiry=int(time.time()) + 3600,
                seq=1,
            )

    def test_invalid_scope_bits(self) -> None:
        """Test that invalid scope bits are rejected."""
        with pytest.raises(ValueError, match="Invalid scope bits"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=0x20,  # bit 5 is invalid
                resource="test",
                expiry=int(time.time()) + 3600,
                seq=1,
            )

    def test_empty_scope(self) -> None:
        """Test that empty scope is rejected."""
        with pytest.raises(ValueError, match="scope must grant at least one capability"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=0,
                resource="test",
                expiry=int(time.time()) + 3600,
                seq=1,
            )

    def test_empty_resource(self) -> None:
        """Test that empty resource is rejected."""
        with pytest.raises(ValueError, match="resource must be non-empty"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=int(DelegationScope.INVITE),
                resource="",
                expiry=int(time.time()) + 3600,
                seq=1,
            )

    def test_invalid_expiry(self) -> None:
        """Test that non-positive expiry is rejected."""
        with pytest.raises(ValueError, match="expiry must be positive"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=int(DelegationScope.INVITE),
                resource="test",
                expiry=0,
                seq=1,
            )

    def test_negative_seq(self) -> None:
        """Test that negative seq is rejected."""
        with pytest.raises(ValueError, match="seq must be non-negative"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=int(DelegationScope.INVITE),
                resource="test",
                expiry=int(time.time()) + 3600,
                seq=-1,
            )

    def test_cbor_roundtrip(self) -> None:
        """Test CBOR encode/decode roundtrip."""
        payload = DelegationTokenPayload(
            delegate=bytes(range(8)),
            scope=int(DelegationScope.INVITE | DelegationScope.READ_MEMBERS),
            resource="group-beta",
            expiry=1700000000,
            seq=100,
        )
        encoded = payload.to_cbor()
        decoded = DelegationTokenPayload.from_cbor(encoded)

        assert decoded.delegate == payload.delegate
        assert decoded.scope == payload.scope
        assert decoded.resource == payload.resource
        assert decoded.expiry == payload.expiry
        assert decoded.seq == payload.seq


class TestDelegationToken:
    """Tests for DelegationToken COSE_Sign1 wrapper."""

    @pytest.fixture
    def delegator_identity(self) -> Identity:
        """Create a delegator identity for testing."""
        return Identity.from_seed(bytes(range(32)))

    @pytest.fixture
    def delegate_identity(self) -> Identity:
        """Create a delegate identity for testing."""
        return Identity.from_seed(bytes([0xFF - i for i in range(32)]))

    @pytest.fixture
    def valid_token(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> DelegationToken:
        """Create a valid delegation token."""
        return create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE | DelegationScope.REMOVE,
            resource="team-alpha",
            expiry=int(time.time()) + 3600,
            seq=1,
        )

    def test_create_and_verify(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test creating and verifying a delegation token."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is True
        assert error is None

    def test_cose_sign1_roundtrip(self, valid_token: DelegationToken) -> None:
        """Test COSE_Sign1 encode/decode roundtrip."""
        encoded = valid_token.to_cose_sign1()
        decoded = decode_delegation_token(encoded)

        assert decoded.delegator_iid == valid_token.delegator_iid
        assert decoded.signature == valid_token.signature
        assert decoded.payload.delegate == valid_token.payload.delegate
        assert decoded.payload.scope == valid_token.payload.scope
        assert decoded.payload.resource == valid_token.payload.resource

    def test_protected_header_format(self) -> None:
        """Test protected header encodes correctly per spec."""
        protected = cose_protected_header()
        decoded = cbor2.loads(protected)
        assert decoded == {COSE_ALG_LABEL: SCHNORR48_ED25519_ALG}

    def test_cose_sign1_structure(self, valid_token: DelegationToken) -> None:
        """Test COSE_Sign1 structure matches spec."""
        encoded = valid_token.to_cose_sign1()
        cose_array = cbor2.loads(encoded)

        assert isinstance(cose_array, list)
        assert len(cose_array) == 4

        protected_bytes, unprotected, payload_bytes, signature = cose_array

        # Check protected header
        protected = cbor2.loads(protected_bytes)
        assert protected[COSE_ALG_LABEL] == SCHNORR48_ED25519_ALG

        # Check unprotected header has kid
        assert COSE_KID_LABEL in unprotected
        assert len(unprotected[COSE_KID_LABEL]) == 8

        # Check signature length
        assert len(signature) == 48

    def test_invalid_delegator_iid_length(self) -> None:
        """Test that wrong delegator_iid length is rejected."""
        with pytest.raises(ValueError, match="delegator_iid must be 8 bytes"):
            DelegationToken(
                payload=DelegationTokenPayload(
                    delegate=bytes(8),
                    scope=1,
                    resource="test",
                    expiry=int(time.time()) + 3600,
                    seq=1,
                ),
                delegator_iid=bytes(4),
                signature=bytes(48),
            )

    def test_invalid_signature_length(self) -> None:
        """Test that wrong signature length is rejected."""
        with pytest.raises(ValueError, match="signature must be 48 bytes"):
            DelegationToken(
                payload=DelegationTokenPayload(
                    delegate=bytes(8),
                    scope=1,
                    resource="test",
                    expiry=int(time.time()) + 3600,
                    seq=1,
                ),
                delegator_iid=bytes(8),
                signature=bytes(32),
            )


class TestVerification:
    """Tests for delegation token verification."""

    @pytest.fixture
    def delegator_identity(self) -> Identity:
        """Create a delegator identity for testing."""
        return Identity.from_seed(bytes(range(32)))

    @pytest.fixture
    def delegate_identity(self) -> Identity:
        """Create a delegate identity for testing."""
        return Identity.from_seed(bytes([0xFF - i for i in range(32)]))

    def test_expired_token(self, delegator_identity: Identity, delegate_identity: Identity) -> None:
        """Test that expired tokens are rejected."""
        past_time = int(time.time()) - 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=past_time,
            seq=1,
        )

        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "EXPIRED"

    def test_replay_detection(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that replay attacks are detected."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=5,
        )

        # Should fail if cached_seq >= seq
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            cached_seq=5,
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "REPLAY_DETECTED"

        # Should pass with lower cached_seq
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            cached_seq=4,
            is_delegator_owner=True,
        )
        assert valid is True
        assert error is None

    def test_delegator_iid_mismatch(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that wrong delegator pubkey is rejected."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Use different identity's pubkey
        wrong_identity = Identity.from_seed(bytes([0xAB] * 32))

        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=wrong_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "DELEGATOR_IID_MISMATCH"

    def test_delegate_mismatch(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that wrong delegate IID is rejected."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Use different delegate IID
        wrong_delegate = Identity.from_seed(bytes([0xCD] * 32))

        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=wrong_delegate.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "DELEGATE_MISMATCH"

    def test_tampered_signature(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that tampered signatures are rejected."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Tamper with signature
        tampered_sig = bytes([b ^ 0xFF for b in token.signature[:4]]) + token.signature[4:]
        tampered = DelegationToken(
            payload=token.payload,
            delegator_iid=token.delegator_iid,
            signature=tampered_sig,
        )

        valid, error = verify_delegation_token(
            tampered,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "SIGNATURE_INVALID"

    def test_admin_scope_exceeded(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that admin cannot delegate owner-only scopes."""
        future_time = int(time.time()) + 3600
        # Create token with owner-only scopes (distribute_key, rekey)
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.DISTRIBUTE_KEY | DelegationScope.REKEY,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Verify as admin (should fail)
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=False,  # Admin, not owner
        )
        assert valid is False
        assert error == "SCOPE_EXCEEDED"

        # Verify as owner (should succeed)
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,  # Owner
        )
        assert valid is True
        assert error is None

    def test_admin_can_delegate_allowed_scopes(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that admin can delegate invite, remove, read_members."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=ADMIN_DELEGATABLE_SCOPE,  # invite | remove | read_members
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Verify as admin (should succeed)
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=False,
        )
        assert valid is True
        assert error is None

    def test_resource_mismatch(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that token for group A is rejected when accessing group B."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="group-alpha",
            expiry=future_time,
            seq=1,
        )

        # Use token for group-alpha to access group-beta (should fail)
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="group-beta",  # Different resource
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "RESOURCE_MISMATCH"

        # Same resource should pass
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="group-alpha",  # Correct resource
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is True
        assert error is None


class TestCoseSign1Decoding:
    """Tests for COSE_Sign1 decoding error handling."""

    def test_invalid_array_length(self) -> None:
        """Test that non-4-element arrays are rejected."""
        bad_data = cbor2.dumps([b"protected", {}, b"payload"])
        with pytest.raises(ValueError, match="must be a 4-element array"):
            decode_delegation_token(bad_data)

    def test_wrong_algorithm(self) -> None:
        """Test that wrong algorithm is rejected."""
        # Create COSE_Sign1 with wrong algorithm
        protected = cbor2.dumps({COSE_ALG_LABEL: -7})  # ES256 instead
        payload = DelegationTokenPayload(
            delegate=bytes(8),
            scope=1,
            resource="test",
            expiry=int(time.time()) + 3600,
            seq=1,
        )
        cose_array = [protected, {COSE_KID_LABEL: bytes(8)}, payload.to_cbor(), bytes(48)]
        bad_data = cbor2.dumps(cose_array)

        with pytest.raises(ValueError, match="Algorithm must be"):
            decode_delegation_token(bad_data)

    def test_invalid_kid_length(self) -> None:
        """Test that wrong kid length is rejected."""
        protected = cose_protected_header()
        payload = DelegationTokenPayload(
            delegate=bytes(8),
            scope=1,
            resource="test",
            expiry=int(time.time()) + 3600,
            seq=1,
        )
        cose_array = [protected, {COSE_KID_LABEL: bytes(4)}, payload.to_cbor(), bytes(48)]
        bad_data = cbor2.dumps(cose_array)

        with pytest.raises(ValueError, match="kid in unprotected header must be 8-byte IID"):
            decode_delegation_token(bad_data)


class TestCheckDelegationScope:
    """Tests for check_delegation_scope helper."""

    def test_single_scope_match(self) -> None:
        """Test checking single scope match."""
        identity = Identity.from_seed(bytes(range(32)))
        delegate = Identity.from_seed(bytes([0xFF] * 32))
        token = create_delegation_token(
            identity=identity,
            delegate_iid=delegate.iid,
            scope=DelegationScope.INVITE,
            resource="test",
            expiry=int(time.time()) + 3600,
            seq=1,
        )

        assert check_delegation_scope(token, DelegationScope.INVITE) is True
        assert check_delegation_scope(token, DelegationScope.REMOVE) is False

    def test_multi_scope_match(self) -> None:
        """Test checking multiple scope match."""
        identity = Identity.from_seed(bytes(range(32)))
        delegate = Identity.from_seed(bytes([0xFF] * 32))
        token = create_delegation_token(
            identity=identity,
            delegate_iid=delegate.iid,
            scope=DelegationScope.INVITE | DelegationScope.REMOVE | DelegationScope.READ_MEMBERS,
            resource="test",
            expiry=int(time.time()) + 3600,
            seq=1,
        )

        # Single scopes
        assert check_delegation_scope(token, DelegationScope.INVITE) is True
        assert check_delegation_scope(token, DelegationScope.REMOVE) is True
        assert check_delegation_scope(token, DelegationScope.READ_MEMBERS) is True
        assert check_delegation_scope(token, DelegationScope.DISTRIBUTE_KEY) is False

        # Combined scopes
        assert (
            check_delegation_scope(token, DelegationScope.INVITE | DelegationScope.REMOVE) is True
        )
        assert (
            check_delegation_scope(token, DelegationScope.INVITE | DelegationScope.DISTRIBUTE_KEY)
            is False
        )


class TestPayloadIntegerKeys:
    """Tests verifying payload uses integer keys per spec."""

    def test_payload_uses_integer_keys(self) -> None:
        """Verify CBOR payload uses integer keys (1-5) per spec 18.8.6."""
        payload = DelegationTokenPayload(
            delegate=bytes(range(8)),
            scope=int(DelegationScope.INVITE),
            resource="team-alpha",
            expiry=1700000000,
            seq=42,
        )
        encoded = payload.to_cbor()
        decoded = cbor2.loads(encoded)

        # Spec says:
        # 1: delegate (bstr 8)
        # 2: scope (uint)
        # 3: resource (tstr)
        # 4: expiry (uint)
        # 5: seq (uint)
        assert 1 in decoded
        assert 2 in decoded
        assert 3 in decoded
        assert 4 in decoded
        assert 5 in decoded

        assert decoded[1] == bytes(range(8))
        assert decoded[2] == int(DelegationScope.INVITE)
        assert decoded[3] == "team-alpha"
        assert decoded[4] == 1700000000
        assert decoded[5] == 42


# ─── Wire-bytes verification (RFC 9052 4.4, C/Rust interop) ──────────────────


def _foreign_delegation_envelope(identity, payload_map):
    """Build a COSE_Sign1 envelope as a non-Python encoder might: payload map
    in an order this module never emits, plus an extra protected-header entry.
    Signed over the transported bstrs with schnorr48 directly (independent of
    the module's own encoding helpers)."""
    from hashlib import sha256

    from lichen.crypto import schnorr48

    payload = cbor2.dumps(payload_map)
    protected = cbor2.dumps({1: SCHNORR48_ED25519_ALG, 99: b"x"})
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = schnorr48.sign(identity.privkey, identity.pubkey, sha256(sig_structure).digest())
    return cbor2.dumps([protected, {COSE_KID_LABEL: identity.iid}, payload, signature])


def test_delegation_token_verified_over_received_wire_bytes() -> None:
    delegator = Identity.from_seed(bytes(range(32)))
    delegate = Identity.from_seed(bytes([0xFF - i for i in range(32)]))
    expiry = int(time.time()) + 3600
    # Foreign key order (5,4,3,2,1) the module's to_cbor() never emits.
    payload_map = {
        5: 9,
        4: expiry,
        3: "team-alpha",
        2: int(DelegationScope.INVITE),
        1: delegate.iid,
    }
    envelope = _foreign_delegation_envelope(delegator, payload_map)
    # Guard the differential: module re-encode would differ, so the old
    # re-encode-verify path could never pass here.
    assert cbor2.dumps(payload_map) != DelegationTokenPayload(
        delegate=delegate.iid,
        scope=int(DelegationScope.INVITE),
        resource="team-alpha",
        expiry=expiry,
        seq=9,
    ).to_cbor()
    token = decode_delegation_token(envelope)
    valid, error = verify_delegation_token(
        token,
        delegator_pubkey=delegator.pubkey,
        delegate_iid=delegate.iid,
        expected_resource="team-alpha",
        current_time=int(time.time()),
        is_delegator_owner=True,
    )
    assert (valid, error) == (True, None)


def test_prefix_delegation_token_verified_over_received_wire_bytes() -> None:
    from lichen.crypto.delegation_tokens import (
        PrefixDelegationToken,
        verify_prefix_delegation_token,
    )

    root = Identity.from_seed(bytes(range(32)))
    delegate = Identity.from_seed(bytes([0xFF - i for i in range(32)]))
    expiry = int(time.time()) + 3600
    # Foreign key order (6..1) the module's to_cbor() never emits.
    payload_map = {6: 0, 5: 3, 4: expiry, 3: delegate.iid, 2: 64, 1: b"\x02" + b"\x00" * 7}
    envelope = _foreign_delegation_envelope(root, payload_map)
    token = PrefixDelegationToken.from_cose_sign1(envelope)
    valid, error = verify_prefix_delegation_token(
        token,
        delegator_pubkey=root.pubkey,
        delegate_iid=delegate.iid,
        current_time=int(time.time()),
    )
    assert (valid, error) == (True, None)


def test_capability_announcement_verified_over_received_wire_bytes() -> None:
    """CapabilityAnnouncement retains+verifies wire bstrs (RFC 9052 4.4)."""
    from hashlib import sha256

    from lichen.crypto import schnorr48
    from lichen.crypto.capability_announcements import (
        Capability,
        CapabilityAnnouncement,
        CapabilityPayload,
        verify_capability_announcement,
    )

    identity = Identity.from_seed(bytes(range(32)))
    expiry = int(time.time()) + 3600
    # Foreign key order (6..1) the module's to_cbor() never emits.
    payload_map = {6: identity.iid, 5: 7, 4: expiry, 3: 64, 2: bytes(8), 1: int(Capability.EGRESS)}
    payload = cbor2.dumps(payload_map)
    protected = cbor2.dumps({1: SCHNORR48_ED25519_ALG, 99: b"x"})
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = schnorr48.sign(identity.privkey, identity.pubkey, sha256(sig_structure).digest())
    envelope = cbor2.dumps([protected, {COSE_KID_LABEL: identity.iid}, payload, signature])
    # Guard the differential: module re-encode would differ.
    assert payload != CapabilityPayload(
        capabilities=int(Capability.EGRESS),
        prefix=bytes(8),
        prefix_len=64,
        expiry=expiry,
        seq=7,
        announcer_iid=identity.iid,
    ).to_cbor()
    announcement = CapabilityAnnouncement.from_cose_sign1(envelope)
    valid, error = verify_capability_announcement(
        announcement=announcement,
        pubkey=identity.pubkey,
        current_time=int(time.time()),
    )
    assert (valid, error) == (True, None)


# ─── Wire-bstr/payload consistency + immutability (2vp1) ─────────────────────


def _delegation_token() -> DelegationToken:
    delegator = Identity.from_seed(bytes(range(32)))
    delegate = Identity.from_seed(bytes([0xFF - i for i in range(32)]))
    return create_delegation_token(
        delegator, delegate.iid, DelegationScope.INVITE, "team-alpha",
        int(time.time()) + 3600, 1,
    )


def test_delegation_token_replace_desync_rejected() -> None:
    token = _delegation_token()
    evil = DelegationTokenPayload(
        delegate=token.payload.delegate, scope=VALID_SCOPE_MASK,
        resource=token.payload.resource, expiry=token.payload.expiry, seq=2,
    )
    with pytest.raises(ValueError, match="do not decode"):
        dataclasses.replace(token, payload=evil)


def test_delegation_token_mismatched_wire_bytes_rejected() -> None:
    token = _delegation_token()
    other = DelegationTokenPayload(
        delegate=token.payload.delegate, scope=VALID_SCOPE_MASK,
        resource=token.payload.resource, expiry=token.payload.expiry, seq=2,
    ).to_cbor()
    with pytest.raises(ValueError, match="do not decode"):
        DelegationToken(
            payload=token.payload, delegator_iid=token.delegator_iid,
            signature=token.signature, protected_bytes=token.protected_bytes,
            payload_bytes=other,
        )


def test_prefix_delegation_token_mismatched_wire_bytes_rejected() -> None:
    from ipaddress import IPv6Address

    from lichen.crypto.delegation_tokens import (
        PrefixDelegationToken,
        PrefixDelegationTokenPayload,
        create_prefix_delegation_token,
    )

    root = Identity.from_seed(bytes(range(32)))
    delegate = Identity.from_seed(bytes([0xFF - i for i in range(32)]))
    expiry = int(time.time()) + 3600
    token = create_prefix_delegation_token(
        root, delegate.iid, IPv6Address("0200::"), 64, expiry, 1
    )
    other = PrefixDelegationTokenPayload(
        prefix=bytes(8), prefix_len=64, delegate_iid=delegate.iid,
        expiry=expiry, delegation_seq=2, flags=0,
    ).to_cbor()
    with pytest.raises(ValueError, match="do not decode"):
        PrefixDelegationToken(
            payload=token.payload, delegator_iid=token.delegator_iid,
            signature=token.signature, protected_bytes=token.protected_bytes,
            payload_bytes=other,
        )


def test_delegation_token_is_frozen() -> None:
    token = _delegation_token()
    with pytest.raises(dataclasses.FrozenInstanceError):
        token.signature = b"\x00" * 48
    with pytest.raises(dataclasses.FrozenInstanceError):
        token.payload.scope = VALID_SCOPE_MASK


def test_prefix_token_garbage_wire_bytes_raise_valueerror() -> None:
    # Non-map payload_bytes must surface as ValueError, not IndexError leaking
    # from the lenient from_cbor (2vp1 review finding).
    from lichen.crypto.delegation_tokens import PrefixDelegationToken, PrefixDelegationTokenPayload

    delegate = Identity.from_seed(bytes(range(32)))
    payload = PrefixDelegationTokenPayload(
        prefix=bytes(8), prefix_len=64, delegate_iid=delegate.iid,
        expiry=int(time.time()) + 3600, delegation_seq=1, flags=0,
    )
    with pytest.raises(ValueError, match="do not decode"):
        PrefixDelegationToken(
            payload=payload, delegator_iid=bytes(8), signature=bytes(48),
            protected_bytes=cbor2.dumps({1: SCHNORR48_ED25519_ALG}),
            payload_bytes=cbor2.dumps([1, 2]),
        )


def test_prefix_token_truncated_wire_bytes_raise_valueerror() -> None:
    # Truncated (undecodable) payload_bytes must surface as ValueError, not a
    # raw cbor2.CBORDecodeError (round-2 review: CBORDecodeError is not a
    # ValueError subclass in cbor2 5.9.0).
    from lichen.crypto.delegation_tokens import PrefixDelegationToken, PrefixDelegationTokenPayload

    delegate = Identity.from_seed(bytes(range(32)))
    payload = PrefixDelegationTokenPayload(
        prefix=bytes(8), prefix_len=64, delegate_iid=delegate.iid,
        expiry=int(time.time()) + 3600, delegation_seq=1, flags=0,
    )
    with pytest.raises(ValueError, match="do not decode"):
        PrefixDelegationToken(
            payload=payload, delegator_iid=bytes(8), signature=bytes(48),
            protected_bytes=cbor2.dumps({1: SCHNORR48_ED25519_ALG}),
            payload_bytes=b"\xa1\x01",  # map(1) header, truncated value
        )


def test_prefix_from_cbor_rejects_non_map() -> None:
    # A non-map payload must surface as TypeError (mirroring the sibling
    # DelegationTokenPayload guard), not an IndexError from list indexing.
    from lichen.crypto.delegation_tokens import PrefixDelegationTokenPayload

    with pytest.raises(TypeError, match="CBOR map"):
        PrefixDelegationTokenPayload.from_cbor(cbor2.dumps([1, 2]))
