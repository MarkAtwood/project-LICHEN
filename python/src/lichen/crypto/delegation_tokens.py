# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Delegation Tokens using COSE_Sign1 per spec section 18.8.6.

Delegation tokens allow owners and admins to grant specific capabilities to
other nodes without transferring full role privileges. Tokens are COSE_Sign1
structures signed by the delegator using Schnorr48-Ed25519.

COSE Algorithm: Schnorr48-Ed25519 (algorithm ID -65537)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
from hashlib import sha256
from ipaddress import IPv6Address
from typing import TYPE_CHECKING

import cbor2

from . import schnorr48
from .identity import Identity, _pubkey_to_iid

if TYPE_CHECKING:
    pass

# COSE algorithm ID for Schnorr48-Ed25519 (private use range)
SCHNORR48_ED25519_ALG = -65537

# COSE header labels
COSE_ALG_LABEL = 1  # Algorithm
COSE_KID_LABEL = 4  # Key ID


class DelegationScope(IntFlag):
    """Delegation capability bits per spec section 18.8.6.

    | Bit | Value | Capability | Owner | Admin |
    |-----|-------|------------|-------|-------|
    | 0 | 0x01 | invite | Yes | Yes |
    | 1 | 0x02 | remove | Yes | Yes |
    | 2 | 0x04 | distribute_key | Yes | No |
    | 3 | 0x08 | rekey | Yes | No |
    | 4 | 0x10 | read_members | Yes | Yes |
    """

    INVITE = 1 << 0  # 0x01 - Can invite members
    REMOVE = 1 << 1  # 0x02 - Can remove members
    DISTRIBUTE_KEY = 1 << 2  # 0x04 - Can distribute group key
    REKEY = 1 << 3  # 0x08 - Can rekey the group
    READ_MEMBERS = 1 << 4  # 0x10 - Can read membership list


# Scopes that admins can delegate (bits 0, 1, 4 = 0x13)
ADMIN_DELEGATABLE_SCOPE = (
    DelegationScope.INVITE | DelegationScope.REMOVE | DelegationScope.READ_MEMBERS
)

# Valid scope bits (0-4)
VALID_SCOPE_MASK = 0x1F


# Payload map keys (integer keys per spec to minimize size)
_PAYLOAD_DELEGATE = 1
_PAYLOAD_SCOPE = 2
_PAYLOAD_RESOURCE = 3
_PAYLOAD_EXPIRY = 4
_PAYLOAD_SEQ = 5


def _encode_protected_header() -> bytes:
    """Encode the protected header for COSE_Sign1.

    Returns:
        CBOR-encoded protected header bytes: {1: -65537} (alg: Schnorr48-Ed25519)
    """
    return cbor2.dumps({COSE_ALG_LABEL: SCHNORR48_ED25519_ALG})


def _build_sig_structure(protected: bytes, payload: bytes) -> bytes:
    """Build COSE Sig_structure per RFC 9052 section 4.4.

    Sig_structure = [
        "Signature1",     ; context string
        protected,        ; protected header bytes
        h'',              ; external_aad (empty)
        payload           ; payload bytes
    ]

    Returns:
        CBOR-encoded Sig_structure
    """
    sig_structure = [
        "Signature1",  # context string
        protected,  # protected header (already CBOR-encoded)
        b"",  # external_aad (empty)
        payload,  # payload bytes
    ]
    return cbor2.dumps(sig_structure)


@dataclass
class DelegationTokenPayload:
    """Delegation token payload per spec section 18.8.6.

    Attributes:
        delegate: 8-byte IID of the delegate node
        scope: Bitmask of delegated capabilities (see DelegationScope enum)
        resource: Group ID or resource path
        expiry: Unix timestamp when token expires
        seq: Strictly increasing sequence number for replay protection
    """

    delegate: bytes
    scope: int
    resource: str
    expiry: int
    seq: int

    def __post_init__(self) -> None:
        # Validate delegate IID
        if len(self.delegate) != 8:
            raise ValueError(f"delegate must be 8 bytes, got {len(self.delegate)}")

        # Validate scope bits (only bits 0-4 are valid)
        if self.scope & ~VALID_SCOPE_MASK:
            raise ValueError(f"Invalid scope bits (only bits 0-4 allowed), got {self.scope}")

        if self.scope == 0:
            raise ValueError("scope must grant at least one capability")

        # Validate resource
        if not self.resource:
            raise ValueError("resource must be non-empty")

        # Validate expiry is positive
        if self.expiry <= 0:
            raise ValueError(f"expiry must be positive, got {self.expiry}")

        # Validate seq is non-negative
        if self.seq < 0:
            raise ValueError(f"seq must be non-negative, got {self.seq}")

    def to_cbor(self) -> bytes:
        """Encode payload as CBOR map with integer keys."""
        payload_map = {
            _PAYLOAD_DELEGATE: self.delegate,
            _PAYLOAD_SCOPE: self.scope,
            _PAYLOAD_RESOURCE: self.resource,
            _PAYLOAD_EXPIRY: self.expiry,
            _PAYLOAD_SEQ: self.seq,
        }
        return cbor2.dumps(payload_map)

    @classmethod
    def from_cbor(cls, data: bytes) -> DelegationTokenPayload:
        """Decode payload from CBOR bytes.

        Raises:
            TypeError: If the payload is not a CBOR map or any field has the
                wrong wire type (bool is rejected for integer fields, and
                bytearray/str are rejected where bytes are required).
            KeyError: If a required field is missing.
        """
        payload_map = cbor2.loads(data)
        if not isinstance(payload_map, dict):
            raise TypeError("payload must be a CBOR map")
        delegate = payload_map[_PAYLOAD_DELEGATE]
        scope = payload_map[_PAYLOAD_SCOPE]
        resource = payload_map[_PAYLOAD_RESOURCE]
        expiry = payload_map[_PAYLOAD_EXPIRY]
        seq = payload_map[_PAYLOAD_SEQ]
        if type(delegate) is not bytes:
            raise TypeError("delegate must be bytes")
        if type(scope) is not int:
            raise TypeError("scope must be an integer")
        if type(resource) is not str:
            raise TypeError("resource must be a string")
        if type(expiry) is not int:
            raise TypeError("expiry must be an integer")
        if type(seq) is not int:
            raise TypeError("seq must be an integer")
        return cls(
            delegate=delegate,
            scope=scope,
            resource=resource,
            expiry=expiry,
            seq=seq,
        )


@dataclass
class DelegationToken:
    """COSE_Sign1 delegation token per spec section 18.8.6.

    COSE_Sign1 structure:
    [
        protected,          ; {1: -65537} encoded
        {4: <delegator-iid>}, ; unprotected: kid
        payload,            ; CBOR-encoded DelegationTokenPayload
        signature           ; 48-byte Schnorr48 signature
    ]

    Attributes:
        payload: The token payload containing delegation details
        delegator_iid: 8-byte IID of the delegator (from unprotected header)
        signature: 48-byte Schnorr48 signature
    """

    payload: DelegationTokenPayload
    delegator_iid: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if len(self.delegator_iid) != 8:
            raise ValueError(f"delegator_iid must be 8 bytes, got {len(self.delegator_iid)}")
        if len(self.signature) != 48:
            raise ValueError(f"signature must be 48 bytes, got {len(self.signature)}")

    def to_cose_sign1(self) -> bytes:
        """Encode as COSE_Sign1 structure.

        Returns:
            CBOR-encoded COSE_Sign1 array
        """
        protected = _encode_protected_header()
        unprotected = {COSE_KID_LABEL: self.delegator_iid}
        payload_bytes = self.payload.to_cbor()

        cose_sign1 = [protected, unprotected, payload_bytes, self.signature]
        return cbor2.dumps(cose_sign1)

    @classmethod
    def from_cose_sign1(cls, data: bytes) -> DelegationToken:
        """Decode from COSE_Sign1 structure.

        Args:
            data: CBOR-encoded COSE_Sign1 array

        Returns:
            DelegationToken

        Raises:
            ValueError: If structure is invalid
        """
        cose_array = cbor2.loads(data)

        if not isinstance(cose_array, list) or len(cose_array) != 4:
            raise ValueError("COSE_Sign1 must be a 4-element array")

        protected_bytes, unprotected, payload_bytes, signature = cose_array

        # Validate protected header
        protected = cbor2.loads(protected_bytes)
        if protected.get(COSE_ALG_LABEL) != SCHNORR48_ED25519_ALG:
            raise ValueError(
                f"Algorithm must be {SCHNORR48_ED25519_ALG}, got {protected.get(COSE_ALG_LABEL)}"
            )

        # Extract delegator IID from unprotected header
        delegator_iid = unprotected.get(COSE_KID_LABEL)
        if not isinstance(delegator_iid, bytes) or len(delegator_iid) != 8:
            raise ValueError("kid in unprotected header must be 8-byte IID")

        # Decode payload
        payload = DelegationTokenPayload.from_cbor(payload_bytes)

        # SECURITY: Validate signature is bytes before passing to constructor
        if not isinstance(signature, bytes):
            raise ValueError("signature must be bytes")

        return cls(payload=payload, delegator_iid=delegator_iid, signature=signature)


def create_delegation_token(
    identity: Identity,
    delegate_iid: bytes,
    scope: DelegationScope | int,
    resource: str,
    expiry: int,
    seq: int,
) -> DelegationToken:
    """Create a signed delegation token.

    Args:
        identity: The delegator's identity (contains signing key)
        delegate_iid: 8-byte IID of the node receiving the delegation
        scope: Bitmask of capabilities being delegated
        resource: Group ID or resource path
        expiry: Unix timestamp when token expires
        seq: Strictly increasing sequence number

    Returns:
        Signed DelegationToken ready for transmission
    """
    payload = DelegationTokenPayload(
        delegate=delegate_iid,
        scope=int(scope),
        resource=resource,
        expiry=expiry,
        seq=seq,
    )

    # Build COSE Sig_structure
    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)

    # Sign SHA-256 hash of Sig_structure with Schnorr48
    to_sign = sha256(sig_structure).digest()
    signature = schnorr48.sign(identity.privkey, identity.pubkey, to_sign)

    return DelegationToken(payload=payload, delegator_iid=identity.iid, signature=signature)


def verify_delegation_token(
    token: DelegationToken,
    delegator_pubkey: bytes,
    delegate_iid: bytes,
    expected_resource: str,
    current_time: int,
    cached_seq: int | None = None,
    is_delegator_owner: bool = False,
) -> tuple[bool, str | None]:
    """Verify a delegation token.

    Performs all validation steps from spec section 18.8.6:
    1. Verify signature using Schnorr48 and provided pubkey
    2. Verify delegator_iid matches derived IID from pubkey
    3. Verify delegate matches the node exercising the capability
    4. Verify resource matches the resource being accessed
    5. Verify expiry > current_time
    6. Verify seq > cached_seq (if provided)
    7. Verify scope is valid (bits 0-4 only)
    8. Verify delegator's role permits the scope (admin cannot delegate bits 2, 3)

    Args:
        token: The delegation token to verify
        delegator_pubkey: 32-byte Ed25519 public key of the delegator
        delegate_iid: 8-byte IID of the node exercising the delegation
        expected_resource: The resource (group ID) being accessed
        current_time: Current Unix timestamp
        cached_seq: Previously cached sequence number (optional)
        is_delegator_owner: True if delegator is the group owner

    Returns:
        (valid, error): Tuple of (True, None) if valid, or (False, error_string)
    """
    payload = token.payload

    # Step 7: Verify scope bits are valid (only bits 0-4)
    if payload.scope & ~VALID_SCOPE_MASK:
        return False, "INVALID_SCOPE_BITS"

    if payload.scope == 0:
        return False, "EMPTY_SCOPE"

    # Step 2: Verify delegator_iid matches derived IID from pubkey
    derived_iid = _pubkey_to_iid(delegator_pubkey)
    if token.delegator_iid != derived_iid:
        return False, "DELEGATOR_IID_MISMATCH"

    # Step 1: Verify signature
    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)
    to_verify = sha256(sig_structure).digest()

    if not schnorr48.verify(delegator_pubkey, to_verify, token.signature):
        return False, "SIGNATURE_INVALID"

    # Step 3: Verify delegate matches the exercising node
    if payload.delegate != delegate_iid:
        return False, "DELEGATE_MISMATCH"

    # SECURITY: Step 4: Verify resource matches the resource being accessed
    # This prevents cross-resource token reuse (e.g., token for group A
    # being used to access group B)
    if payload.resource != expected_resource:
        return False, "RESOURCE_MISMATCH"

    # Step 5: Verify expiry > current_time
    if payload.expiry <= current_time:
        return False, "EXPIRED"

    # Step 6: Verify seq > cached_seq
    if cached_seq is not None and payload.seq <= cached_seq:
        return False, "REPLAY_DETECTED"

    # Step 8: Verify delegator's role permits the scope
    # Admins can only delegate bits 0, 1, 4 (invite, remove, read_members)
    if not is_delegator_owner:
        owner_only_bits = DelegationScope.DISTRIBUTE_KEY | DelegationScope.REKEY
        if payload.scope & int(owner_only_bits):
            return False, "SCOPE_EXCEEDED"

    return True, None


def check_delegation_scope(token: DelegationToken, required_scope: DelegationScope | int) -> bool:
    """Check if a token grants the required scope.

    Args:
        token: The delegation token
        required_scope: The capability being exercised

    Returns:
        True if the token grants all bits in required_scope
    """
    return (token.payload.scope & int(required_scope)) == int(required_scope)


def decode_delegation_token(data: bytes) -> DelegationToken:
    """Decode a COSE_Sign1 delegation token from bytes.

    This is a convenience wrapper around DelegationToken.from_cose_sign1().

    Args:
        data: CBOR-encoded COSE_Sign1 structure

    Returns:
        Decoded DelegationToken
    """
    return DelegationToken.from_cose_sign1(data)


# Prefix delegation payload map keys (integer keys per spec to minimize size)
_PREFIX_PAYLOAD_PREFIX = 1
_PREFIX_PAYLOAD_PREFIX_LEN = 2
_PREFIX_PAYLOAD_DELEGATE = 3
_PREFIX_PAYLOAD_EXPIRY = 4
_PREFIX_PAYLOAD_SEQ = 5
_PREFIX_PAYLOAD_FLAGS = 6

# Delegation flags per spec section 8.7.2
DELEGATION_FLAG_EXTERNAL = 1 << 0  # E: delegate may set Transit E flag
DELEGATION_RESERVED_FLAG_MASK = 0xFE  # Bits 1-7 reserved, MUST be zero


@dataclass
class PrefixDelegationTokenPayload:
    """Prefix delegation token payload per spec/05-routing.md section 8.7.2.

    Attributes:
        prefix: Prefix bytes, ceil(prefix_len/8), zero-padded
        prefix_len: Prefix length in bits (0-128)
        delegate_iid: 8-byte IID of the authorized delegate
        expiry: Unix timestamp when delegation expires
        delegation_seq: Monotonic sequence for replay protection
        flags: Delegation flags (bit 0 = E/external, bits 1-7 reserved zero)
    """

    prefix: bytes
    prefix_len: int
    delegate_iid: bytes
    expiry: int
    delegation_seq: int
    flags: int

    def __post_init__(self) -> None:
        if not isinstance(self.prefix, bytes):
            raise ValueError("prefix must be bytes")
        if not isinstance(self.prefix_len, int) or not 0 <= self.prefix_len <= 128:
            raise ValueError(f"prefix_len must be 0-128, got {self.prefix_len}")
        if len(self.prefix) != (self.prefix_len + 7) // 8:
            raise ValueError(
                f"prefix must be ceil(prefix_len/8) bytes: expected "
                f"{(self.prefix_len + 7) // 8}, got {len(self.prefix)}"
            )
        if len(self.delegate_iid) != 8:
            raise ValueError(f"delegate_iid must be 8 bytes, got {len(self.delegate_iid)}")
        if self.expiry <= 0:
            raise ValueError(f"expiry must be positive, got {self.expiry}")
        if self.delegation_seq < 0:
            raise ValueError(f"delegation_seq must be non-negative, got {self.delegation_seq}")
        if self.flags & DELEGATION_RESERVED_FLAG_MASK:
            raise ValueError(f"reserved flag bits (1-7) must be zero, got {self.flags:#x}")

    def to_cbor(self) -> bytes:
        """Encode payload as CBOR map with integer keys."""
        payload_map = {
            _PREFIX_PAYLOAD_PREFIX: self.prefix,
            _PREFIX_PAYLOAD_PREFIX_LEN: self.prefix_len,
            _PREFIX_PAYLOAD_DELEGATE: self.delegate_iid,
            _PREFIX_PAYLOAD_EXPIRY: self.expiry,
            _PREFIX_PAYLOAD_SEQ: self.delegation_seq,
            _PREFIX_PAYLOAD_FLAGS: self.flags,
        }
        return cbor2.dumps(payload_map)

    @classmethod
    def from_cbor(cls, data: bytes) -> PrefixDelegationTokenPayload:
        """Decode payload from CBOR bytes."""
        payload_map = cbor2.loads(data)
        return cls(
            prefix=payload_map[_PREFIX_PAYLOAD_PREFIX],
            prefix_len=payload_map[_PREFIX_PAYLOAD_PREFIX_LEN],
            delegate_iid=payload_map[_PREFIX_PAYLOAD_DELEGATE],
            expiry=payload_map[_PREFIX_PAYLOAD_EXPIRY],
            delegation_seq=payload_map[_PREFIX_PAYLOAD_SEQ],
            flags=payload_map[_PREFIX_PAYLOAD_FLAGS],
        )


@dataclass
class PrefixDelegationToken:
    """COSE_Sign1 prefix delegation token per spec/05-routing.md 8.7.2.

    Same COSE_Sign1 envelope as the group delegation token: protected header
    {1: -65537} (Schnorr48-Ed25519), unprotected {4: delegator IID}, payload,
    48-byte Schnorr48 signature.
    """

    payload: PrefixDelegationTokenPayload
    delegator_iid: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if len(self.delegator_iid) != 8:
            raise ValueError(f"delegator_iid must be 8 bytes, got {len(self.delegator_iid)}")
        if len(self.signature) != 48:
            raise ValueError(f"signature must be 48 bytes, got {len(self.signature)}")

    def to_cose_sign1(self) -> bytes:
        """Encode as COSE_Sign1 structure."""
        protected = _encode_protected_header()
        unprotected = {COSE_KID_LABEL: self.delegator_iid}
        payload_bytes = self.payload.to_cbor()
        cose_sign1 = [protected, unprotected, payload_bytes, self.signature]
        return cbor2.dumps(cose_sign1)

    @classmethod
    def from_cose_sign1(cls, data: bytes) -> PrefixDelegationToken:
        """Decode from COSE_Sign1 structure.

        Raises:
            ValueError: If structure is invalid
        """
        cose_array = cbor2.loads(data)

        if not isinstance(cose_array, list) or len(cose_array) != 4:
            raise ValueError("COSE_Sign1 must be a 4-element array")

        protected_bytes, unprotected, payload_bytes, signature = cose_array

        protected = cbor2.loads(protected_bytes)
        if protected.get(COSE_ALG_LABEL) != SCHNORR48_ED25519_ALG:
            raise ValueError(
                f"Algorithm must be {SCHNORR48_ED25519_ALG}, got {protected.get(COSE_ALG_LABEL)}"
            )

        delegator_iid = unprotected.get(COSE_KID_LABEL)
        if not isinstance(delegator_iid, bytes) or len(delegator_iid) != 8:
            raise ValueError("kid in unprotected header must be 8-byte IID")

        payload = PrefixDelegationTokenPayload.from_cbor(payload_bytes)

        if not isinstance(signature, bytes):
            raise ValueError("signature must be bytes")

        return cls(payload=payload, delegator_iid=delegator_iid, signature=signature)


def _masked_prefix_bytes(prefix: IPv6Address, prefix_len: int) -> bytes:
    """Encode the ceil(prefix_len/8) prefix octets with host bits cleared."""
    host_octets = (prefix_len + 7) // 8
    masked = bytearray(prefix.packed[:host_octets])
    rem = prefix_len % 8
    if rem:
        masked[-1] &= (0xFF << (8 - rem)) & 0xFF
    return bytes(masked)


def create_prefix_delegation_token(
    identity: Identity,
    delegate_iid: bytes,
    prefix: IPv6Address,
    prefix_len: int,
    expiry: int,
    delegation_seq: int,
    external: bool = False,
) -> PrefixDelegationToken:
    """Create a signed prefix delegation token (spec section 8.7.2).

    Args:
        identity: The delegator's (root's) identity
        delegate_iid: 8-byte IID of the node receiving the delegation
        prefix: Delegated prefix; host bits beyond prefix_len are cleared
        prefix_len: Prefix length in bits (0-128)
        expiry: Unix timestamp when delegation expires
        delegation_seq: Strictly increasing sequence per prefix
        external: True to grant external reachability (Transit E flag)

    Returns:
        Signed PrefixDelegationToken ready for delivery
    """
    payload = PrefixDelegationTokenPayload(
        prefix=_masked_prefix_bytes(prefix, prefix_len),
        prefix_len=prefix_len,
        delegate_iid=delegate_iid,
        expiry=expiry,
        delegation_seq=delegation_seq,
        flags=DELEGATION_FLAG_EXTERNAL if external else 0,
    )

    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)
    to_sign = sha256(sig_structure).digest()
    signature = schnorr48.sign(identity.privkey, identity.pubkey, to_sign)

    return PrefixDelegationToken(payload=payload, delegator_iid=identity.iid, signature=signature)


def verify_prefix_delegation_token(
    token: PrefixDelegationToken,
    delegator_pubkey: bytes,
    delegate_iid: bytes,
    current_time: int,
    cached_seq: int | None = None,
) -> tuple[bool, str | None]:
    """Verify a prefix delegation token (spec section 8.7.2).

    Performs the delegate validation steps: signature, delegator-IID binding,
    delegate binding, expiry, sequence replay, and flag validity.

    Args:
        token: The token to verify
        delegator_pubkey: 32-byte Ed25519 public key of the delegator (root)
        delegate_iid: 8-byte IID of the node exercising the delegation
        current_time: Current Unix timestamp
        cached_seq: Previously cached delegation_seq for this prefix

    Returns:
        (valid, error): (True, None) if valid, else (False, error_string)
    """
    payload = token.payload

    if payload.flags & DELEGATION_RESERVED_FLAG_MASK:
        return False, "INVALID_FLAGS"

    derived_iid = _pubkey_to_iid(delegator_pubkey)
    if token.delegator_iid != derived_iid:
        return False, "DELEGATOR_IID_MISMATCH"

    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)
    to_verify = sha256(sig_structure).digest()

    if not schnorr48.verify(delegator_pubkey, to_verify, token.signature):
        return False, "SIGNATURE_INVALID"

    if payload.delegate_iid != delegate_iid:
        return False, "DELEGATE_MISMATCH"

    if payload.expiry <= current_time:
        return False, "EXPIRED"

    if cached_seq is not None and payload.delegation_seq <= cached_seq:
        return False, "REPLAY_DETECTED"

    return True, None
