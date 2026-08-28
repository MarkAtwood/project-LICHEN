# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group OSCORE key wrap: pairwise ECDH-ES+A128KW distribution envelope.

Wraps a group master_secret pairwise for each member using the JWE-style
key-agreement key wrap "ECDH-ES+A128KW" (RFC 7518 Section 4.6): a fresh
ephemeral X25519 key per member, NIST SP 800-56A Concat KDF with SHA-256,
and AES Key Wrap (RFC 3394). This is the mechanism that makes pairwise
distribution of a group OSCORE master_secret possible; the CoAP delivery
itself lives outside this module.

Spec 12-apps.md 18.8.2: the wrapped group key MUST be delivered only over
the existing pairwise OSCORE context (EDHOC-established) between sender
and member, never in plaintext.

Key model (spec 8.6, identity.py): members are identified by their 32-byte
Ed25519 node public keys. Each key agreement converts the member's Ed25519
public key to its X25519 form (RFC 7748), exactly as EDHOC Suite 0 does,
so the single-seed node identity serves both signing and pairwise unwrap.

Usage:
    wrapped = wrap_for_members(master_secret, [alice.pubkey, bob.pubkey])

    # Deliver wrapped.member_wrapped_keys[alice.pubkey] to alice ONLY over
    # the existing pairwise OSCORE context (never plaintext, spec 18.8.2).

    # On the member side (Identity.x25519_private comes from the node seed):
    master_secret = unwrap_group_key(wrapped, alice.pubkey, alice.x25519_private)
"""

from __future__ import annotations

import hmac
from collections.abc import Sequence
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import (
    aes_key_unwrap,
    aes_key_wrap,
)
from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519

__all__ = [
    "ED25519_PUBKEY_LEN",
    "X25519_KEY_LEN",
    "MemberWrappedKey",
    "WRAP_ALGORITHM",
    "WrappedGroupKey",
    "unwrap_group_key",
    "unwrap_member_key",
    "wrap_for_members",
]

# Vector field wrap_algorithm (test/vectors/group_oscore_key.json) names this
# JWE/COSE-style key agreement with key wrapping algorithm (RFC 7518 4.6).
WRAP_ALGORITHM = "ECDH-ES+A128KW"

ED25519_PUBKEY_LEN = 32
X25519_KEY_LEN = 32

# Concat KDF output length: the A128KW KEK is 128 bits (RFC 7518 Section 4.6.2).
_A128KW_KEY_LEN = 16
# AES-KW (RFC 3394) wraps payloads of 16..128 bytes in 8-byte multiples. Group
# master_secret is 16 bytes (AES-CCM-16-64-128) or 32 bytes per spec 18.8.2.
_MASTER_SECRET_MAX_LEN = 128


@dataclass(frozen=True)
class MemberWrappedKey:
    """ECDH-ES+A128KW wrap of the group master_secret for one member.

    Attributes:
        epk: 32-byte ephemeral X25519 public key (JWE "epk" parameter,
            RFC 7518 Section 4.6.1.1).
        wrapped_key: AES-KW ciphertext of the group master_secret
            (JWE "encrypted_key").
    """

    epk: bytes
    wrapped_key: bytes


@dataclass(frozen=True)
class WrappedGroupKey:
    """Per-member wrapped copies of one group master_secret.

    Attributes:
        wrap_algorithm: Key wrap algorithm identifier (vector field name).
        member_wrapped_keys: Member Ed25519 public key -> that member's wrap.
    """

    wrap_algorithm: str
    member_wrapped_keys: dict[bytes, MemberWrappedKey]


def _u32_len_prefixed(data: bytes) -> bytes:
    """Encode an RFC 7518 Section 4.6.2 field: Datalen || Data."""
    return len(data).to_bytes(4, "big") + data


def _concat_kdf_kek(z: bytes) -> bytes:
    """Derive the A128KW KEK from shared secret Z (RFC 7518 Section 4.6.2).

    OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo, each
    variable-length field 32-bit big-endian length prefixed: AlgorithmID is
    the ASCII "alg" value, apu/apv are absent (empty), SuppPubInfo is
    keydatalen = 128; SuppPrivInfo is empty (NIST SP 800-56A Section 5.8.1).
    """
    otherinfo = (
        _u32_len_prefixed(WRAP_ALGORITHM.encode("ascii"))
        + _u32_len_prefixed(b"")
        + _u32_len_prefixed(b"")
        + (_A128KW_KEY_LEN * 8).to_bytes(4, "big")
    )
    kdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=_A128KW_KEY_LEN, otherinfo=otherinfo)
    return kdf.derive(z)


def _member_x25519_public(member_pubkey: bytes) -> bytes:
    """Convert a member's Ed25519 public key to its X25519 form (RFC 7748)."""
    if not isinstance(member_pubkey, bytes):
        raise ValueError("member public key must be bytes")
    if len(member_pubkey) != ED25519_PUBKEY_LEN:
        raise ValueError(
            f"member public key must be {ED25519_PUBKEY_LEN} bytes, got {len(member_pubkey)}"
        )
    try:
        return crypto_sign_ed25519_pk_to_curve25519(member_pubkey)
    except Exception:
        # SECURITY: Do not chain exception - it may reveal key material state.
        raise ValueError("member public key is not a valid Ed25519 public key") from None


def _validate_x25519_private(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise ValueError(f"{name} must be bytes")
    if len(value) != X25519_KEY_LEN:
        raise ValueError(f"{name} must be {X25519_KEY_LEN} bytes, got {len(value)}")
    return value


def _shared_secret(private_key: X25519PrivateKey, peer_public: bytes) -> bytes:
    """Compute X25519 shared secret, rejecting the all-zero result."""
    z = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    # SECURITY: Reject all-zero shared secret - indicates the peer key is a
    # low-order point (small subgroup attack). Constant-time comparison.
    if hmac.compare_digest(z, b"\x00" * X25519_KEY_LEN):
        raise ValueError("X25519 shared secret is zero - possible small subgroup attack")
    return z


def wrap_for_members(master_secret: bytes, member_pubkeys: Sequence[bytes]) -> WrappedGroupKey:
    """Wrap a group master_secret pairwise for each member.

    Args:
        master_secret: Group OSCORE master secret (16..128 bytes, multiple
            of 8 bytes per RFC 3394 AES-KW).
        member_pubkeys: Member 32-byte Ed25519 node public keys (vector
            field "member_pubkeys"). A fresh ephemeral X25519 key is used
            per member (RFC 7518 Section 4.6 requirement), so every member
            receives a unique wrapped key.

    Returns:
        WrappedGroupKey with one MemberWrappedKey per member, ready for
        pairwise OSCORE delivery.

    Raises:
        ValueError: If master_secret is malformed, member_pubkeys is empty,
            or any member public key is malformed or duplicated.

    SECURITY: Deliver each MemberWrappedKey only over the existing pairwise
    OSCORE context with that member (spec 18.8.2); never in plaintext.
    """
    if not isinstance(master_secret, bytes):
        raise ValueError("master_secret must be bytes")
    if len(master_secret) < _A128KW_KEY_LEN or len(master_secret) % 8 != 0:
        raise ValueError(
            f"master_secret must be at least 16 bytes and a multiple of 8, got {len(master_secret)}"
        )
    if len(master_secret) > _MASTER_SECRET_MAX_LEN:
        raise ValueError(
            f"master_secret must be at most {_MASTER_SECRET_MAX_LEN} bytes, "
            f"got {len(master_secret)}"
        )
    if not member_pubkeys:
        raise ValueError("member_pubkeys must not be empty")

    member_wrapped_keys: dict[bytes, MemberWrappedKey] = {}
    for member_pubkey in member_pubkeys:
        if member_pubkey in member_wrapped_keys:
            raise ValueError("member_pubkeys contains a duplicate member")
        member_public = _member_x25519_public(member_pubkey)
        epk = X25519PrivateKey.generate()
        z = _shared_secret(epk, member_public)
        kek = _concat_kdf_kek(z)
        wrapped_key = aes_key_wrap(kek, master_secret)
        member_wrapped_keys[member_pubkey] = MemberWrappedKey(
            epk=epk.public_key().public_bytes_raw(),
            wrapped_key=wrapped_key,
        )
    return WrappedGroupKey(
        wrap_algorithm=WRAP_ALGORITHM,
        member_wrapped_keys=member_wrapped_keys,
    )


def unwrap_member_key(member_wrapped_key: MemberWrappedKey, member_x25519_private: bytes) -> bytes:
    """Recover the group master_secret from one member's wrapped key.

    Args:
        member_wrapped_key: This member's MemberWrappedKey, received over
            the pairwise OSCORE context.
        member_x25519_private: The member's 32-byte X25519 private key
            (Identity.x25519_private, derived from the node seed).

    Returns:
        The group master_secret bytes.

    Raises:
        InvalidUnwrap: If the wrap does not decrypt under this member's
            key (wrong member, tampered epk, or tampered wrapped_key).
        ValueError: If inputs are malformed.
    """
    _validate_x25519_private(member_x25519_private, "member_x25519_private")
    epk = member_wrapped_key.epk
    if not isinstance(epk, bytes) or len(epk) != X25519_KEY_LEN:
        raise ValueError(f"epk must be {X25519_KEY_LEN} bytes")
    wrapped_key = member_wrapped_key.wrapped_key
    if not isinstance(wrapped_key, bytes) or len(wrapped_key) < _A128KW_KEY_LEN + 8:
        raise ValueError("wrapped_key is too short")
    private_key = X25519PrivateKey.from_private_bytes(member_x25519_private)
    z = _shared_secret(private_key, epk)
    return aes_key_unwrap(_concat_kdf_kek(z), wrapped_key)


def unwrap_group_key(
    wrapped_group_key: WrappedGroupKey,
    member_pubkey: bytes,
    member_x25519_private: bytes,
) -> bytes:
    """Counterpart to wrap_for_members: unwrap the group key as one member.

    Args:
        wrapped_group_key: The WrappedGroupKey received over pairwise OSCORE.
        member_pubkey: This member's 32-byte Ed25519 node public key.
        member_x25519_private: This member's X25519 private key
            (Identity.x25519_private).

    Returns:
        The group master_secret bytes.

    Raises:
        ValueError: If wrap_algorithm is unsupported, the member key is
            malformed, or no wrap exists for this member.
        InvalidUnwrap: If the wrap does not decrypt under this member's key.
    """
    if wrapped_group_key.wrap_algorithm != WRAP_ALGORITHM:
        raise ValueError(
            f"unsupported wrap_algorithm {wrapped_group_key.wrap_algorithm!r}; "
            f"expected {WRAP_ALGORITHM!r}"
        )
    if not isinstance(member_pubkey, bytes) or len(member_pubkey) != ED25519_PUBKEY_LEN:
        raise ValueError(f"member_pubkey must be {ED25519_PUBKEY_LEN} bytes")
    if member_pubkey not in wrapped_group_key.member_wrapped_keys:
        raise ValueError("no wrapped group key for this member")
    return unwrap_member_key(
        wrapped_group_key.member_wrapped_keys[member_pubkey],
        member_x25519_private,
    )
