# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Node identity and keypair management.

Why this exists: Every LICHEN node needs a stable cryptographic identity for:
1. Signing outgoing frames (authentication)
2. Verifying signatures from known peers
3. Building the trust graph (TOFU model)

The identity is derived from a 32-byte seed (typically from secure storage or
hardware RNG). The seed MUST be kept secret; the public key can be shared freely.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from hashlib import sha256

from .schnorr48 import derive_keypair


@dataclass(frozen=True, slots=True)
class Identity:
    """A node's cryptographic identity.

    Why frozen: Identity should never change after creation. A changed identity
    means a different node. Frozen prevents accidental mutation.

    Why slots: Memory efficiency matters on constrained devices. We may have
    many peer identities cached.

    Attributes:
        seed: 32-byte secret seed. NEVER log, transmit, or expose this.
        privkey: 32-byte Ed25519 private scalar (derived from seed).
        pubkey: 32-byte Ed25519 public point (can be shared).
        iid: 8-byte Interface Identifier derived from pubkey (for IPv6).
    """

    seed: bytes
    privkey: bytes
    pubkey: bytes
    iid: bytes

    def __post_init__(self) -> None:
        # Why validate here: catch bugs early, fail fast
        if len(self.seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(self.seed)}")
        if len(self.privkey) != 32:
            raise ValueError(f"privkey must be 32 bytes, got {len(self.privkey)}")
        if len(self.pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if len(self.iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(self.iid)}")

    @classmethod
    def from_seed(cls, seed: bytes) -> Identity:
        """Create an identity from a 32-byte seed.

        Why from_seed: Separates seed storage from identity creation. The caller
        controls where seeds come from (hardware, file, test fixture).

        Args:
            seed: 32 bytes of secret randomness. Use os.urandom(32) for real keys.

        Returns:
            A new Identity with derived keys.

        Raises:
            ValueError: If seed is not exactly 32 bytes.
        """
        if len(seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(seed)}")

        privkey, pubkey = derive_keypair(seed)
        iid = _pubkey_to_iid(pubkey)

        return cls(seed=seed, privkey=privkey, pubkey=pubkey, iid=iid)

    @classmethod
    def generate(cls) -> Identity:
        """Generate a new random identity.

        Why separate from from_seed: Convenience for tests and fresh nodes.
        Production code should use from_seed with persistent storage.

        Returns:
            A new Identity with cryptographically random keys.
        """
        # Why os.urandom: It's the standard secure RNG on all platforms.
        # Never use random.randbytes() for crypto - it's not secure.
        seed = os.urandom(32)
        return cls.from_seed(seed)

    def __repr__(self) -> str:
        # Why custom repr: NEVER leak seed or privkey in logs
        return f"Identity(pubkey={self.pubkey.hex()[:16]}..., iid={self.iid.hex()})"


def _pubkey_to_iid(pubkey: bytes) -> bytes:
    """Derive 8-byte Interface Identifier from public key.

    Why not use EUI-64: We don't have a MAC address. The pubkey is our identity,
    so we derive the IID from it. This is a LICHEN-specific convention.

    Why SHA-256 truncation: Simple, fast, no birthday concerns at 64 bits for
    our use case (identifier, not security). Matches what ORCHID does (RFC 7343).

    Args:
        pubkey: 32-byte Ed25519 public key.

    Returns:
        8-byte IID suitable for IPv6 link-local address construction.
    """
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")

    # Why SHA-256: Standard, fast, available everywhere
    digest = sha256(pubkey).digest()

    # Why first 8 bytes: Simple truncation is fine for identifiers
    iid = bytearray(digest[:8])

    # Why set bit 6 to 0: RFC 4291 says the "u" bit (universal/local) should be
    # 0 for locally-assigned addresses. Our IID is locally derived, not from
    # a globally-unique EUI-64.
    iid[0] &= 0b1111_1101  # clear bit 1 (the "u" bit in byte 0)

    return bytes(iid)


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """A remote peer's public identity (no secret material).

    Why separate from Identity: We only know peers' public keys, not their seeds.
    This type makes it impossible to accidentally treat a peer as self.

    Attributes:
        pubkey: 32-byte Ed25519 public key.
        iid: 8-byte Interface Identifier.
    """

    pubkey: bytes
    iid: bytes

    def __post_init__(self) -> None:
        if len(self.pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if len(self.iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(self.iid)}")

    @classmethod
    def from_pubkey(cls, pubkey: bytes) -> PeerIdentity:
        """Create a peer identity from their public key.

        Args:
            pubkey: 32-byte Ed25519 public key.

        Returns:
            A PeerIdentity with derived IID.
        """
        if len(pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
        iid = _pubkey_to_iid(pubkey)
        return cls(pubkey=pubkey, iid=iid)

    def __repr__(self) -> str:
        return f"PeerIdentity(pubkey={self.pubkey.hex()[:16]}..., iid={self.iid.hex()})"
