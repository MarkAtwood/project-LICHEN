# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Node identity and keypair management.

Why this exists: Every LICHEN node needs a stable cryptographic identity for:
1. Signing outgoing frames (authentication)
2. Verifying signatures from known peers
3. Building the trust graph (TOFU model)

The identity is derived from a 32-byte seed (typically from secure storage or
hardware RNG). The seed MUST be kept secret; the public key can be shared freely.

Security Note on Key Material Zeroing
-------------------------------------
This module makes a best-effort attempt to zero sensitive key material (seed,
privkey) when an Identity is wiped or garbage-collected. However, Python has
fundamental limitations that prevent guaranteed secure erasure:

1. Immutable bytes: Python's `bytes` type is immutable, so any bytes object
   passed to us may persist elsewhere in memory.
2. GC copies: The garbage collector may copy objects during compaction.
3. Interning: Small bytes objects may be interned by the interpreter.
4. String coercion: Debug output, exceptions, etc. may create copies.
5. No mlock: Python doesn't support memory locking to prevent swapping.

We mitigate by storing secrets in mutable `bytearray` internally, which allows
in-place zeroing. This is defense-in-depth, not a guarantee. For high-security
applications, consider hardware security modules or native extensions with
proper memory protection (e.g., libsodium's sodium_memzero).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from hashlib import sha256

from .schnorr48 import derive_keypair


def _to_bytearray(data: bytes | bytearray) -> bytearray:
    """Convert bytes to bytearray for mutable storage."""
    if isinstance(data, bytearray):
        return data
    return bytearray(data)


def _zero_bytearray(arr: bytearray) -> None:
    """Zero out a bytearray in-place."""
    for i in range(len(arr)):
        arr[i] = 0


@dataclass(slots=True)
class Identity:
    """A node's cryptographic identity.

    Why not frozen: We need mutable bytearrays for secure zeroing of key
    material. The class is otherwise treated as immutable after construction.

    Why slots: Memory efficiency matters on constrained devices. We may have
    many peer identities cached.

    Security: Call wipe() when done with this identity to zero key material.
    The destructor also attempts zeroing, but explicit wipe() is preferred
    since Python's GC timing is unpredictable.

    Attributes:
        seed: 32-byte secret seed. NEVER log, transmit, or expose this.
        privkey: 32-byte Ed25519 private scalar (derived from seed).
        pubkey: 32-byte Ed25519 public point (can be shared).
        iid: 8-byte Interface Identifier derived from pubkey (for IPv6).
    """

    # Internal storage uses bytearray for mutable zeroing
    _seed: bytearray = field(repr=False)
    _privkey: bytearray = field(repr=False)
    pubkey: bytes
    iid: bytes
    _wiped: bool = field(default=False, repr=False)

    @property
    def seed(self) -> bytes:
        """Return seed as immutable bytes (for API compatibility)."""
        if self._wiped:
            raise ValueError("Identity has been wiped")
        return bytes(self._seed)

    @property
    def privkey(self) -> bytes:
        """Return privkey as immutable bytes (for API compatibility)."""
        if self._wiped:
            raise ValueError("Identity has been wiped")
        return bytes(self._privkey)

    def __post_init__(self) -> None:
        # Why validate here: catch bugs early, fail fast
        if len(self._seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(self._seed)}")
        if len(self._privkey) != 32:
            raise ValueError(f"privkey must be 32 bytes, got {len(self._privkey)}")
        if len(self.pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if len(self.iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(self.iid)}")

    def wipe(self) -> None:
        """Zero key material. Call when done with this identity.

        Best-effort zeroing of secret key material. See module docstring for
        limitations. After wiping, accessing seed or privkey raises ValueError.

        This is idempotent - calling multiple times is safe.
        """
        if self._wiped:
            return
        _zero_bytearray(self._seed)
        _zero_bytearray(self._privkey)
        self._wiped = True

    def __del__(self) -> None:
        """Best-effort zeroing on garbage collection.

        Explicit wipe() is preferred since GC timing is unpredictable.
        """
        # Guard against partially-constructed objects during __del__
        if hasattr(self, "_wiped") and not self._wiped:
            if hasattr(self, "_seed"):
                _zero_bytearray(self._seed)
            if hasattr(self, "_privkey"):
                _zero_bytearray(self._privkey)

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

        return cls(
            _seed=_to_bytearray(seed),
            _privkey=_to_bytearray(privkey),
            pubkey=pubkey,
            iid=iid,
        )

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
        if self._wiped:
            return "Identity(WIPED)"
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
