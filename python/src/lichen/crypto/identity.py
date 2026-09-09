# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Node identity and keypair management.

Every LICHEN node needs a stable cryptographic identity for:
1. Signing outgoing frames (authentication)
2. Verifying signatures from known peers
3. Building the trust graph (TOFU model)

The identity is derived from a 32-byte seed (typically from secure storage or
hardware RNG). The seed MUST be kept secret; the public key can be shared freely.

Note: Python cannot securely erase memory (GC copies, no mlock, immutable bytes).
For memory-forensics threat models, use Rust/C implementations or HSMs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from hashlib import sha512
from ipaddress import IPv6Address

from nacl.bindings import crypto_scalarmult_base

from .schnorr48 import clamp, derive_keypair


@dataclass
class Identity:
    """A node's cryptographic identity.

    Attributes:
        seed: 32-byte secret seed. NEVER log, transmit, or expose this.
        privkey: 32-byte Ed25519 private scalar (derived from seed).
        pubkey: 32-byte Ed25519 public point (can be shared).
        iid: 8-byte Interface Identifier derived from pubkey.
        ygg_addr: 16-byte key-derived primary IPv6 address (0200::/8).
    """

    seed: bytes
    privkey: bytes
    pubkey: bytes
    iid: bytes
    ygg_addr: bytes

    def __post_init__(self) -> None:
        if len(self.seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(self.seed)}")
        if len(self.privkey) != 32:
            raise ValueError(f"privkey must be 32 bytes, got {len(self.privkey)}")
        if len(self.pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if len(self.iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(self.iid)}")
        if len(self.ygg_addr) != 16:
            raise ValueError(f"ygg_addr must be 16 bytes, got {len(self.ygg_addr)}")

    @classmethod
    def from_seed(cls, seed: bytes) -> Identity:
        """Create an identity from a 32-byte seed.

        Args:
            seed: 32 bytes of secret randomness. Use os.urandom(32) for real keys.

        Returns:
            A new Identity with derived keys.
        """
        # SECURITY: Seed length validation is critical. Per spec 8.7, all
        # cryptographic material (Schnorr48, X25519, IID, 0200::/8 address) derives
        # from this single 32-byte seed. An incorrect length could produce weak
        # or undefined key material.
        if len(seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(seed)}")

        privkey, pubkey = derive_keypair(seed)
        iid = _pubkey_to_iid(pubkey)
        ygg_addr = yggdrasil_address(pubkey).packed

        return cls(seed=seed, privkey=privkey, pubkey=pubkey, iid=iid, ygg_addr=ygg_addr)

    @classmethod
    def generate(cls) -> Identity:
        """Generate a new random identity.

        Returns:
            A new Identity with cryptographically random keys.
        """
        return cls.from_seed(os.urandom(32))

    def __repr__(self) -> str:
        pk = self.pubkey.hex()[:16]
        iid = self.iid.hex()
        ygg = self.ygg_addr.hex()[:16]
        return f"Identity(pubkey={pk}..., iid={iid}, ygg={ygg})"

    @property
    def x25519_private(self) -> bytes:
        """Derive X25519 private key from Ed25519 seed (for static DH).

        x25519_private = clamp(SHA-512(seed)[0:32]) per RFC 7748 §5,
        standards/crypto.md and draft-lichen-security. Clamping is required
        to place scalar in correct subgroup (avoids small subgroup attacks
        in static DH for EDHOC/OSCORE).

        Returns:
            32-byte clamped X25519 private key.
        """
        h = sha512(self.seed).digest()[:32]
        return clamp(h)

    @property
    def x25519_public(self) -> bytes:
        """Derive X25519 public key from Ed25519 seed (for static DH).

        Returns:
            32-byte X25519 public key for ECDH key agreement.
        """
        return crypto_scalarmult_base(self.x25519_private)


def hash_32(data: bytes | str) -> int:
    """Keyed FNV-1a 32-bit hash with the LICHEN "LICH" basis (0x4c494348).

    The basis is the leading 32 bits of the ASCII project key ``LICHEN``,
    matching the C ``LICHEN_MESHTASTIC_DEFAULT_NODE_NUM`` constant. Unlike
    the interpreter-salted built-in ``hash()``, results are stable across
    processes, making this suitable for persistent endpoint identifiers.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = 0x4C494348
    for byte in data:
        h = ((h ^ byte) * 0x01000193) & 0xFFFFFFFF
    return h


def _pubkey_to_iid(pubkey: bytes) -> bytes:
    """Derive IID from Ed25519 public key.

    LICHEN native profile inspired by Yggdrasil 0200::/8 range; NOT
    wire-compatible with upstream AddrForKey (which bit-packs without hashing).
    See test/vectors/yggdrasil_address.json for divergence documentation.
    """
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")

    digest = sha512(pubkey).digest()
    iid = bytearray(digest[:8])
    iid[0] &= 0b1111_1101
    return bytes(iid)


@dataclass(frozen=True)
class PeerIdentity:
    """A remote peer's public identity (no secret material).

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
        """Create a peer identity from their public key."""
        if len(pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
        return cls(pubkey=pubkey, iid=_pubkey_to_iid(pubkey))

    def __repr__(self) -> str:
        return f"PeerIdentity(iid={self.iid.hex()[:8]}, human={self.human_address})"

    @property
    def human_address(self) -> str:
        """Human-readable node address (Base32 of IID, 13 chars with dashes)."""
        return iid_to_human_address(self.iid)


def iid_to_human_address(iid: bytes) -> str:
    """Convert 8-byte IID (from SHA-512 of Ed25519 pubkey) to 13-char
    human-readable Crockford Base32 address with dashes (XXXX-XXXX-XXXXX).

    Matches spec/03-addressing.md. Collision-resistant at planetary scale.
    """
    if len(iid) != 8:
        raise ValueError(f"IID must be 8 bytes, got {len(iid)}")
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    n = int.from_bytes(iid, "big")
    chars: list[str] = []
    for _ in range(13):
        n, rem = divmod(n, 32)
        chars.append(alphabet[rem])
    s = "".join(reversed(chars))
    return f"{s[:4]}-{s[4:8]}-{s[8:]}"


def yggdrasil_address(pubkey: bytes) -> IPv6Address:
    """Derive the routable 0200::/8 address from an Ed25519 public key.

    This is the upstream Yggdrasil ``AddrForKey`` algorithm, byte-for-byte,
    per the settled ``upstream-yggdrasil-addressing`` decision
    (``spec/decisions.jsonl``; yggdrasil-go commit ``422836ee``
    ``src/address/address.go``). The former SHA-512-based LICHEN native
    profile is REJECTED and MUST NOT be used.

    Algorithm (no hashing):

      1. Bit-invert the 32-byte public key.
      2. ``addr[0] = 0x02`` (the ``0200::/8`` prefix; last bit 0 = node address).
      3. ``addr[1]`` = count of leading 1 bits in the inverted key, mod 256
         (matches Go's ``byte`` overflow semantics).
      4. Skip the leading 1 bits and the first 0 bit (the separator).
      5. Pack the remaining inverted-key bits MSB-first into whole bytes,
         discarding any trailing partial byte; copy into ``addr[2:16]``,
         truncating at 14 bytes, leaving unwritten tail bytes zero.

    Degenerate case (all-zero public key → inverted all-ones): no separator 0
    bit is ever seen, so no payload bits are appended and the leading-1 count
    wraps 256 → 0, matching upstream exactly.

    The IID (``_pubkey_to_iid``, a SHA-512 digest) is NOT embedded in this
    address; the routable address binds to the key by self-derivation. The
    pinned byte-equality oracle is the ``upstream_addr_for_key`` vector in
    ``test/vectors/yggdrasil_address.json`` (anchored to upstream
    ``address_test.go``); it is cross-checked against the independent Rust
    implementation (``ygg_addr_from_pubkey``, i72x.2).
    """
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")

    buf = bytearray(b ^ 0xFF for b in pubkey)

    addr = bytearray(16)
    addr[0] = 0x02

    temp = bytearray()  # whole bytes collected from the bit stream
    done = False
    ones = 0  # wraps mod 256 like Go's `byte`
    cur = 0
    nbits = 0

    for idx in range(8 * len(buf)):
        bit = (buf[idx // 8] >> (7 - (idx % 8))) & 0x01
        if not done and bit != 0:
            ones = (ones + 1) & 0xFF
            continue
        if not done:
            # first leading 0 bit: separator, skipped
            done = True
            continue
        cur = ((cur << 1) | bit) & 0xFF
        nbits += 1
        if nbits == 8:
            nbits = 0
            temp.append(cur)

    addr[1] = ones
    n = min(len(temp), 14)
    addr[2 : 2 + n] = temp[:n]
    return IPv6Address(bytes(addr))


def subnet_for_key(pubkey: bytes) -> bytes:
    """Derive the 8-byte routable 0300::/8 subnet prefix from an Ed25519 pubkey.

    Upstream Yggdrasil ``SubnetForKey`` (same source as :func:`yggdrasil_address`):
    take ``AddrForKey``, keep the first 8 bytes, and set the low bit of the
    first byte (``byte[0] |= 0x01``) to mark a prefix rather than a node
    address. Returns the 8-byte subnet prefix.
    """
    addr = yggdrasil_address(pubkey).packed
    snet = bytearray(addr[:8])
    snet[0] |= 0x01
    return bytes(snet)
