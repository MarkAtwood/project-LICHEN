# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group OSCORE key distribution (spec 18.8.5, vectors ``group_oscore_key.json``).

A group controller holds the current group key and distributes it to members
pairwise: each member receives the group key encrypted under a key derived
from an X25519 exchange with the member's own public key, so no other member
(or observer) can unwrap it.

Contract highlights (operative contract is the vector file):

- Pairwise wrap: unique ciphertext per member pubkey
  (X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305-IETF).
- ``key_epoch``: monotonic u32 counter over the cyclic epoch space
  1..``EPOCH_WRAP``; it wraps after ``0xFFFFFFFF`` (the successor of the
  maximum epoch is 1 -- a new wrap generation, never a rollback).
- Two predicates encode one acceptance policy (spec 18.8.2):

  - :meth:`GroupKeyManager.validate_epoch` is *accept-for-processing*: a
    structural, wrap-aware gate on the epoch stamped on a message. It
    accepts the current epoch, the immediate successor (a peer may rekey
    before we do), and the immediate predecessor while we still hold that
    material inside its grace window; the old key_epoch is rejected only
    *after* the 1-hour grace period.
  - :meth:`GroupKeyManager.key_valid_at` is *use-authorization*: whether a
    specific key material may be used at a given time. Current material
    (identified by identity, not epoch-number equality -- numbers recur
    after a wrap) is always valid; other held material is valid within its
    grace window; material the manager does not hold is never authorized.

- OSCORE context isolation: ``id_context = group_id || key_epoch(u32 BE)``.
  Epoch numbers recur across wrap generations; the unqualified encoding is
  safe because key material is never reused for a recurring epoch number --
  :meth:`GroupKeyManager.rekey` enforces this (raises on reuse).
- Grace window and bounded retention: after a rekey the previous key stays
  valid for one hour (strict expiry) so stragglers can decrypt in-flight
  traffic; each rekey drops held material whose grace window has expired
  and zeroizes dropped mutable (``bytearray``) key buffers where practical.
- Membership: rekey distributes to current members only (removed members get
  no new key material but can still decrypt the previous key during grace);
  newly added members receive only the current key, never historical ones.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass

import nacl.bindings as bindings
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# Old key remains valid this long after a rekey (spec 18.8.5 grace window).
GRACE_PERIOD_S = 3600

# key_epoch is a u32 monotonic counter; it wraps after this value.
EPOCH_WRAP = 0xFFFFFFFF

# Domain separators for HKDF derivations.
_WRAP_INFO = b"LICHEN-GROUP-WRAP-v1"
_NONCE_INFO = b"LICHEN-GROUP-WRAP-NONCE-v1"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF with SHA-256 (extract-then-expand)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def _to_x25519_public(ed25519_pubkey: bytes) -> bytes:
    """Convert an Ed25519 public key to its Curve25519 equivalent."""
    return bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_pubkey)


def _to_x25519_private(ed25519_scalar: bytes) -> bytes:
    """Map a LICHEN Ed25519 private scalar to its Curve25519 equivalent.

    ``derive_keypair`` already returns the clamped ``SHA-512(seed)[:32]``
    scalar that Ed25519 uses, which is exactly the X25519 private scalar for
    the same key -- no further hashing (libsodium's ``*_sk_to_curve25519``
    expects a raw seed and would hash a second time).
    """
    if len(ed25519_scalar) != 32:
        raise ValueError("ed25519 private scalar must be 32 bytes")
    return ed25519_scalar


@dataclass(frozen=True)
class GroupKeyMaterial:
    """A group key bound to its epoch.

    ``key`` may be a mutable ``bytearray``; ``rekey`` zeroizes the buffer of
    dropped material on purge (``bytes`` keys are immutable and cannot be
    scrubbed).
    """

    epoch: int
    key: bytes | bytearray
    created_s: float

    def __repr__(self) -> str:
        return (
            f"GroupKeyMaterial(epoch={self.epoch}, "
            f"key=<redacted {len(self.key)} bytes>, "
            f"created_s={self.created_s!r})"
        )

    __str__ = __repr__


class GroupKeyManager:
    """Distributes and rotates a group key among authenticated members.

    Args:
        group_id: Stable group identifier (used in OSCORE id_context).
        group_key: Initial group key material (e.g. 16-byte AES-CCM key).
        members: Mapping of member IID (hex) -> Ed25519 public key.
        time_func: Monotonic clock; defaults to :func:`time.monotonic`
            (spec 18.10.3-style uptime requirement applies equally here).
    """

    def __init__(
        self,
        group_id: bytes,
        group_key: bytes,
        members: dict[str, bytes] | None = None,
        *,
        time_func: Callable[[], float] | None = None,
    ) -> None:
        self.group_id = group_id
        self._time_func = time_func if time_func is not None else time.monotonic
        self._current = GroupKeyMaterial(epoch=1, key=group_key, created_s=self._time_func())
        self._previous: list[GroupKeyMaterial] = []
        self.members: dict[str, bytes] = dict(members or {})

    # -- epoch / context ----------------------------------------------------

    @property
    def epoch(self) -> int:
        """Current key_epoch."""
        return self._current.epoch

    def oscore_id_context(self, epoch: int | None = None) -> bytes:
        """OSCORE id_context: ``group_id || key_epoch`` (u32 big-endian).

        The encoding is not qualified by wrap generation (the vector file
        pins ``group_id || key_epoch``); it stays collision-safe across
        wraps because :meth:`rekey` enforces that key material is never
        reused for a recurring epoch number.
        """
        e = self._current.epoch if epoch is None else epoch
        return self.group_id + struct.pack(">I", e)

    def _epoch_distance(self, message_epoch: int) -> int:
        """Signed wrap-aware distance from the current to *message_epoch*.

        Measured on the cyclic epoch space (``EPOCH_WRAP`` values, since
        epochs start at 1 and 0 is never assigned): ``+1`` is the successor
        (``EPOCH_WRAP`` wraps to 1), ``-1`` the predecessor. For the small
        windows this protocol uses this is equivalent to comparing
        wrap-generation-qualified values.
        """
        distance = (message_epoch - self._current.epoch) % EPOCH_WRAP
        if distance > EPOCH_WRAP // 2:
            distance -= EPOCH_WRAP
        return distance

    def validate_epoch(self, message_epoch: int) -> tuple[bool, str]:
        """Accept-for-processing gate for an incoming message epoch.

        One half of the acceptance policy (see module docstring): this
        predicate decides structurally which epochs are processable;
        :meth:`key_valid_at` separately authorizes use of a specific
        material at a given time.

        Epochs are compared by signed distance on the cyclic epoch space,
        so after a wrap the new epoch 1 is the *successor* of ``0xFFFFFFFF``,
        not a rollback.

        Accepted:

        - the current epoch and the immediate successor (a peer may have
          rekeyed before us; the successor key may not be held yet);
        - the immediate predecessor while we still hold its material inside
          the grace window (spec 18.8.2: the old key_epoch is rejected only
          *after* the 1-hour grace period). A predecessor we never held
          (e.g. we joined after that rekey), or whose grace has expired,
          is ``epoch_rollback``.

        Returns ``(accept, reason)``; reasons mirror the vector names:
        ``epoch_rollback`` for anything behind the grace candidate,
        ``future_epoch_unknown`` for anything more than one ahead.
        """
        if message_epoch < 1:
            return False, "epoch_rollback"
        if message_epoch > EPOCH_WRAP:
            return False, "future_epoch_unknown"
        distance = self._epoch_distance(message_epoch)
        if distance == 0 or distance == 1:
            return True, "ok"
        if distance == -1:
            # Grace candidate (spec 18.8.2): accepted only while we still
            # hold the material and its grace window is open.
            material = self.key_for_epoch(message_epoch)
            if material is not None and self.key_valid_at(material):
                return True, "ok"
            return False, "epoch_rollback"
        if distance > 1:
            return False, "future_epoch_unknown"
        return False, "epoch_rollback"

    # -- key validity / grace -----------------------------------------------

    def key_valid_at(self, material: GroupKeyMaterial, now_s: float | None = None) -> bool:
        """Whether *material* may still be used at *now_s* (use-authorization).

        The other half of the acceptance policy: :meth:`validate_epoch`
        gates which epochs are processable; this predicate authorizes a
        specific material.

        Authorization is scoped to material this manager holds and is by
        *identity*, never epoch-number equality -- epoch numbers recur
        after a wrap, and a foreign object with a matching number must not
        inherit current status. The current material is always valid;
        superseded held material remains valid until its grace window
        expires (strictly, per the 3600001 ms vector). Material the manager
        does not hold is never authorized.
        """
        if now_s is None:
            now_s = self._time_func()
        if material is self._current:
            return True
        if any(held is material for held in self._previous):
            return now_s - material.created_s <= GRACE_PERIOD_S
        return False

    def key_for_epoch(self, epoch: int) -> GroupKeyMaterial | None:
        """Return held key material for *epoch*, or ``None``.

        Resolution is by epoch number over the material this manager holds
        (current first, then superseded, newest first). ``rekey`` drops
        retained entries whose epoch number would collide with a wrapped
        epoch, so numbers are unambiguous within the held set; numbers do
        recur across wrap generations, so use-authorization
        (:meth:`key_valid_at`) is still required before using the result.
        """
        if self._current.epoch == epoch:
            return self._current
        for material in reversed(self._previous):
            if material.epoch == epoch:
                return material
        return None

    # -- distribution --------------------------------------------------------

    def distribute_current(self, member_iids: list[str] | None = None) -> dict[str, bytes]:
        """Wrap the current group key pairwise for the given (or all) members."""
        targets = member_iids if member_iids is not None else list(self.members)
        wrapped: dict[str, bytes] = {}
        for iid in targets:
            try:
                pubkey = self.members[iid]
            except KeyError as exc:  # unknown member: no key material
                raise KeyError(f"unknown group member: {iid}") from exc
            wrapped[iid] = pairwise_wrap(self._current.key, pubkey)
        return wrapped

    def rekey(self, new_key: bytes | None = None) -> dict[str, bytes]:
        """Rotate the group key and distribute it to every current member.

        Removed members are excluded automatically (forward secrecy on
        removal); they can still decrypt the previous key during grace.

        Wrap handling: rotating past ``EPOCH_WRAP`` starts a new wrap
        generation at epoch 1. Retained material whose epoch number would
        collide with the wrapped epoch is dropped (it would shadow the new
        current in :meth:`key_for_epoch`), and an enforced never-reuse
        invariant refuses key material byte-identical to retained material
        from an earlier generation -- reusing material for a recurring
        epoch number would reuse OSCORE nonces (full plaintext recovery).

        Raises:
            RuntimeError: If *new_key* duplicates retained material across
                a wrap generation (never-reuse invariant).

        Retention is bounded: material whose grace window expired before
        *now* is dropped here, and collision-dropped wrap entries are
        zeroized, so a memory compromise of the controller cannot
        retroactively expose traffic keys older than the grace window.
        """
        if new_key is None:
            new_key = bindings.randombytes(16)
        now = self._time_func()
        wrapping = self._current.epoch == EPOCH_WRAP
        new_epoch = 1 if wrapping else self._current.epoch + 1
        if wrapping:
            for held in self._previous:
                if held.epoch == new_epoch and hmac.compare_digest(held.key, new_key):
                    raise RuntimeError(
                        "group key material reused across wrap generations: "
                        f"epoch {new_epoch} would recur with identical key "
                        "(OSCORE nonce reuse)"
                    )
            kept = []
            for held in self._previous:
                if held.epoch == new_epoch:
                    self._zeroize(held)
                else:
                    kept.append(held)
            self._previous = kept
        self._previous.append(self._current)
        self._current = GroupKeyMaterial(
            epoch=new_epoch,
            key=new_key,
            created_s=now,
        )
        self._purge_expired(now)
        return self.distribute_current()

    def _purge_expired(self, now_s: float) -> None:
        """Drop held material whose grace window expired before *now_s*.

        The boundary is strict (drop iff ``created_s + GRACE_PERIOD_S <
        now_s``), matching :meth:`key_valid_at` (valid iff
        ``now - created_s <= GRACE_PERIOD_S``): material is retained
        exactly as long as it is still authorized.
        """
        kept = []
        for held in self._previous:
            if held.created_s + GRACE_PERIOD_S < now_s:
                self._zeroize(held)
            else:
                kept.append(held)
        self._previous = kept

    @staticmethod
    def _zeroize(material: GroupKeyMaterial) -> None:
        """Best-effort scrub of a dropped key buffer.

        Mutable (``bytearray``) keys are overwritten in place; ``bytes``
        keys are immutable and cannot be scrubbed.
        """
        key = material.key
        if isinstance(key, bytearray):
            for index in range(len(key)):
                key[index] = 0

    # -- membership -----------------------------------------------------------

    def add_member(self, iid: str, pubkey: bytes) -> bytes:
        """Admit a member; returns the current key wrapped for them only.

        New members never receive historical key material (no backward
        access).
        """
        self.members[iid] = pubkey
        return pairwise_wrap(self._current.key, pubkey)

    def remove_member(self, iid: str) -> None:
        """Remove a member. They keep access only until the next rekey."""
        self.members.pop(iid, None)

    def __repr__(self) -> str:
        return (
            f"GroupKeyManager(group_id={self.group_id.hex()}, "
            f"epoch={self.epoch}, members={len(self.members)}, "
            f"previous_retained={len(self._previous)})"
        )

    __str__ = __repr__


def pairwise_wrap(group_key: bytes, member_ed25519_pubkey: bytes) -> bytes:
    """Wrap *group_key* for one member (unique ciphertext per pubkey).

    Layout: ``ephemeral_x25519_pub (32 B) || ChaCha20-Poly1305-IETF
    ciphertext(group_key)``. The ephemeral scalar is derived deterministically
    from (group_key, member_pubkey) so wrapping is reproducible for testing
    while remaining unique per member. KEK and nonce are derived from the
    ECDH shared secret, so the receiver can recompute both.

    Raises:
        ValueError: If the member key cannot be converted to Curve25519.
    """
    member_x_pub = _to_x25519_public(member_ed25519_pubkey)
    eph_seed = hkdf_sha256(group_key, salt=b"LICHEN-GROUP-WRAP-v1", info=_WRAP_INFO + member_x_pub)
    eph_pub = bindings.crypto_scalarmult_base(eph_seed)
    shared = bindings.crypto_scalarmult(eph_seed, member_x_pub)
    kek = hkdf_sha256(shared, salt=eph_pub + member_x_pub, info=_WRAP_INFO)
    nonce = hkdf_sha256(shared, salt=eph_pub + member_x_pub, info=_NONCE_INFO, length=12)
    ciphertext = bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
        group_key, aad=member_x_pub, nonce=nonce, key=kek
    )
    return eph_pub + ciphertext


def pairwise_unwrap(
    wrapped: bytes,
    member_ed25519_seed: bytes,
    member_ed25519_pubkey: bytes,
) -> bytes:
    """Undo :func:`pairwise_wrap`; returns the original group key."""
    if len(wrapped) < 32 + 16:
        raise ValueError("wrapped key too short")
    eph_pub, ciphertext = wrapped[:32], wrapped[32:]
    member_x_pub = _to_x25519_public(member_ed25519_pubkey)
    member_x_priv = _to_x25519_private(member_ed25519_seed)
    shared = bindings.crypto_scalarmult(member_x_priv, eph_pub)
    kek = hkdf_sha256(shared, salt=eph_pub + member_x_pub, info=_WRAP_INFO)
    nonce = hkdf_sha256(shared, salt=eph_pub + member_x_pub, info=_NONCE_INFO, length=12)
    return bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
        ciphertext, aad=member_x_pub, nonce=nonce, key=kek
    )


__all__ = [
    "EPOCH_WRAP",
    "GRACE_PERIOD_S",
    "GroupKeyManager",
    "GroupKeyMaterial",
    "hkdf_sha256",
    "pairwise_unwrap",
    "pairwise_wrap",
]


# -- group payload AEAD (spec 12-apps.md 18.2.4, bead l1qw.35.1) -------------

# AES-CCM-16-64-128 per spec 18.8.2 group key (matches edhoc.py suite 0).
_PAYLOAD_CCM_KEY_LEN = 16
_PAYLOAD_CCM_NONCE_LEN = 13
_PAYLOAD_CCM_TAG_LEN = 8

# Payload nonces are random per message (transmitted alongside the
# ciphertext, so receivers need no derivation). Random nonces are safe under
# CCM's birthday bound for the message volumes a LICHEN group sees, and the
# transmitted nonce is bound to the ciphertext by the AEAD tag.


def seal_group_payload(
    manager: GroupKeyManager,
    plaintext: bytes,
    aad: bytes = b"",
    *,
    epoch: int | None = None,
) -> tuple[bytes, bytes, int]:
    """Encrypt a group payload with the current group key (spec 18.2.4).

    Uses AES-CCM-16-64-128 — the algorithm named for group keys by spec
    18.8.2 — with a random per-message nonce (transmitted alongside the
    ciphertext; receivers need no derivation).

    Args:
        manager: Group key manager holding the current key material.
        plaintext: Payload to encrypt (position beacon body, etc.).
        aad: Additional authenticated data (e.g. destination ff35 address).
        epoch: Key epoch to seal under; defaults to the manager's current.

    Returns:
        ``(ciphertext, nonce, key_epoch)`` — the tuple to transmit; the
        receiver opens it with :func:`open_group_payload` against held
        material for that epoch.

    Raises:
        ValueError: If the manager's current key is not a 16-byte AES-CCM
            key.
    """
    material = manager.key_for_epoch(epoch) if epoch is not None else manager._current
    if material is None:
        raise ValueError("no key material for the requested epoch")
    if not manager.key_valid_at(material):
        raise ValueError(
            f"key material for epoch {material.epoch} is not valid now"
        )
    key = bytes(material.key)
    if len(key) != _PAYLOAD_CCM_KEY_LEN:
        raise ValueError(
            f"group key must be {_PAYLOAD_CCM_KEY_LEN} bytes for "
            f"AES-CCM-16-64-128, got {len(key)}"
        )
    nonce = os.urandom(_PAYLOAD_CCM_NONCE_LEN)
    ciphertext = AESCCM(key, tag_length=_PAYLOAD_CCM_TAG_LEN).encrypt(
        nonce, plaintext, aad if aad else None
    )
    return ciphertext, nonce, material.epoch


def open_group_payload(
    manager: GroupKeyManager,
    ciphertext: bytes,
    nonce: bytes,
    key_epoch: int,
    aad: bytes = b"",
) -> bytes:
    """Decrypt a group payload sealed with :func:`seal_group_payload`.

    Uses the key material the manager holds for *key_epoch*; honors the
    grace-window policy via :meth:`GroupKeyManager.key_valid_at` — material
    the manager does not hold is never authorized.

    Raises:
        ValueError: If no key material is held for *key_epoch*, the held
            material is outside its validity window, or decryption fails
            (wrong key, tampered ciphertext/AAD).
    """
    material = manager.key_for_epoch(key_epoch)
    if material is None:
        raise ValueError(f"no key material held for epoch {key_epoch}")
    if not manager.key_valid_at(material):
        raise ValueError(f"key material for epoch {key_epoch} is not valid now")
    key = bytes(material.key)
    if len(key) != _PAYLOAD_CCM_KEY_LEN:
        raise ValueError(
            f"group key must be {_PAYLOAD_CCM_KEY_LEN} bytes for "
            f"AES-CCM-16-64-128, got {len(key)}"
        )
    try:
        return AESCCM(key, tag_length=_PAYLOAD_CCM_TAG_LEN).decrypt(
            nonce, ciphertext, aad if aad else None
        )
    except InvalidTag as e:
        raise ValueError("group payload decryption failed") from e
