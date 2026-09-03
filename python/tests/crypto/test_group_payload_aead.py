# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group payload AEAD tests (spec 18.2.4, bead l1qw.35.1)."""

from __future__ import annotations

import pytest

from lichen.crypto.group_oscore import (
    GroupKeyManager,
    open_group_payload,
    seal_group_payload,
)

GROUP_ID = b"team-alpha"
GROUP_KEY = bytes(range(16))
PLAINTXT = b"position beacon payload: 37.774929,-122.419416"


@pytest.fixture
def manager() -> GroupKeyManager:
    return GroupKeyManager(GROUP_ID, GROUP_KEY)


def test_seal_open_roundtrip(manager: GroupKeyManager) -> None:
    ct, nonce, epoch = seal_group_payload(manager, PLAINTXT)
    assert epoch == 1
    assert ct != PLAINTXT
    assert len(nonce) == 13  # CCM-16-64-128 nonce length
    assert open_group_payload(manager, ct, nonce, epoch) == PLAINTXT


def test_nonces_unique_across_messages(manager: GroupKeyManager) -> None:
    """Random per-message nonces: two seals of the same plaintext must not
    reuse (nonce, keystream) — CCM is CTR-mode, so keystream reuse would be
    a two-time-pad break."""
    nonces = {seal_group_payload(manager, PLAINTXT)[1] for _ in range(8)}
    assert len(nonces) == 8


def test_aad_mismatch_fails(manager: GroupKeyManager) -> None:
    ct, nonce, epoch = seal_group_payload(manager, PLAINTXT, aad=b"ff35::1")
    with pytest.raises(ValueError):
        open_group_payload(manager, ct, nonce, epoch, aad=b"ff35::2")


def test_tampered_ciphertext_fails(manager: GroupKeyManager) -> None:
    ct, nonce, epoch = seal_group_payload(manager, PLAINTXT)
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    with pytest.raises(ValueError):
        open_group_payload(manager, bytes(tampered), nonce, epoch)


def test_rekey_rotates_epoch_and_ciphertext(manager: GroupKeyManager) -> None:
    ct1, nonce1, epoch1 = seal_group_payload(manager, PLAINTXT)
    manager.rekey()
    ct2, _, epoch2 = seal_group_payload(manager, PLAINTXT)
    assert epoch2 == 2
    assert ct2 != ct1
    # Old epoch payload still opens under grace-window material.
    assert open_group_payload(manager, ct1, nonce1, epoch1) == PLAINTXT


def test_no_material_for_future_epoch_fails(manager: GroupKeyManager) -> None:
    with pytest.raises(ValueError):
        seal_group_payload(manager, PLAINTXT, epoch=99)
    with pytest.raises(ValueError):
        open_group_payload(manager, b"x", b"n" * 13, 99)


def test_non_16_byte_key_rejected() -> None:
    bad = GroupKeyManager(b"gid", b"short-key")
    with pytest.raises(ValueError):
        seal_group_payload(bad, PLAINTXT)


def test_seal_under_grace_expired_key_fails(manager: GroupKeyManager) -> None:
    """Seal-side validity: material outside its grace window must not seal."""
    manager.rekey()
    # Force the old material's created_s far into the past so its grace
    # window has expired.
    for material in manager._previous:
        object.__setattr__(material, "created_s", 0.0)
    old_epoch = 1
    with pytest.raises(ValueError):
        seal_group_payload(manager, PLAINTXT, epoch=old_epoch)
