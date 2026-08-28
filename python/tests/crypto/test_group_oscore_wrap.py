# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Unit tests for group OSCORE pairwise key wrap (ECDH-ES+A128KW).

Drives test/vectors/group_oscore_key.json vector key_pairwise_wrap. That
vector is a behavioral contract, not byte-exact: its member_pubkeys and
expected wrapped-key values are symbolic placeholders ("pubkey_alice",
"unique_for_alice"), so real Ed25519 member keys are substituted and the
assertions enforce the vector's contract: one wrap per member, wrapped
keys unique per member (reason "pairwise_encryption"), and the
wrap_algorithm field. Byte-exact recovery of the group key is verified by
round-trip unwrap.
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from lichen.crypto.group_oscore_wrap import (
    WRAP_ALGORITHM,
    MemberWrappedKey,
    WrappedGroupKey,
    unwrap_group_key,
    unwrap_member_key,
    wrap_for_members,
)
from lichen.crypto.identity import Identity

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _key_pairwise_wrap_vector() -> dict[str, object]:
    doc = json.loads((VECTORS_DIR / "group_oscore_key.json").read_text(encoding="utf-8"))
    for vector in doc["vectors"]:
        if vector["name"] == "key_pairwise_wrap":
            return vector
    raise AssertionError("key_pairwise_wrap vector missing from group_oscore_key.json")


def _alice_and_bob() -> tuple[Identity, Identity]:
    """Real Ed25519 identities for the vector's symbolic pubkey_alice/pubkey_bob."""
    return Identity.generate(), Identity.generate()


def test_key_pairwise_wrap_vector_end_to_end() -> None:
    vector = _key_pairwise_wrap_vector()
    group_key = bytes.fromhex(str(vector["group_key"]))
    alice, bob = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey, bob.pubkey])

    expected = vector["expected"]
    assert isinstance(expected, dict)
    # Vector field: "ECDH-ES+A128KW or HPKE" (disjunctive). Our implementation
    # is ECDH-ES+A128KW, which the vector's allowed set includes.
    assert wrapped.wrap_algorithm in ("ECDH-ES+A128KW", "HPKE")
    assert wrapped.wrap_algorithm == WRAP_ALGORITHM
    assert expected["reason"] == "pairwise_encryption"

    assert list(wrapped.member_wrapped_keys) == [alice.pubkey, bob.pubkey]
    for member in (alice, bob):
        assert unwrap_group_key(wrapped, member.pubkey, member.x25519_private) == group_key


def test_wrapped_keys_unique_per_member() -> None:
    """Vector expected values: unique_for_alice / unique_for_bob."""
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, bob = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey, bob.pubkey])

    alice_wrap = wrapped.member_wrapped_keys[alice.pubkey]
    bob_wrap = wrapped.member_wrapped_keys[bob.pubkey]
    assert (alice_wrap.epk, alice_wrap.wrapped_key) != (bob_wrap.epk, bob_wrap.wrapped_key)
    # Pairwise wrap, not plaintext distribution: the secret must not appear raw.
    for member_wrap in (alice_wrap, bob_wrap):
        assert member_wrap.wrapped_key != group_key
        assert group_key not in member_wrap.wrapped_key


def test_fresh_ephemeral_per_wrap() -> None:
    """RFC 7518 Section 4.6: a new ephemeral key per key agreement operation."""
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, _ = _alice_and_bob()

    first = wrap_for_members(group_key, [alice.pubkey])
    second = wrap_for_members(group_key, [alice.pubkey])

    first_wrap = first.member_wrapped_keys[alice.pubkey]
    second_wrap = second.member_wrapped_keys[alice.pubkey]
    assert first_wrap.epk != second_wrap.epk
    assert first_wrap.wrapped_key != second_wrap.wrapped_key
    for wrapped in (first, second):
        assert unwrap_group_key(wrapped, alice.pubkey, alice.x25519_private) == group_key


def test_master_secret_32_bytes_roundtrip() -> None:
    """Spec 18.8.2 key distribution response: master_secret is 32 bytes."""
    group_key = bytes(range(32))
    alice, bob = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey, bob.pubkey])

    for member in (alice, bob):
        assert unwrap_group_key(wrapped, member.pubkey, member.x25519_private) == group_key


def test_wrong_member_cannot_unwrap() -> None:
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, bob = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey])

    alice_wrap = wrapped.member_wrapped_keys[alice.pubkey]
    with pytest.raises(InvalidUnwrap):
        unwrap_member_key(alice_wrap, bob.x25519_private)


def test_tampered_wrapped_key_rejected() -> None:
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, _ = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey])
    alice_wrap = wrapped.member_wrapped_keys[alice.pubkey]
    tampered = MemberWrappedKey(
        epk=alice_wrap.epk,
        wrapped_key=bytes([alice_wrap.wrapped_key[0] ^ 0x01]) + alice_wrap.wrapped_key[1:],
    )

    with pytest.raises(InvalidUnwrap):
        unwrap_member_key(tampered, alice.x25519_private)


def test_tampered_epk_rejected() -> None:
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, _ = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey])
    alice_wrap = wrapped.member_wrapped_keys[alice.pubkey]
    tampered = MemberWrappedKey(
        epk=bytes([alice_wrap.epk[0] ^ 0x01]) + alice_wrap.epk[1:],
        wrapped_key=alice_wrap.wrapped_key,
    )

    # Garbage KEK: AES-KW integrity check fails, or (zero shared secret)
    # the small-subgroup guard fires. Either way the unwrap must fail.
    with pytest.raises((InvalidUnwrap, ValueError)):
        unwrap_member_key(tampered, alice.x25519_private)


def test_zero_epk_rejected() -> None:
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, _ = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey])
    alice_wrap = wrapped.member_wrapped_keys[alice.pubkey]
    zero_epk = MemberWrappedKey(epk=b"\x00" * 32, wrapped_key=alice_wrap.wrapped_key)

    with pytest.raises(ValueError):
        unwrap_member_key(zero_epk, alice.x25519_private)


def test_unsupported_wrap_algorithm_rejected() -> None:
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, _ = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey])
    bogus = WrappedGroupKey(
        wrap_algorithm="HPKE",
        member_wrapped_keys=wrapped.member_wrapped_keys,
    )

    with pytest.raises(ValueError, match="wrap_algorithm"):
        unwrap_group_key(bogus, alice.pubkey, alice.x25519_private)


def test_missing_member_rejected() -> None:
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, carol = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey])

    with pytest.raises(ValueError, match="no wrapped group key"):
        unwrap_group_key(wrapped, carol.pubkey, carol.x25519_private)


def test_invalid_master_secret_lengths() -> None:
    alice, _ = _alice_and_bob()

    for bad in (b"\x00" * 8, b"\x00" * 17, b"\x00" * 136, b""):
        with pytest.raises(ValueError, match="master_secret"):
            wrap_for_members(bad, [alice.pubkey])


def test_invalid_member_pubkeys_rejected() -> None:
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, _ = _alice_and_bob()

    with pytest.raises(ValueError, match="member public key"):
        wrap_for_members(group_key, [b"\x00" * 31])
    with pytest.raises(ValueError, match="duplicate"):
        wrap_for_members(group_key, [alice.pubkey, alice.pubkey])
    with pytest.raises(ValueError, match="empty"):
        wrap_for_members(group_key, [])


def test_invalid_unwrap_inputs_rejected() -> None:
    group_key = bytes.fromhex("deadbeefcafebabedeadbeefcafebabe")
    alice, _ = _alice_and_bob()

    wrapped = wrap_for_members(group_key, [alice.pubkey])
    alice_wrap = wrapped.member_wrapped_keys[alice.pubkey]

    short_epk = MemberWrappedKey(epk=b"\x00" * 31, wrapped_key=alice_wrap.wrapped_key)
    with pytest.raises(ValueError, match="epk"):
        unwrap_member_key(short_epk, alice.x25519_private)
    with pytest.raises(ValueError, match="member_x25519_private"):
        unwrap_member_key(alice_wrap, b"\x00" * 31)
