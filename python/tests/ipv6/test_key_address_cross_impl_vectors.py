# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-corpus checks for canonical Ed25519-key IPv6 derivation."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.crypto.identity import _pubkey_to_iid, yggdrasil_address
from lichen.ipv6.addr import (
    eui64_to_iid,
    link_local_from_pubkey,
    native_address_from_pubkey,
    short_addr_to_iid,
)

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _load(name: str) -> object:
    return json.loads((VECTORS_DIR / name).read_text())


def _independent_derivation(public_key: bytes) -> tuple[bytes, bytes, bytes]:
    """Independent oracle for IID, link-local, and routable 0200::/8 address.

    The IID and link-local use the LICHEN SHA-512 IID profile. The routable
    address implements upstream Yggdrasil ``AddrForKey`` directly from the
    public reference (yggdrasil-go ``src/address/address.go`` @422836ee),
    independently of ``lichen.crypto.identity.yggdrasil_address`` under test.
    """
    digest = hashlib.sha512(public_key).digest()
    iid = bytearray(digest[:8])
    iid[0] &= 0xFD
    link_local = b"\xfe\x80" + bytes(6) + iid

    # Upstream AddrForKey: bit-invert, count leading 1s, drop separator 0,
    # pack remaining bits MSB-first into whole bytes (discard trailing partial).
    inv = bytearray(b ^ 0xFF for b in public_key)
    addr = bytearray(16)
    addr[0] = 0x02
    ones = 0
    done = False
    cur = 0
    nbits = 0
    temp = bytearray()
    for idx in range(8 * len(inv)):
        bit = (inv[idx // 8] >> (7 - (idx % 8))) & 0x01
        if not done and bit != 0:
            ones = (ones + 1) & 0xFF
            continue
        if not done:
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
    return bytes(iid), bytes(link_local), bytes(addr)


def test_ipv6_address_vectors_bind_one_key_to_both_addresses_byte_exact() -> None:
    document = _load("ipv6-addresses.json")
    # The live corpus pins IID + link-local (unchanged by the migration). The
    # routable 0200::/8 address is upstream AddrForKey; the rejected SHA-512
    # native profile and its quarantined corpus are no longer consumed here.
    # The independent oracle above provides the upstream-address oracle.
    assert isinstance(document, dict)
    vectors = document["vectors"]
    assert isinstance(vectors, list)
    key_vectors = [item for item in vectors if item["profile"] == "key_derived_identity"]

    assert len(key_vectors) >= 5
    for vector in key_vectors:
        public_key = bytes.fromhex(vector["pubkey"])
        iid, link_local, routable = _independent_derivation(public_key)

        assert iid.hex() == vector["iid"], vector["name"]
        assert link_local.hex() == vector["link_local_packed"], vector["name"]
        assert str(IPv6Address(link_local)) == vector["link_local"], vector["name"]

        assert _pubkey_to_iid(public_key) == iid, vector["name"]
        assert link_local_from_pubkey(public_key).packed == link_local, vector["name"]
        # Routable address == independent upstream AddrForKey oracle.
        assert yggdrasil_address(public_key).packed == routable, vector["name"]
        assert native_address_from_pubkey(public_key).packed == routable, vector["name"]

        assert link_local[:8] == bytes.fromhex("fe80000000000000"), vector["name"]
        assert link_local[8:] == iid, vector["name"]
        assert routable[0] == 0x02, vector["name"]
        assert iid[0] & 0x02 == 0, vector["name"]


def test_eui_and_short_vectors_are_interop_helpers_not_identity() -> None:
    """EUI-64 and short-address vectors are wire-interop helpers, not identities.

    They carry no key-derived identity material, and the EUI-64 mapping is
    the RFC 4291 U/L flip -- provably not the SHA-512 identity derivation.
    """
    document = _load("ipv6-addresses.json")
    assert isinstance(document, dict)
    vectors = document["vectors"]
    assert isinstance(vectors, list)

    assert {item["profile"] for item in vectors} <= {
        "key_derived_identity",
        "link_interoperability_only",
    }
    interop = [item for item in vectors if item["profile"] == "link_interoperability_only"]
    eui_vectors = [item for item in interop if "eui64" in item]
    short_vectors = [item for item in interop if "short_addr" in item]
    assert len(interop) == len(eui_vectors) + len(short_vectors) == 6

    for vector in eui_vectors:
        assert "pubkey" not in vector and "native" not in vector, vector["name"]
        eui64 = bytes.fromhex(vector["eui64"])
        iid = bytes([eui64[0] ^ 0x02]) + eui64[1:]
        link_local = b"\xfe\x80" + bytes(6) + iid

        assert iid.hex() == vector["iid"], vector["name"]
        assert link_local.hex() == vector["link_local_packed"], vector["name"]
        assert str(IPv6Address(link_local)) == vector["link_local"], vector["name"]
        assert eui64_to_iid(eui64) == iid, vector["name"]

        # Interop, not identity: SHA-512 of the same octets derives a
        # different IID than the U/L flip, so this is not key derivation.
        digest = hashlib.sha512(eui64).digest()
        identity_iid = bytearray(digest[:8])
        identity_iid[0] &= 0xFD
        assert iid != bytes(identity_iid), vector["name"]

    for vector in short_vectors:
        assert "pubkey" not in vector and "native" not in vector, vector["name"]
        # RFC 4944 section 6 layout, computed here independently of production.
        iid = (0x0000_00FF_FE00_0000 | vector["short_addr"]).to_bytes(8, "big")
        assert iid.hex() == vector["iid"], vector["name"]
        assert short_addr_to_iid(vector["short_addr"]) == iid, vector["name"]


def test_address_derivation_accepts_exact_width_raw_key_octets() -> None:
    """Addressing is a 32-byte hash map; subgroup checks belong to signature use."""
    low_order_encoding = bytes(32)
    iid, link_local, routable = _independent_derivation(low_order_encoding)

    assert _pubkey_to_iid(low_order_encoding) == iid
    assert link_local_from_pubkey(low_order_encoding).packed == link_local
    assert yggdrasil_address(low_order_encoding).packed == routable


@pytest.mark.parametrize("public_key", [b"", bytes(31), bytes(33)])
def test_address_derivation_rejects_malformed_key_lengths(public_key: bytes) -> None:
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        _pubkey_to_iid(public_key)
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        yggdrasil_address(public_key)


def test_committed_ipv6_address_vectors_match_stdlib_generator() -> None:
    before = VECTORS_DIR.joinpath("ipv6-addresses.json").read_bytes()
    result = subprocess.run(
        [sys.executable, str(VECTORS_DIR / "generate_ipv6_addresses.py"), "--check"],
        cwd=VECTORS_DIR.parent.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert VECTORS_DIR.joinpath("ipv6-addresses.json").read_bytes() == before
