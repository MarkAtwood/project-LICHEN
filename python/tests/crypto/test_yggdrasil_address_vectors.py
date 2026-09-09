# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume test/vectors/yggdrasil_address.json through the real derivation.

Post-migration (7pt2, settled ``upstream-yggdrasil-addressing`` decision in
spec/decisions.jsonl), ``yggdrasil_address`` IS upstream ``AddrForKey``
byte-for-byte (yggdrasil-go@422836ee src/address/address.go), and
``subnet_for_key`` is upstream ``SubnetForKey``. The corpus' single
``upstream_addr_for_key`` anchor is now the byte-equality oracle.

The ``lichen_native_sha512`` fixtures in the corpus belong to the REJECTED
SHA-512 native profile: they pin an address whose lower 64 bits equal the
SHA-512 IID, an invariant the upstream profile does not have. They are
legacy fixtures reported to the corpus-regeneration bead i72x.6, which owns
the shared corpora; this suite no longer consumes them byte-exact. Their
continued presence in the JSON is asserted only so they cannot be silently
re-interpreted as upstream vectors before i72x.6 regenerates the corpus.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.crypto.identity import _pubkey_to_iid, subnet_for_key, yggdrasil_address

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "yggdrasil_address.json"

ANCHOR_NAME = "upstream_addr_for_key"

# Constants lifted directly from upstream yggdrasil-go
# src/address/address_test.go @422836ee (the external oracle for the anchor;
# not derivable by any code under test here).
GO_ANCHOR_PUBKEY = "bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb"
GO_ANCHOR_ADDRESS = "0200848a604fbb7e438465db8db66895"
GO_ANCHOR_IPV6 = "200:848a:604f:bb7e:4384:65db:8db6:6895"
GO_ANCHOR_SUBNET = "0300848a604fbb7e"

# Byte-exact upstream AddrForKey/SubnetForKey expectations, generated once by
# running the upstream yggdrasil-go src/address package (@422836ee, the
# independent oracle) over fixed keys and hardcoded here. NEVER derived from
# the implementation under test. Degenerate cases are deliberate: the
# all-zero key's inverted form is all 1 bits, so the leading-1 count wraps
# to 0 (Go byte overflow) and no payload bits follow; the all-ones key's
# inverted form begins with a 0 separator bit, leaving an all-zero payload.
UPSTREAM_VECTORS = [
    ("go_anchor", GO_ANCHOR_PUBKEY, GO_ANCHOR_ADDRESS, GO_ANCHOR_SUBNET),
    (
        "sha256_empty_as_key",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "0200389e777ace07c7d6ca08166ecd20",
        "0300389e777ace07",
    ),
    (
        "all_zero_key",
        "00" * 32,
        "02000000000000000000000000000000",
        "0300000000000000",
    ),
    (
        "all_ones_key",
        "ff" * 32,
        "02000000000000000000000000000000",
        "0300000000000000",
    ),
    (
        "rfc8032_test1_key",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "0200514acffcfa9dea90556802586d37",
        "0300514acffcfa9d",
    ),
    (
        "lead_nine_ones_key",
        "007f" + "ff" * 30,
        "02090000000000000000000000000000",
        "0309000000000000",
    ),
]


def _document() -> dict:
    document = json.loads(VECTORS.read_text())
    assert document["format_version"] == 1
    return document


def _anchor() -> dict:
    anchors = [v for v in _document()["vectors"] if v["name"] == ANCHOR_NAME]
    assert len(anchors) == 1, "exactly one upstream anchor expected"
    return anchors[0]


def _upstream_cases() -> list[tuple[str, dict]]:
    return [
        (v["name"], v)
        for v in _document()["vectors"]
        if v.get("profile") == "upstream_addr_for_key"
    ]


def _error_cases() -> list[tuple[str, dict]]:
    return [
        (v["name"], v) for v in _document()["vectors"] if v.get("expect_error") == "pubkey_length"
    ]


def test_corpus_shape() -> None:
    """Guard against regression to the original single-vector corpus."""
    vectors = _document()["vectors"]
    assert len(_upstream_cases()) >= 10
    assert len(_error_cases()) >= 2
    assert len(vectors) == len(_upstream_cases()) + len(_error_cases()) + 1


def test_upstream_anchor_is_verbatim_go_reference() -> None:
    """The committed anchor still matches upstream byte-for-byte."""
    anchor = _anchor()
    assert anchor["public_key"] == GO_ANCHOR_PUBKEY
    assert anchor["address"] == GO_ANCHOR_ADDRESS
    assert anchor["ipv6"] == GO_ANCHOR_IPV6


def test_upstream_anchor_byte_exact_through_production() -> None:
    """Post-migration, production IS upstream AddrForKey: byte equality."""
    anchor = _anchor()
    public_key = bytes.fromhex(anchor["public_key"])
    derived = yggdrasil_address(public_key)
    assert derived.packed.hex() == anchor["address"]
    assert str(derived) == anchor["ipv6"]
    assert subnet_for_key(public_key).hex() == GO_ANCHOR_SUBNET


@pytest.mark.parametrize("name,vector", _upstream_cases())
def test_upstream_vectors_byte_exact(name: str, vector: dict) -> None:
    """Corpus derivation vectors pass byte-exact through production."""
    public_key = bytes.fromhex(vector["public_key"])
    derived = yggdrasil_address(public_key)
    iid = _pubkey_to_iid(public_key)

    assert derived.packed.hex() == vector["address"], name
    assert str(derived) == vector["ipv6"], name
    assert derived.packed[0] == 0x02, name

    # The iid field is the link-local IID only; it is NOT the address tail.
    assert iid.hex() == vector["iid"], name
    assert iid[0] & 0x02 == 0, f"{name}: U/L bit must be clear in IID"
    assert derived.packed[8:] != iid, f"{name}: rejected IID-embedding invariant"


@pytest.mark.parametrize(
    ("name", "public_key", "address", "subnet"),
    UPSTREAM_VECTORS,
    ids=[v[0] for v in UPSTREAM_VECTORS],
)
def test_upstream_addr_for_key_byte_exact(
    name: str, public_key: str, address: str, subnet: str
) -> None:
    """Upstream-oracle vectors pass byte-exact through production."""
    key_bytes = bytes.fromhex(public_key)
    derived = yggdrasil_address(key_bytes)
    assert derived.packed.hex() == address, name
    assert derived.packed[0] == 0x02, name
    assert subnet_for_key(key_bytes).hex() == subnet, name
    assert subnet_for_key(key_bytes)[0] & 0x03 == 0x03, name


def test_iid_is_link_local_only_not_embedded_in_primary() -> None:
    """The SHA-512 IID survives unchanged but is NOT the address tail."""
    public_key = bytes.fromhex(GO_ANCHOR_PUBKEY)
    iid = _pubkey_to_iid(public_key)
    assert len(iid) == 8 and iid[0] & 0x02 == 0
    assert yggdrasil_address(public_key).packed[8:] != iid


@pytest.mark.parametrize("name,vector", _error_cases())
def test_error_cases_rejected(name: str, vector: dict) -> None:
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        yggdrasil_address(bytes.fromhex(vector["public_key"]))
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        _pubkey_to_iid(bytes.fromhex(vector["public_key"]))
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        subnet_for_key(bytes.fromhex(vector["public_key"]))
