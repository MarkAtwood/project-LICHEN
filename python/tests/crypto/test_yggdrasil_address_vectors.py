# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the yggdrasil addressing corpus through the real derivation.

Per spec/decisions.jsonl ``upstream-yggdrasil-addressing``, a node's routable
address MUST equal upstream Yggdrasil ``AddrForKey(Ed25519PublicKey)`` and a
routed /64 subnet MUST equal upstream ``SubnetForKey`` in ``0300::/8``. The
implementation under test IS the upstream algorithm; the single upstream
yggdrasil-go anchor (``upstream_addr_for_key``) is the pinned external oracle,
kept verbatim, and MUST match byte-for-byte.

The former ``lichen_native_sha512`` profile is REJECTED; its vectors are
quarantined in ``test/vectors/legacy/yggdrasil_address_native_sha512.json``
and are NOT consumed here (the upstream AddrForKey migration has landed).
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


def _document() -> dict:
    document = json.loads(VECTORS.read_text())
    assert document["format_version"] == 1
    return document


def _anchor() -> dict:
    anchors = [v for v in _document()["vectors"] if v["name"] == ANCHOR_NAME]
    assert len(anchors) == 1, "exactly one upstream anchor expected"
    return anchors[0]


def _error_cases() -> list[tuple[str, dict]]:
    return [
        (v["name"], v) for v in _document()["vectors"] if v.get("expect_error") == "pubkey_length"
    ]


def test_corpus_shape() -> None:
    """Live corpus holds the anchor + error cases; no rejected native vectors."""
    vectors = _document()["vectors"]
    assert len(_error_cases()) >= 2
    assert all(v.get("profile") != "lichen_native_sha512" for v in vectors), (
        "live corpus must not hold rejected native-profile vectors"
    )


def test_upstream_anchor_is_verbatim_go_reference() -> None:
    """The committed anchor still matches upstream byte-for-byte."""
    anchor = _anchor()
    assert anchor["public_key"] == GO_ANCHOR_PUBKEY
    assert anchor["address"] == GO_ANCHOR_ADDRESS
    assert anchor["ipv6"] == GO_ANCHOR_IPV6


def test_upstream_addr_for_key_byte_equality() -> None:
    """yggdrasil_address MUST equal upstream AddrForKey byte-for-byte."""
    anchor = _anchor()
    derived = yggdrasil_address(bytes.fromhex(anchor["public_key"]))
    assert derived.packed.hex() == anchor["address"], (
        "yggdrasil_address must equal upstream AddrForKey byte-for-byte"
    )
    assert str(derived) == anchor["ipv6"]
    assert derived.packed[0] == 0x02


def test_upstream_subnet_for_key_byte_equality() -> None:
    """subnet_for_key MUST equal upstream SubnetForKey byte-for-byte."""
    anchor = _anchor()
    pubkey = bytes.fromhex(anchor["public_key"])
    subnet = subnet_for_key(pubkey)
    assert subnet.hex() == GO_ANCHOR_SUBNET, (
        "subnet_for_key must equal upstream SubnetForKey byte-for-byte"
    )
    # Subnet lives in 0300::/8 (prefix low bit set) and shares the
    # leading-1 count byte with the address.
    assert subnet[0] & 0x01 == 0x01
    assert subnet[1] == yggdrasil_address(pubkey).packed[1]


def test_degenerate_all_zero_key_matches_upstream_semantics() -> None:
    """All-zero key -> inverted all-ones -> no separator -> empty payload.

    The leading-1 count wraps 256 -> 0 (Go byte overflow) and no payload bits
    are appended, yielding 0200:: (0x02 followed by fifteen zero bytes).
    """
    derived = yggdrasil_address(bytes(32))
    assert derived.packed == b"\x02" + bytes(15)


def test_routable_address_does_not_embed_iid() -> None:
    """The routable address carries no SHA-512 IID in its lower 64 bits."""
    anchor = _anchor()
    pubkey = bytes.fromhex(anchor["public_key"])
    derived = yggdrasil_address(pubkey)
    iid = _pubkey_to_iid(pubkey)
    assert derived.packed[8:] != iid, "routable address must not embed the IID"


@pytest.mark.parametrize("name,vector", _error_cases())
def test_error_cases_rejected(name: str, vector: dict) -> None:
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        yggdrasil_address(bytes.fromhex(vector["public_key"]))
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        _pubkey_to_iid(bytes.fromhex(vector["public_key"]))
