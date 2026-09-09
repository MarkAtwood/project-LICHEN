# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the yggdrasil addressing corpora through the real derivation.

Per spec/decisions.jsonl ``upstream-yggdrasil-addressing``, a node's routable
address MUST equal upstream Yggdrasil ``AddrForKey(Ed25519PublicKey)``. The
former ``lichen_native_sha512`` profile is REJECTED.

Two files are consumed:

1. ``test/vectors/yggdrasil_address.json`` (LIVE) — the pinned upstream
   yggdrasil-go ``AddrForKey`` anchor (verbatim external oracle) plus
   profile-agnostic ``error_case`` length rejections.
2. ``test/vectors/legacy/yggdrasil_address_native_sha512.json`` (QUARANTINED,
   see ``test/vectors/legacy/README.md``) — the ten rejected-profile vectors,
   moved verbatim out of the live corpus. They are consumed ONLY as a
   quarantine-integrity pin of pre-migration behavior, never as a conformance
   oracle: the current Python derivation still implements the rejected
   profile, so the byte-exact cases document that state and trip if the
   derivation changes accidentally before the upstream AddrForKey migration
   lands. When the migration lands, those cases MUST be deleted and the
   anchor divergence test MUST flip from inequality to byte-equality.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.crypto.identity import _pubkey_to_iid, yggdrasil_address

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "yggdrasil_address.json"
LEGACY_NATIVE = (
    Path(__file__).resolve().parents[3]
    / "test"
    / "vectors"
    / "legacy"
    / "yggdrasil_address_native_sha512.json"
)

ANCHOR_NAME = "upstream_addr_for_key"

# Constants lifted directly from upstream yggdrasil-go
# src/address/address_test.go @422836ee (the external oracle for the anchor;
# not derivable by any code under test here).
GO_ANCHOR_PUBKEY = "bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb"
GO_ANCHOR_ADDRESS = "0200848a604fbb7e438465db8db66895"
GO_ANCHOR_IPV6 = "200:848a:604f:bb7e:4384:65db:8db6:6895"


def _document() -> dict:
    document = json.loads(VECTORS.read_text())
    assert document["format_version"] == 1
    return document


def _legacy_document() -> dict:
    document = json.loads(LEGACY_NATIVE.read_text())
    assert document["format_version"] == 1
    return document


def _anchor() -> dict:
    anchors = [v for v in _document()["vectors"] if v["name"] == ANCHOR_NAME]
    assert len(anchors) == 1, "exactly one upstream anchor expected"
    return anchors[0]


def _legacy_native_cases() -> list[tuple[str, dict]]:
    return [
        (v["name"], v)
        for v in _legacy_document()["vectors"]
        if v.get("profile") == "lichen_native_sha512"
    ]


def _error_cases() -> list[tuple[str, dict]]:
    return [
        (v["name"], v) for v in _document()["vectors"] if v.get("expect_error") == "pubkey_length"
    ]


def test_corpus_shape() -> None:
    """Live corpus holds anchor + error cases only; native vectors stay quarantined."""
    vectors = _document()["vectors"]
    assert len(_legacy_native_cases()) >= 10
    assert len(_error_cases()) >= 2
    assert len(vectors) == len(_error_cases()) + 1, (
        "live corpus must hold exactly the anchor plus the error cases"
    )
    assert all(v.get("profile") != "lichen_native_sha512" for v in vectors), (
        "live corpus must not hold rejected native-profile vectors"
    )


def test_upstream_anchor_is_verbatim_go_reference() -> None:
    """The committed anchor still matches upstream byte-for-byte."""
    anchor = _anchor()
    assert anchor["public_key"] == GO_ANCHOR_PUBKEY
    assert anchor["address"] == GO_ANCHOR_ADDRESS
    assert anchor["ipv6"] == GO_ANCHOR_IPV6


def test_upstream_anchor_diverges_from_current_native_profile() -> None:
    """PINNED MIGRATION GAP, not a target state.

    Upstream AddrForKey bit-packs the inverted key; the current derivation
    still implements the REJECTED SHA-512 profile (decisions.jsonl
    upstream-yggdrasil-addressing). The only shared byte is the leading 0x02
    prefix. When the upstream AddrForKey migration lands, the inequality
    below MUST flip to byte-equality (it will fail loudly until flipped).
    """
    anchor = _anchor()
    derived = yggdrasil_address(bytes.fromhex(anchor["public_key"]))
    assert derived.packed.hex() != anchor["address"], (
        "upstream AddrForKey migration has landed: flip this test to byte-equality"
    )
    assert derived.packed[0] == bytes.fromhex(anchor["address"])[0]


@pytest.mark.parametrize("name,vector", _legacy_native_cases())
def test_quarantined_native_vectors_byte_exact_pin(name: str, vector: dict) -> None:
    """QUARANTINE-INTEGRITY PIN, not a conformance oracle.

    The vectors encode the REJECTED SHA-512 native profile
    (test/vectors/legacy/README.md). The implementation still derives that
    profile — a known, tracked migration gap. This test trips if the
    derivation changes accidentally before the upstream AddrForKey migration
    lands; when it lands, this test MUST be deleted.
    """
    public_key = bytes.fromhex(vector["public_key"])
    derived = yggdrasil_address(public_key)
    iid = _pubkey_to_iid(public_key)

    # Byte-exact address and canonical text form.
    assert derived.packed.hex() == vector["address"], name
    assert str(derived) == vector["ipv6"], name
    assert derived.packed[0] == 0x02, name

    # IID agreement plus the legacy binding invariant: lower 64 bits of the
    # address equal the key-derived IID.
    assert iid.hex() == vector["iid"], name
    assert derived.packed[8:] == iid, name
    assert iid[0] & 0x02 == 0, f"{name}: U/L bit must be clear in IID"


@pytest.mark.parametrize("name,vector", _error_cases())
def test_error_cases_rejected(name: str, vector: dict) -> None:
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        yggdrasil_address(bytes.fromhex(vector["public_key"]))
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        _pubkey_to_iid(bytes.fromhex(vector["public_key"]))
