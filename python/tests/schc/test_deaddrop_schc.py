# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""/deaddrop SCHC compressed-packet vector coverage (appendix-schc.md A.4.1).

Vectors are produced by an independent wire-spec generator
(``test/vectors/generate_deaddrop_schc.py``) that imports neither SCHC
implementation. This test pins the Python codec against that oracle for OSCORE
POSTs (Rule 5/6), a protected GET (Rule 5), and public GETs (Rule 0/1 with
Uri-Path carried verbatim in the tail).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.schc.headers import compress_packet, decompress_packet

DOCUMENT = json.loads(
    (Path(__file__).parents[3] / "test" / "vectors" / "deaddrop_schc.json").read_text()
)
assert DOCUMENT["format_version"] == 2
VECTORS = DOCUMENT["vectors"]

REQUIRED = {
    "deaddrop_post_linklocal",
    "deaddrop_post_global",
    "deaddrop_get_protected_linklocal",
    "deaddrop_get_public_linklocal",
    "deaddrop_get_public_global",
}


def test_vectors_cover_every_provisioned_rule() -> None:
    names = {entry["name"] for entry in VECTORS}
    assert names >= REQUIRED


@pytest.mark.parametrize("entry", VECTORS, ids=lambda item: item["name"])
def test_deaddrop_compress_matches_independent_oracle(entry: dict[str, Any]) -> None:
    packet = bytes.fromhex(entry["ipv6_packet"])
    expected = bytes.fromhex(entry["compressed"])
    compressed = compress_packet(packet)
    assert compressed == expected
    assert compressed[0] == entry["rule_id"]


@pytest.mark.parametrize("entry", VECTORS, ids=lambda item: item["name"])
def test_deaddrop_roundtrip_is_lossless(entry: dict[str, Any]) -> None:
    packet = bytes.fromhex(entry["ipv6_packet"])
    compressed = bytes.fromhex(entry["compressed"])
    assert decompress_packet(compressed) == packet


@pytest.mark.parametrize("entry", VECTORS, ids=lambda item: item["name"])
def test_deaddrop_coap_code_is_preserved(entry: dict[str, Any]) -> None:
    # The CoAP code travels in the residue; confirm it survives the round trip
    # so POSTs (0.02) and GETs (0.01) are not conflated on decompress.
    packet = bytes.fromhex(entry["ipv6_packet"])
    compressed = bytes.fromhex(entry["compressed"])
    restored = decompress_packet(compressed)
    assert restored[49] == entry["coap_code"]  # CoAP code is byte 2 of CoAP header.
    assert len(restored) == len(packet)
