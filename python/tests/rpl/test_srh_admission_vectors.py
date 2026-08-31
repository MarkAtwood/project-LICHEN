# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Verify Python RH3 admission against the cross-implementation vectors.

Each case in ``test/vectors/srh_admission.json`` carries a wire packet and a
fixed spec-derived verdict (``admit_in_transit``, ``admit_consumed``, or
``reject``) generated independently of the LICHEN implementation by
``test/vectors/generate_srh_admission.py`` per the C router's
``parse_ipv6_dispatch`` policy. The same corpus is consumed by the Rust unit
test ``lichen-node/src/rpl_stack/tests.rs::srh_admission_vectors_match_c_router_policy``.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from lichen.ipv6.packet import IPv6Packet, PacketError
from lichen.rpl.routing import RoutingError, survey_source_route

VECTORS_PATH = Path(__file__).resolve().parents[3] / "test" / "vectors" / "srh_admission.json"
SCHEMA_PATH = VECTORS_PATH.with_name("srh_admission.schema.json")


def _document() -> dict:
    document = json.loads(VECTORS_PATH.read_text())
    jsonschema.Draft7Validator(json.loads(SCHEMA_PATH.read_text())).validate(document)
    return document


CASES = _document()["cases"]


def actual_verdict(packet_hex: str) -> str:
    try:
        packet = IPv6Packet.from_bytes(bytes.fromhex(packet_hex), strict=True)
        in_transit = survey_source_route(packet)
    except (PacketError, RoutingError):
        return "reject"
    return "admit_in_transit" if in_transit else "admit_consumed"


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_srh_admission_vector(case: dict) -> None:
    assert actual_verdict(case["packet"]) == case["verdict"]


def test_corpus_pins_in_transit_precedence() -> None:
    """The corpus must cover the forwarding-precedence attack class."""
    assert any(case["verdict"] == "admit_in_transit" for case in CASES)
