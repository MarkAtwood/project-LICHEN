# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the FNV-1a32 (hash_32) vectors through production Python code.

Every standard-basis (0x811c9dc5) hash_32 implementation in the Python
package must agree with the shared vectors, which the generator pins
against the published FNV reference values before emitting. The keyed
LICH-basis variant in lichen.crypto.identity is a different function and
is deliberately not exercised here.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen.ccp import hash_32 as hash_32_ccp
from lichen.channel_plan import hash_32 as hash_32_channel_plan
from lichen.link.channel import hash_32 as hash_32_link_channel
from lichen.timing.sfn import hash_32 as hash_32_sfn

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test" / "vectors"

FNV1A32_BASIS = 0x811C9DC5
FNV1A32_PRIME = 0x01000193
U32_MASK = (1 << 32) - 1


def _fnv1a32(data: bytes) -> int:
    """Literal FNV-1a 32-bit transcription, independent of generator and LICHEN."""
    value = FNV1A32_BASIS
    for octet in data:
        value = ((value ^ octet) * FNV1A32_PRIME) & U32_MASK
    return value


IMPLEMENTATIONS: tuple[tuple[str, Callable[[bytes], int]], ...] = (
    ("lichen.timing.sfn.hash_32", hash_32_sfn),
    ("lichen.channel_plan.hash_32", hash_32_channel_plan),
    ("lichen.ccp.hash_32", hash_32_ccp),
    ("lichen.link.channel.hash_32", hash_32_link_channel),
)


def _load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


def test_hash_32_document_matches_shared_schema() -> None:
    document = _load("hash_32.json")
    errors = sorted(
        Draft7Validator(_load("schema.json")).iter_errors(document),
        key=lambda error: list(error.path),
    )
    assert not errors, [error.message for error in errors]


def test_vector_names_and_inputs_are_unique() -> None:
    vectors = _load("hash_32.json")["vectors"]
    names = [vector["name"] for vector in vectors]
    assert len(names) == len(set(names)), "duplicate vector name would be silently collapsed"
    inputs = [(vector["input_hex"], vector["output"]) for vector in vectors]
    assert len(inputs) == len(set(inputs)), "duplicate input adds no coverage"


def test_document_outputs_match_independent_oracle() -> None:
    for vector in _load("hash_32.json")["vectors"]:
        data = bytes.fromhex(vector["input_hex"])
        assert _fnv1a32(data) == int(vector["output"], 16), vector["name"]


def test_document_pins_published_fnv_reference_values() -> None:
    vectors = {v["name"]: v for v in _load("hash_32.json")["vectors"]}
    assert vectors["empty_input"]["output"] == "0x811c9dc5"
    assert vectors["ascii_a"]["output"] == "0xe40c292c"
    assert vectors["ascii_foobar"]["output"] == "0xbf9cf968"


def test_production_hash_32_matches_every_vector() -> None:
    document = _load("hash_32.json")
    for vector in document["vectors"]:
        data = bytes.fromhex(vector["input_hex"])
        expected = int(vector["output"], 16)
        for label, implementation in IMPLEMENTATIONS:
            assert implementation(data) == expected, (vector["name"], label)


def test_byte_order_probe_vectors_differ() -> None:
    vectors = {v["name"]: v for v in _load("hash_32.json")["vectors"]}
    assert (
        vectors["u32_be_one"]["output"] != vectors["u32_le_one_probe"]["output"]
    ), "big- and little-endian encodings of integer 1 must hash differently"
