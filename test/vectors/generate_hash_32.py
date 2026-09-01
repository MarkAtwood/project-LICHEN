#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate implementation-independent FNV-1a32 (hash_32) vectors.

The oracle below is a literal transcription of the FNV-1a 32-bit algorithm
(basis 0x811c9dc5, prime 0x01000193). It imports no LICHEN code; at generation
time it pins itself against the published FNV reference test vectors
(chongo's FNV page, also distributed as draft-eastlake-fnv) before any
LICHEN-domain vector is emitted, so a wrong oracle cannot regenerate
self-consistent garbage.

Covers the input shapes LICHEN hashes for slot/channel selection:
EUI-64 identifiers, 16-byte DODAG IDs, big-endian integer fields (SFN, epoch)
at u16/u32/u64 widths, and composite seed||field buffers. Byte-order probes
contrast big- and little-endian encodings of the same integer. The standard
FNV-1a32 basis is what spec/02a §2a.2 mandates; the keyed LICH-basis variant
in lichen.crypto.identity is a different function and is out of scope.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, TypedDict

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import atomic_write_json_batch, json_bytes, read_bounded_exact  # noqa: E402

OUTPUT = VECTORS_DIR / "hash_32.json"
U32_MASK = (1 << 32) - 1
FNV1A32_BASIS = 0x811C9DC5
FNV1A32_PRIME = 0x01000193

# Published FNV-1a 32-bit reference vectors (external oracle).
PUBLISHED_VECTORS: tuple[tuple[str, int], ...] = (
    ("", 0x811C9DC5),
    ("a", 0xE40C292C),
    ("b", 0xE70C2DE5),
    ("foobar", 0xBF9CF968),
)


class Hash32Vector(TypedDict):
    name: str
    description: str
    input_hex: str
    output: str


class Hash32Document(TypedDict):
    format_version: int
    name: str
    description: str
    spec: str
    vectors: list[Hash32Vector]


def fnv1a32(data: bytes) -> int:
    """Literal FNV-1a 32-bit oracle; no LICHEN imports."""
    value = FNV1A32_BASIS
    for octet in data:
        value = ((value ^ octet) * FNV1A32_PRIME) & U32_MASK
    return value


def check_oracle_against_published_vectors() -> None:
    for text, expected in PUBLISHED_VECTORS:
        actual = fnv1a32(text.encode("ascii"))
        if actual != expected:
            raise SystemExit(
                f"oracle disagrees with published FNV-1a32 vector "
                f"{text!r}: got {actual:#010x}, expected {expected:#010x}"
            )


def vector(name: str, description: str, domain: str, data: bytes) -> Hash32Vector:
    return {
        "name": name,
        "description": f"[{domain}] {description}",
        "input_hex": data.hex(),
        "output": f"{fnv1a32(data):#010x}",
    }


def document() -> Hash32Document:
    eui64_mixed = bytes.fromhex("deadbeefcafebabe")
    dodag16_mixed = bytes(range(16))
    sfn_one_be = (1).to_bytes(4, "big")
    return {
        "format_version": 2,
        "name": "hash_32",
        "description": (
            "FNV-1a 32-bit (basis 0x811c9dc5, prime 0x01000193) over byte "
            "strings, the hash LICHEN uses for TDMA slot and channel "
            "selection. Inputs are recorded as lowercase hex of the exact "
            "byte sequence hashed: EUI-64 and DODAG ID identifiers in "
            "network byte order, integer fields (SFN, epoch) in big-endian "
            "at u16/u32/u64 widths, and composite seed||field buffers. "
            "Byte-order probes contrast big- and little-endian encodings of "
            "the same integer and must hash differently. The edge vectors "
            "are the published FNV reference values; the generator oracle "
            "pins against them before emitting LICHEN-domain vectors. "
            "Expected values come from this standalone oracle, not LICHEN "
            "code; the keyed LICH-basis variant in lichen.crypto.identity "
            "is a different function and is not covered here."
        ),
        "spec": "spec/02a-coordinated-capacity.md#2a2-tdma-slots-and-hash-selection",
        "vectors": [
            vector(
                "empty_input",
                "Published FNV reference: hashing the empty string yields the basis.",
                "edge",
                b"",
            ),
            vector(
                "ascii_a",
                "Published FNV reference single-byte vector.",
                "edge",
                b"a",
            ),
            vector(
                "ascii_foobar",
                "Published FNV reference multi-byte vector.",
                "edge",
                b"foobar",
            ),
            vector("eui64_all_zeros", "All-zero EUI-64.", "eui64", bytes(8)),
            vector(
                "eui64_all_ones",
                "All-ones EUI-64.",
                "eui64",
                b"\xff" * 8,
            ),
            vector(
                "eui64_mixed",
                "Mixed-pattern EUI-64.",
                "eui64",
                eui64_mixed,
            ),
            vector(
                "u16_be_max",
                "u16 field 0xffff in big-endian (two-byte width).",
                "integer_be",
                (0xFFFF).to_bytes(2, "big"),
            ),
            vector(
                "u32_be_one",
                "SFN 1 as u32 big-endian.",
                "integer_be",
                sfn_one_be,
            ),
            vector(
                "u32_be_max",
                "SFN/epoch 0xffffffff as u32 big-endian.",
                "integer_be",
                (0xFFFFFFFF).to_bytes(4, "big"),
            ),
            vector(
                "u32_le_one_probe",
                "Little-endian encoding of integer 1; must differ from u32_be_one.",
                "integer_le",
                (1).to_bytes(4, "little"),
            ),
            vector(
                "u64_be_one",
                "u64 field 1 in big-endian (eight-byte width).",
                "integer_be",
                (1).to_bytes(8, "big"),
            ),
            vector(
                "u64_be_mixed",
                "u64 field 0x0123456789abcdef in big-endian (eight-byte width).",
                "integer_be",
                bytes.fromhex("0123456789abcdef"),
            ),
            vector(
                "dodag16_all_zeros",
                "All-zero 16-byte DODAG ID.",
                "dodag_id",
                bytes(16),
            ),
            vector(
                "dodag16_all_ones",
                "All-ones 16-byte DODAG ID.",
                "dodag_id",
                b"\xff" * 16,
            ),
            vector(
                "dodag16_mixed",
                "Mixed-pattern 16-byte DODAG ID (0x00..0x0f).",
                "dodag_id",
                dodag16_mixed,
            ),
            vector(
                "mixed_eui64_plus_sfn_be",
                "Composite input-shape probe: EUI-64 followed by u32 value 1 big-endian. Slot selection adds SFN numerically and must not hash a concatenation; this vector pins the raw primitive on such buffers only.",
                "mixed",
                eui64_mixed + sfn_one_be,
            ),
            vector(
                "mixed_dodag16_plus_epoch_be",
                "Composite input-shape probe: 16-byte DODAG ID followed by u32 value 1 big-endian.",
                "mixed",
                dodag16_mixed + sfn_one_be,
            ),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare canonical output byte-for-byte without writing",
    )
    arguments = parser.parse_args(argv)
    check_oracle_against_published_vectors()
    doc: dict[str, Any] = document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            print("out-of-date vector file: hash_32.json", file=sys.stderr)
            return 1
        if current != json_bytes(doc):
            print("out-of-date vector file: hash_32.json", file=sys.stderr)
            return 1
    else:
        atomic_write_json_batch([(OUTPUT, doc)])
    action = "Checked" if arguments.check else "Wrote"
    print(f"{action} {len(doc['vectors'])} vectors in hash_32.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
