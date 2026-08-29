#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate u32-carry TDMA slot-assignment vectors (spec 09-packets-timing.md
14.7, 02a-coordinated-capacity.md 2a.2).

Every case selects SFN so that ``hash_32(eui64) + sfn`` exceeds 2**32 and pins
a NON-power-of-two ``num_slots``, so the only formula that produces the pinned
slot is the wrapping sum:

    slot = ((hash_32(eui64) + (sfn & 0xFFFFFFFF)) & 0xFFFFFFFF) % num_slots

The generator embeds an independent FNV-1a32 oracle (public reference
parameters: offset basis 0x811c9dc5, prime 0x01000193) and cross-checks every
pinned value against the Python reference implementation
(:func:`lichen.timing.sfn.slot_for`, :func:`lichen.timing.sfn.hash_32`) before
writing. ``unwrapped_wrong_slot`` is the slot an implementation that skips the
u32 mask would report; it is deliberately different from ``expected_slot`` in
every case, which makes the corpus discriminate wrapping.

Run:
    PYTHONPATH=python/src python3 test/vectors/generate_ccp_slot_hash_carry.py
"""

from __future__ import annotations

import sys
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))
REPO_ROOT = VECTORS_DIR.parents[1]
if str(REPO_ROOT / "python" / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "python" / "src"))

from atomic_json import atomic_write_json  # noqa: E402

from lichen.timing.sfn import hash_32 as reference_hash_32  # noqa: E402
from lichen.timing.sfn import slot_for as reference_slot_for  # noqa: E402

OUTPUT = VECTORS_DIR / "ccp_slot_hash_carry.json"

U32_MASK = 0xFFFFFFFF
U32_LIMIT = 1 << 32


def _oracle_hash_32(data: bytes) -> int:
    """Independent FNV-1a32 (basis 0x811c9dc5, prime 0x01000193)."""
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & U32_MASK
    return h


def _oracle_slot(eui64: bytes, sfn: int, num_slots: int) -> int:
    """Independent spec 14.7 slot: wrapping u32 sum before the modulus."""
    wrapped_sum = (_oracle_hash_32(eui64) + (sfn & U32_MASK)) & U32_MASK
    return wrapped_sum % num_slots


# (name, eui64_hex, sfn, num_slots, description)
# sfn values are chosen so hash_32(eui64) + sfn crosses 2**32; several are the
# exact wrap boundary (sum == 2**32, wrapped sum == 0).
CASES = [
    (
        "carry_exact_wrap_boundary_ns3",
        "0102030405060708",
        0xD7FB9873,
        3,
        "sfn = 2**32 - hash_32(eui64): the sum lands exactly on the u32 "
        "boundary, the wrapped sum is 0, and mod 3 the unwrapped sum points "
        "at a different slot",
    ),
    (
        "carry_one_past_boundary_ns5",
        "0102030405060708",
        0xD7FB9874,
        5,
        "one superframe past the exact boundary: wrapped sum is 1, mod 5 the "
        "unwrapped sum points elsewhere",
    ),
    (
        "carry_max_sfn_ns7",
        "0011223344556677",
        0xFFFFFFFF,
        7,
        "maximum SFN with a high hash value: the addition carries out of u32 "
        "before the non-power-of-two mod 7",
    ),
    (
        "carry_large_sfn_ns6",
        "aabbccddeeff0011",
        0x0D2BE044,
        6,
        "one past the minimum SFN that carries this EUI's hash over the u32 "
        "boundary; wrapped sum is 1, mod 6 the unwrapped sum differs",
    ),
    (
        "carry_all_ones_eui_ns9",
        "ffffffffffffffff",
        0x9351F5A4,
        9,
        "all-ones EUI-64 one superframe past its exact wrap boundary, mod 9",
    ),
    (
        "carry_all_zeros_eui_ns11",
        "0000000000000000",
        0x641E8E9B,
        11,
        "all-zero EUI-64 landing exactly on the u32 boundary: wrapped sum is "
        "0, mod 11 the unwrapped sum is not",
    ),
    (
        "carry_ul_flipped_eui_ns13",
        "0200000000000001",
        0xAA5BD1EC,
        13,
        "U/L-flipped minimal EUI-64 landing exactly on the u32 boundary, "
        "mod 13",
    ),
    (
        "carry_two_before_max_ns10",
        "0011223344556677",
        0xFFFFFFFE,
        10,
        "two superframes before SFN max: a mid-range wrapped sum, mod 10 the "
        "unwrapped sum picks a different slot",
    ),
]


def build_document() -> dict:
    vectors = []
    for name, eui64_hex, sfn, num_slots, description in CASES:
        eui64 = bytes.fromhex(eui64_hex)
        oracle_hash = _oracle_hash_32(eui64)
        oracle_slot = _oracle_slot(eui64, sfn, num_slots)
        # Cross-check the independent oracle against the Python reference
        # implementation; the file is only written when both agree.
        assert oracle_hash == reference_hash_32(eui64), name
        assert oracle_slot == reference_slot_for(eui64, sfn, num_slots), name

        unwrapped_sum = oracle_hash + sfn
        unwrapped_wrong_slot = unwrapped_sum % num_slots
        wrapped_sum = unwrapped_sum & U32_MASK
        # Corpus invariants: every case actually carries, and the modulus is
        # non-power-of-two so the unwrapped sum picks a different slot.
        assert unwrapped_sum >= U32_LIMIT, name
        assert wrapped_sum < U32_LIMIT, name
        assert unwrapped_wrong_slot != oracle_slot, name

        vectors.append(
            {
                "name": name,
                "description": description,
                "eui64_hex": eui64_hex,
                "sfn": sfn,
                "sfn_hex": f"0x{sfn:08x}",
                "num_slots": num_slots,
                "expected_hash_32": f"0x{oracle_hash:08x}",
                "expected_hash_32_decimal": oracle_hash,
                "expected_wrapped_sum": f"0x{wrapped_sum:08x}",
                "expected_slot": oracle_slot,
                "unwrapped_wrong_slot": unwrapped_wrong_slot,
                "formula": (
                    f"((0x{oracle_hash:08x} + 0x{sfn:08x}) & 0xFFFFFFFF) % "
                    f"{num_slots} = 0x{wrapped_sum:08x} % {num_slots} = "
                    f"{oracle_slot}"
                ),
            }
        )

    names = [v["name"] for v in vectors]
    assert len(names) == len(set(names)) == 8, "consumer pins exactly 8 unique cases"
    return {
        "$schema": "./schema.json",
        "format_version": 2,
        "description": (
            "LICHEN CCP TDMA slot assignment with u32 carry test vectors (spec "
            "09-packets-timing.md 14.7, 02a-coordinated-capacity.md 2a.2). Every "
            "case selects SFN so that hash_32(eui64) + sfn exceeds 2**32 and a "
            "NON-power-of-two num_slots, pinning slot_for(eui64, sfn, num_slots) "
            "= ((hash_32(eui64) + (sfn & 0xFFFFFFFF)) & 0xFFFFFFFF) % num_slots: "
            "the u32 sum must wrap BEFORE the modulus. unwrapped_wrong_slot is "
            "the slot an implementation that skips the mask would report; it "
            "differs from expected_slot in every case. Consumed by "
            "python/tests/test_ccp_sync_vector_consumers.py."
        ),
        "oracle_provenance": (
            "Independent FNV-1a32 oracle (offset basis 0x811c9dc5, prime "
            "0x01000193, public-domain reference parameters) cross-checked "
            "against the Python reference implementation lichen.timing.sfn "
            "(hash_32, slot_for); every pinned value is computed, never "
            "hand-invented."
        ),
        "vectors": vectors,
    }


def main() -> None:
    atomic_write_json(OUTPUT, build_document())
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
