# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for lichen.link.slot_coordination module.

Tests slot coordination oracle against spec 02a-coordinated-capacity.md and
test vectors in test/vectors/ccp_*.json.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.link.slot_coordination import (
    HOLDOFF_SUPERFRAMES,
    MAX_CANDIDATES,
    MAX_SLOT_MAP_ENTRIES,
    MultiRootState,
    RootCandidate,
    SlotMapError,
    VersionChangeOutcome,
    compare_iid,
    encode_slot_map,
    hash_32,
    select_root,
    sfn_delta,
    slot_for,
    tx_allowed,
    validate_slot_map,
)

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


class TestSlotMapValidation:
    """Test validate_slot_map per spec 02a-coordinated-capacity.md:80."""

    def test_empty_slot_map_valid(self) -> None:
        is_valid, error = validate_slot_map([], 8)
        assert is_valid
        assert error is None

    def test_single_valid_slot(self) -> None:
        is_valid, error = validate_slot_map([3], 8)
        assert is_valid
        assert error is None

    def test_multiple_valid_slots_sorted(self) -> None:
        is_valid, error = validate_slot_map([0, 1, 3, 7], 8)
        assert is_valid
        assert error is None

    def test_slot_at_boundary_valid(self) -> None:
        is_valid, error = validate_slot_map([7], 8)
        assert is_valid
        assert error is None

    def test_slot_at_boundary_invalid(self) -> None:
        is_valid, error = validate_slot_map([8], 8)
        assert not is_valid
        assert error == SlotMapError.SLOT_OUT_OF_BOUNDS

    def test_slot_out_of_bounds(self) -> None:
        is_valid, error = validate_slot_map([0, 3, 8, 12], 8)
        assert not is_valid
        assert error == SlotMapError.SLOT_OUT_OF_BOUNDS

    def test_unsorted_slots(self) -> None:
        is_valid, error = validate_slot_map([3, 1, 5, 2], 16)
        assert not is_valid
        assert error == SlotMapError.UNSORTED

    def test_duplicate_slots(self) -> None:
        is_valid, error = validate_slot_map([1, 1, 3], 8)
        assert not is_valid
        assert error == SlotMapError.DUPLICATE

    def test_descending_slots(self) -> None:
        is_valid, error = validate_slot_map([7, 5, 3, 1], 8)
        assert not is_valid
        assert error == SlotMapError.UNSORTED

    def test_zero_num_slots(self) -> None:
        is_valid, error = validate_slot_map([0], 0)
        assert not is_valid
        assert error == SlotMapError.SLOT_OUT_OF_BOUNDS

    def test_all_slots_valid(self) -> None:
        is_valid, error = validate_slot_map([0, 1, 2, 3, 4, 5, 6, 7], 8)
        assert is_valid
        assert error is None


class TestSlotMapVectors:
    """Test validate_slot_map against test vectors."""

    @pytest.fixture(scope="class")
    def vectors(self) -> list[dict]:
        path = VECTORS_DIR / "ccp_slot_map_validation.json"
        with open(path) as f:
            doc = json.load(f)
        return doc["vectors"]

    def test_vectors_exist(self, vectors: list[dict]) -> None:
        assert len(vectors) > 0

    @pytest.mark.parametrize(
        "vector",
        json.loads((VECTORS_DIR / "ccp_slot_map_validation.json").read_text())["vectors"],
        ids=lambda v: v["name"],
    )
    def test_slot_map_vector(self, vector: dict) -> None:
        slot_map = vector["slot_map"]
        num_slots = vector["num_slots"]
        expected_valid = vector["expected_valid"]
        expected_error = vector["expected_error"]

        is_valid, error = validate_slot_map(slot_map, num_slots)

        assert is_valid == expected_valid, (
            f"{vector['name']}: expected valid={expected_valid}, got {is_valid}"
        )

        if not expected_valid:
            error_str = error.name.lower() if error else None
            assert error_str == expected_error, (
                f"{vector['name']}: expected error={expected_error}, got {error_str}"
            )


class TestTxAllowed:
    """Test tx_allowed slot permission check."""

    def test_tx_allowed_in_slot(self) -> None:
        assert tx_allowed([0, 3, 5], 3, 8)

    def test_tx_not_allowed_outside_slot(self) -> None:
        assert not tx_allowed([0, 3, 5], 2, 8)

    def test_tx_not_allowed_empty_slot_map(self) -> None:
        assert not tx_allowed([], 0, 8)

    def test_tx_not_allowed_invalid_current_slot(self) -> None:
        assert not tx_allowed([0, 3, 5], -1, 8)
        assert not tx_allowed([0, 3, 5], 8, 8)

    def test_tx_allowed_first_slot(self) -> None:
        assert tx_allowed([0], 0, 8)

    def test_tx_allowed_last_slot(self) -> None:
        assert tx_allowed([7], 7, 8)


class TestRootCandidate:
    """Test RootCandidate for multi-root conflict resolution."""

    def test_from_beacon_defaults_fail_closed(self) -> None:
        """SECURITY: signature_valid defaults False until verification succeeds."""
        candidate = RootCandidate.from_beacon(
            eui64=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            dodag_preference=128,
            stratum=1,
            rssi_ema=-80.0,
            snr_ema=10.0,
        )
        assert candidate.signature_valid is False
        assert select_root([candidate]) is None

    def test_from_beacon_signature_opt_in_after_verification(self) -> None:
        """signature_valid=True is an explicit post-verification opt-in."""
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        candidate = RootCandidate.from_beacon(
            eui64=eui64,
            dodag_preference=128,
            stratum=1,
            rssi_ema=-80.0,
            snr_ema=10.0,
            signature_valid=True,
        )
        assert candidate.eui64 == eui64
        assert candidate.signature_valid is True

    def test_from_beacon_invalid_eui64(self) -> None:
        with pytest.raises(ValueError, match="eui64 must be 8 bytes"):
            RootCandidate.from_beacon(eui64=b"\x01\x02\x03", dodag_preference=0)

    def test_ordering_by_dodag_preference(self) -> None:
        # Higher preference wins (lower sort key)
        high_pref = RootCandidate.from_beacon(eui64=b"\x00" * 8, dodag_preference=200)
        low_pref = RootCandidate.from_beacon(eui64=b"\xff" * 8, dodag_preference=100)
        assert high_pref < low_pref

    def test_ordering_by_stratum(self) -> None:
        # Equal preference, lower stratum wins
        gnss = RootCandidate.from_beacon(eui64=b"\xff" * 8, dodag_preference=128, stratum=0)
        ntp = RootCandidate.from_beacon(eui64=b"\x00" * 8, dodag_preference=128, stratum=1)
        assert gnss < ntp

    def test_ordering_by_rssi_snr(self) -> None:
        # Equal preference and stratum, higher RSSI+SNR wins
        strong = RootCandidate.from_beacon(
            eui64=b"\xff" * 8,
            dodag_preference=128,
            stratum=1,
            rssi_ema=-70.0,
            snr_ema=15.0,
        )
        weak = RootCandidate.from_beacon(
            eui64=b"\x00" * 8,
            dodag_preference=128,
            stratum=1,
            rssi_ema=-100.0,
            snr_ema=5.0,
        )
        assert strong < weak

    def test_ordering_by_iid_tiebreak(self) -> None:
        # All else equal, lower IID wins
        low_iid = RootCandidate.from_beacon(
            eui64=b"\x00\x00\x00\x00\x00\x00\x00\x01",
            dodag_preference=128,
            stratum=1,
            rssi_ema=-80.0,
            snr_ema=10.0,
        )
        high_iid = RootCandidate.from_beacon(
            eui64=b"\x00\x00\x00\x00\x00\x00\x00\x02",
            dodag_preference=128,
            stratum=1,
            rssi_ema=-80.0,
            snr_ema=10.0,
        )
        assert low_iid < high_iid


class TestSelectRoot:
    """Test select_root conflict resolution."""

    def test_select_root_empty(self) -> None:
        assert select_root([]) is None

    def test_select_root_single_valid(self) -> None:
        candidate = RootCandidate.from_beacon(eui64=b"\x01" * 8, signature_valid=True)
        result = select_root([candidate])
        assert result is candidate

    def test_select_root_single_invalid_signature(self) -> None:
        candidate = RootCandidate.from_beacon(eui64=b"\x01" * 8, signature_valid=False)
        assert select_root([candidate]) is None

    def test_select_root_filters_invalid_signatures(self) -> None:
        valid = RootCandidate.from_beacon(
            eui64=b"\xff" * 8, dodag_preference=100, signature_valid=True
        )
        invalid = RootCandidate.from_beacon(
            eui64=b"\x00" * 8, dodag_preference=200, signature_valid=False
        )
        result = select_root([invalid, valid])
        assert result is valid

    def test_select_root_best_candidate(self) -> None:
        best = RootCandidate.from_beacon(
            eui64=b"\x00" * 8, dodag_preference=200, stratum=0, signature_valid=True
        )
        worst = RootCandidate.from_beacon(
            eui64=b"\xff" * 8, dodag_preference=100, stratum=2, signature_valid=True
        )
        result = select_root([worst, best])
        assert result is best

    def test_select_root_iid_tiebreak(self) -> None:
        # Same metrics, lower IID wins
        low_iid = RootCandidate.from_beacon(
            eui64=b"\x00\x00\x00\x00\x00\x00\x00\x01",
            dodag_preference=128,
            stratum=1,
            signature_valid=True,
        )
        high_iid = RootCandidate.from_beacon(
            eui64=b"\x00\x00\x00\x00\x00\x00\x00\x99",
            dodag_preference=128,
            stratum=1,
            signature_valid=True,
        )
        result = select_root([high_iid, low_iid])
        assert result is low_iid


class TestCompareIid:
    """Test compare_iid tiebreak comparison."""

    def test_compare_iid_less(self) -> None:
        a = b"\x00\x00\x00\x00\x00\x00\x00\x01"
        b_eui = b"\x00\x00\x00\x00\x00\x00\x00\x02"
        assert compare_iid(a, b_eui) == -1

    def test_compare_iid_greater(self) -> None:
        a = b"\x00\x00\x00\x00\x00\x00\x00\x02"
        b_eui = b"\x00\x00\x00\x00\x00\x00\x00\x01"
        assert compare_iid(a, b_eui) == 1

    def test_compare_iid_equal(self) -> None:
        a = b"\x00\x00\x00\x00\x00\x00\x00\x01"
        assert compare_iid(a, a) == 0

    def test_compare_iid_big_endian(self) -> None:
        # First byte is most significant
        a = b"\x00\x00\x00\x00\x00\x00\x00\xff"  # 255
        b_eui = b"\x00\x00\x00\x00\x00\x00\x01\x00"  # 256
        assert compare_iid(a, b_eui) == -1  # 255 < 256

    def test_compare_iid_invalid_length(self) -> None:
        with pytest.raises(ValueError):
            compare_iid(b"\x01\x02\x03", b"\x01" * 8)


class TestSlotForVectors:
    """Test slot_for against SFN wrap test vectors."""

    @pytest.mark.parametrize(
        "vector",
        [
            v
            for v in json.loads((VECTORS_DIR / "ccp_sfn_wrap_slot_hash.json").read_text())[
                "vectors"
            ]
            if "eui64_hex" in v and "sfn" in v and "num_slots" in v
        ],
        ids=lambda v: v["name"],
    )
    def test_slot_for_vector(self, vector: dict) -> None:
        eui64 = bytes.fromhex(vector["eui64_hex"])
        sfn = vector.get("sfn", vector.get("sfn_masked", 0))
        if isinstance(sfn, str):
            sfn = int(sfn, 16)
        # Handle large SFN values that need masking
        if "sfn_large" in vector:
            sfn = vector["sfn_large"] & 0xFFFFFFFF
        num_slots = vector["num_slots"]
        expected_slot = vector["expected_slot"]

        result = slot_for(eui64, sfn, num_slots)
        assert result == expected_slot, (
            f"{vector['name']}: expected slot={expected_slot}, got {result}"
        )


class TestSfnDeltaVectors:
    """Test sfn_delta against SFN wrap test vectors."""

    @pytest.mark.parametrize(
        "vector",
        [
            v
            for v in json.loads((VECTORS_DIR / "ccp_sfn_wrap_slot_hash.json").read_text())[
                "vectors"
            ]
            if "current_sfn" in v and "last_sfn" in v
        ],
        ids=lambda v: v["name"],
    )
    def test_sfn_delta_vector(self, vector: dict) -> None:
        current_sfn = vector["current_sfn"]
        last_sfn = vector["last_sfn"]
        expected_delta = vector["expected_delta"]

        result = sfn_delta(current_sfn, last_sfn)
        assert result == expected_delta, (
            f"{vector['name']}: expected delta={expected_delta}, got {result}"
        )


class TestHash32Vectors:
    """Test hash_32 against reference vectors."""

    @pytest.mark.parametrize(
        "vector",
        [
            v
            for v in json.loads((VECTORS_DIR / "ccp_sfn_wrap_slot_hash.json").read_text())[
                "vectors"
            ]
            if "expected_hash_32" in v and "eui64_hex" in v
        ],
        ids=lambda v: v["name"],
    )
    def test_hash_32_vector(self, vector: dict) -> None:
        eui64 = bytes.fromhex(vector["eui64_hex"])
        expected_hex = vector["expected_hash_32"]
        expected = int(expected_hex, 16) if isinstance(expected_hex, str) else expected_hex

        result = hash_32(eui64)
        assert result == expected, (
            f"{vector['name']}: expected hash={hex(expected)}, got {hex(result)}"
        )


class TestConstants:
    """Test module constants."""

    def test_holdoff_superframes(self) -> None:
        assert HOLDOFF_SUPERFRAMES == 3

    def test_max_candidates(self) -> None:
        """MAX_CANDIDATES mirrors the Rust DoS-guard constant."""
        assert MAX_CANDIDATES == 32


class TestMultiRootState:
    """Test MultiRootState for spec 02a.5.4 version change during multi-root conflict."""

    def test_initial_state(self) -> None:
        state = MultiRootState()
        assert state.current_root is None
        assert state.current_version == 0
        assert state.holdoff_counter == 0
        assert not state.is_in_holdoff()

    def test_add_candidate_filters_invalid_signatures(self) -> None:
        """Per 2a.5.1: Only candidates with valid signatures are retained."""
        state = MultiRootState()
        valid = RootCandidate.from_beacon(eui64=b"\x01" * 8, signature_valid=True)
        invalid = RootCandidate.from_beacon(eui64=b"\x02" * 8, signature_valid=False)

        assert state.add_candidate(valid) is True
        assert state.add_candidate(invalid) is False

        assert len(state.candidates) == 1
        assert state.candidates[0].eui64 == valid.eui64

    def test_add_candidate_enforces_max_candidates(self) -> None:
        """SECURITY: candidates capped at MAX_CANDIDATES=32 (mirrors Rust)."""
        state = MultiRootState()
        for i in range(MAX_CANDIDATES):
            candidate = RootCandidate.from_beacon(
                eui64=bytes([i + 1]) + b"\x00" * 7, signature_valid=True
            )
            assert state.add_candidate(candidate) is True
        assert len(state.candidates) == MAX_CANDIDATES

        overflow = RootCandidate.from_beacon(eui64=b"\xff" * 8, signature_valid=True)
        assert state.add_candidate(overflow) is False
        assert len(state.candidates) == MAX_CANDIDATES

    def test_process_beacon_window_selects_best(self) -> None:
        state = MultiRootState()
        best = RootCandidate.from_beacon(
            eui64=b"\x01" * 8, dodag_preference=200, signature_valid=True
        )
        worse = RootCandidate.from_beacon(
            eui64=b"\x02" * 8, dodag_preference=100, signature_valid=True
        )

        state.add_candidate(worse)
        state.add_candidate(best)
        selected = state.process_beacon_window()

        assert selected is best
        assert state.current_root is best

    def test_holdoff_initiated_on_root_change(self) -> None:
        """Per 2a.5.3: Defer transition for 3 superframes."""
        state = MultiRootState()
        first = RootCandidate.from_beacon(
            eui64=b"\x01" * 8, dodag_preference=100, signature_valid=True
        )
        state.add_candidate(first)
        state.process_beacon_window()
        state.clear_candidates()

        # Now a better root appears
        second = RootCandidate.from_beacon(
            eui64=b"\x02" * 8, dodag_preference=200, signature_valid=True
        )
        state.add_candidate(second)
        state.process_beacon_window()

        assert state.is_in_holdoff()
        assert state.holdoff_counter == HOLDOFF_SUPERFRAMES
        assert state.holdoff_selected is second
        # Current root unchanged until holdoff completes
        assert state.current_root is first

    def test_holdoff_completes_after_3_superframes(self) -> None:
        """Per 2a.5.3: Transition after 3-superframe holdoff."""
        state = MultiRootState()
        first = RootCandidate.from_beacon(
            eui64=b"\x01" * 8, dodag_preference=100, signature_valid=True
        )
        state.add_candidate(first)
        state.process_beacon_window()
        state.clear_candidates()

        second = RootCandidate.from_beacon(
            eui64=b"\x02" * 8, dodag_preference=200, signature_valid=True
        )
        state.add_candidate(second)
        state.process_beacon_window()
        state.clear_candidates()

        # Advance through holdoff
        assert not state.advance_holdoff()  # 2 remaining
        assert not state.advance_holdoff()  # 1 remaining
        assert state.advance_holdoff()  # Complete

        assert not state.is_in_holdoff()
        assert state.current_root is second

    def test_version_change_resets_sfn(self) -> None:
        """Per 2a.5.4: Reset SFN relative to current root's new epoch."""
        state = MultiRootState()
        root = RootCandidate.from_beacon(eui64=b"\x01" * 8, signature_valid=True)
        state.add_candidate(root)
        state.process_beacon_window()
        state.current_version = 1

        result = state.on_version_change(new_version=2, signature_valid=True)

        assert result.outcome == VersionChangeOutcome.ACCEPTED
        assert result.sfn_reset is True
        assert state.current_version == 2

    def test_version_change_no_change_same_version(self) -> None:
        state = MultiRootState()
        state.current_version = 5

        result = state.on_version_change(new_version=5, signature_valid=True)

        assert result.outcome == VersionChangeOutcome.NO_CHANGE
        assert result.sfn_reset is False

    def test_version_change_during_holdoff_resets_counter(self) -> None:
        """Per 2a.5.4: Version change resets holdoff counter to zero and restarts."""
        state = MultiRootState()
        first = RootCandidate.from_beacon(
            eui64=b"\x01" * 8, dodag_preference=100, signature_valid=True
        )
        state.add_candidate(first)
        state.process_beacon_window()
        state.clear_candidates()

        second = RootCandidate.from_beacon(
            eui64=b"\x02" * 8, dodag_preference=200, signature_valid=True
        )
        state.add_candidate(second)
        state.process_beacon_window()
        state.current_version = 1

        # Advance holdoff partway
        state.advance_holdoff()  # 2 remaining
        assert state.holdoff_counter == 2

        # Version change should reset holdoff
        result = state.on_version_change(new_version=2, signature_valid=True)

        assert result.outcome == VersionChangeOutcome.HOLDOFF_RESET
        assert result.holdoff_reset is True
        assert result.sfn_reset is True
        assert state.holdoff_counter == HOLDOFF_SUPERFRAMES  # Reset to 3

    def test_version_change_sig_fail_discards_root(self) -> None:
        """Per 2a.5.4: If signature verification fails, discard current root."""
        state = MultiRootState()
        root = RootCandidate.from_beacon(eui64=b"\x01" * 8, signature_valid=True)
        state.add_candidate(root)
        state.process_beacon_window()
        state.current_version = 1

        result = state.on_version_change(new_version=2, signature_valid=False)

        assert result.outcome == VersionChangeOutcome.SIG_FAILED_DISCARD
        assert result.evaluate_candidates is True
        assert state.current_root is None

    def test_version_change_sig_fail_during_holdoff_cancels(self) -> None:
        """Per 2a.5.4: Sig fail during holdoff -> immediately evaluate candidates."""
        state = MultiRootState()
        first = RootCandidate.from_beacon(
            eui64=b"\x01" * 8, dodag_preference=100, signature_valid=True
        )
        state.add_candidate(first)
        state.process_beacon_window()
        state.clear_candidates()

        second = RootCandidate.from_beacon(
            eui64=b"\x02" * 8, dodag_preference=200, signature_valid=True
        )
        state.add_candidate(second)
        state.process_beacon_window()
        state.current_version = 1

        # Now version change with sig failure
        result = state.on_version_change(new_version=2, signature_valid=False)

        assert result.outcome == VersionChangeOutcome.SIG_FAILED_DISCARD
        assert result.evaluate_candidates is True
        assert not state.is_in_holdoff()
        assert state.holdoff_selected is None

    def test_version_change_resets_desync_state(self) -> None:
        """Per 2a.5.4 step 2: Reset desync state that depended on prior version."""
        state = MultiRootState()
        root = RootCandidate.from_beacon(eui64=b"\x01" * 8, signature_valid=True)
        state.add_candidate(root)
        state.process_beacon_window()
        state.current_version = 1
        state.set_desync_state_version(1)  # Mark desync state depends on v1

        result = state.on_version_change(new_version=2, signature_valid=True)

        assert result.outcome == VersionChangeOutcome.ACCEPTED
        assert state.desync_state_version is None  # Reset

    def test_cancel_holdoff(self) -> None:
        state = MultiRootState()
        first = RootCandidate.from_beacon(
            eui64=b"\x01" * 8, dodag_preference=100, signature_valid=True
        )
        state.add_candidate(first)
        state.process_beacon_window()
        state.clear_candidates()

        second = RootCandidate.from_beacon(
            eui64=b"\x02" * 8, dodag_preference=200, signature_valid=True
        )
        state.add_candidate(second)
        state.process_beacon_window()

        assert state.is_in_holdoff()
        state.cancel_holdoff()

        assert not state.is_in_holdoff()
        assert state.holdoff_selected is None

    def test_reset(self) -> None:
        state = MultiRootState()
        root = RootCandidate.from_beacon(eui64=b"\x01" * 8, signature_valid=True)
        state.add_candidate(root)
        state.process_beacon_window()
        state.current_version = 5
        state.set_desync_state_version(5)

        state.reset()

        assert state.current_root is None
        assert state.current_version == 0
        assert len(state.candidates) == 0
        assert state.holdoff_counter == 0
        assert state.desync_state_version is None


class TestSlotMapWriter:
    """Test encode_slot_map (R-02a-013 root-side writer, spec 02a 2a.2).

    Byte-level expectations are cross-implementation vectors: the same
    wire bytes are pinned by the C suite (lichen/tests/tdma_beacon/main.c)
    and the Rust suite (rust/lichen-core/src/tdma_beacon.rs unit tests),
    both landed independently against the spec.
    """

    @staticmethod
    def _decode_slot_map(cbor: bytes) -> list[int]:
        """Minimal CBOR slot_map decoder mirroring the Rust parser rules.

        Accepts short-form array headers 0x80..=0x97, long form 0x98 + len;
        entries are immediate 0x00..=0x17 or 0x18-prefixed. Anything else
        fails the test.
        """
        pos = 0
        first = cbor[pos]
        pos += 1
        if 0x80 <= first <= 0x97:
            length = first - 0x80
        elif first == 0x98:
            length = cbor[pos]
            pos += 1
        else:
            pytest.fail("decoder input is not a supported array header")
        slots: list[int] = []
        for _ in range(length):
            entry = cbor[pos]
            pos += 1
            if entry <= 0x17:
                slots.append(entry)
            elif entry == 0x18:
                slots.append(cbor[pos])
                pos += 1
            else:
                pytest.fail("decoder input has unsupported entry encoding")
        assert pos == len(cbor), "trailing bytes after CBOR array"
        return slots

    def test_encode_empty(self) -> None:
        assert encode_slot_map([]) == b"\x80"

    def test_encode_short_form(self) -> None:
        # Byte vector from Rust test_slot_map_write_roundtrip_simple; the
        # C suite (main.c "slot_map writer short-form", input {0,1,2}) pins
        # the same wire shape with different values.
        assert encode_slot_map([1, 3, 5]) == b"\x83\x01\x03\x05"

    def test_encode_two_byte_entries(self) -> None:
        # Cross-impl vector: Rust test_slot_map_value_over_23 wire shape.
        assert encode_slot_map([24, 30]) == b"\x82\x18\x18\x18\x1e"

    def test_encode_header_boundary_23_24(self) -> None:
        # 23 entries: short-form header 0x80+23 == 0x97.
        slots_23 = list(range(23))
        encoded = encode_slot_map(slots_23)
        assert encoded[0] == 0x97
        assert len(encoded) == 1 + 23
        # 24 entries: long-form header 0x98 + one-byte length.
        encoded_24 = encode_slot_map(list(range(24)))
        assert encoded_24[0] == 0x98
        assert encoded_24[1] == 24

    def test_encode_long_form_30_entries(self) -> None:
        # Cross-impl vector: Rust test_slot_map_write_roundtrip_over_23_entries
        # (values 24..53 exercise two-byte entries).
        slots = list(range(24, 54))
        encoded = encode_slot_map(slots)
        assert len(encoded) == 2 + 30 * 2
        assert encoded[0] == 0x98
        assert encoded[1] == 30
        assert self._decode_slot_map(encoded) == slots

    def test_encode_max_64_entries_ok(self) -> None:
        slots = list(range(64))
        encoded = encode_slot_map(slots)
        # 2 header bytes + 24 immediates (0..23) + 40 two-byte entries.
        assert len(encoded) == 2 + 24 + 40 * 2
        assert self._decode_slot_map(encoded) == slots

    def test_encode_rejects_65_entries(self) -> None:
        with pytest.raises(ValueError, match="maximum entries"):
            encode_slot_map(list(range(65)))

    def test_encode_rejects_out_of_u8_range(self) -> None:
        with pytest.raises(ValueError, match="u8 range"):
            encode_slot_map([1, 256])
        with pytest.raises(ValueError, match="u8 range"):
            encode_slot_map([-1])

    def test_encode_constant_matches_sibling_implementations(self) -> None:
        assert MAX_SLOT_MAP_ENTRIES == 64

    def test_roundtrip_through_validate(self) -> None:
        # Encode -> decode -> spec validator: the writer feeds the same
        # slot_map values the receiver-side validator accepts.
        for slots, num_slots in (([1, 3, 5], 16), ([24, 30], 64), ([], 8)):
            decoded = self._decode_slot_map(encode_slot_map(slots))
            is_valid, error = validate_slot_map(decoded, num_slots)
            assert is_valid, error
            assert decoded == slots

    def test_roundtrip_tx_allowed(self) -> None:
        decoded = self._decode_slot_map(encode_slot_map([3]))
        assert tx_allowed(decoded, 3, 8)
        assert not tx_allowed(decoded, 4, 8)
