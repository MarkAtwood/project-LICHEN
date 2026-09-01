# SPDX-FileCopyrightText: The contributors to the LICHEN project
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for R-02a-040 overlap window and R-02a-043 hold-off rejoin
wiring on MultiRootState (bead q0pg, slice of b7z9.25)."""

from dataclasses import dataclass

import pytest

from lichen.link.slot_coordination import (
    HOLDOFF_SUPERFRAMES,
    MultiRootState,
    RootCandidate,
)


def _cand(iid_byte: int, sf: int = 9) -> RootCandidate:
    c = RootCandidate.from_beacon(
        bytes([iid_byte] * 8), signature_valid=True
    )
    return c


@dataclass
class TdmaWindow:
    slot_start_us: int
    setup_window_us: int
    occupied_time_us: int
    guard_us: int


def test_beacon_overlaps_window_inside() -> None:
    state = MultiRootState()
    window = TdmaWindow(1000, 20, 2300, 50)
    assert state.beacon_overlaps_window(1000 + 500, window)


def test_beacon_before_window_outside() -> None:
    state = MultiRootState()
    window = TdmaWindow(1000, 20, 2300, 50)
    # 1000 - 20 = 980 is window start; 900 is before it.
    assert not state.beacon_overlaps_window(900, window)


def test_beacon_after_window_outside() -> None:
    state = MultiRootState()
    window = TdmaWindow(1000, 20, 2300, 50)
    # slot end 3320 + guard 50 = 3370; 3400 is after.
    assert not state.beacon_overlaps_window(3400, window)


def test_holdoff_complete_rejoin_drops_old_root() -> None:
    state = MultiRootState()
    old = _cand(0x11)
    new = _cand(0x22)
    state.current_root = old
    state.add_candidate(new)
    state.holdoff_selected = new
    state.holdoff_counter = HOLDOFF_SUPERFRAMES
    state.desync_state_version = 5

    # Advance holdoff to its last superframe, then the rejoin replaces
    # the final advance (R-02a-043: holdoff completion initiates desync
    # and rejoin rather than silently switching roots).
    state.holdoff_counter = 1
    assert state.holdoff_complete_rejoin(42) is True
    assert state.current_root is None
    assert not state.candidates
    assert state.desync_state_version is None
    assert state.holdoff_counter == 0


def test_holdoff_complete_rejoin_not_in_holdoff() -> None:
    state = MultiRootState()
    assert state.holdoff_complete_rejoin(0) is False
