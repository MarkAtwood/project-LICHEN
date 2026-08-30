# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Giant-dt hang regression for all mobility patterns.

Sub-microsecond leg times used to truncate to 0 in the arrival-time
accounting (int(distance / speed * 1e6) == 0), so remaining_us never
decreased and step() looped forever. These tests pin the fix: step()
must terminate in bounded time for giant dt values with legal configs
that produce sub-microsecond legs.
"""

from __future__ import annotations

import pytest

from lichen.sim.mobility import (
    RPGM,
    GroupMobility,
    ManhattanGrid,
    RandomWaypoint,
)
from lichen.sim.node import SimNode

GIANT_DT_US = 10**12


def _assert_in_bounds(node: SimNode) -> None:
    x, y, _ = node.position
    assert 0.0 <= x <= 100.0
    assert 0.0 <= y <= 100.0


@pytest.mark.timeout(10)
def test_random_waypoint_giant_dt_sub_us_legs_terminates() -> None:
    # 100 m box at 1e9 m/s and zero pause: every leg completes in far
    # less than 1 us, so the PAUSED<->MOVING cycle consumed 0 us per
    # iteration and looped forever.
    pattern = RandomWaypoint(
        area_bounds=(0, 100, 0, 100),
        speed_m_s=1e9,
        pause_time_us=0,
        seed=42,
    )
    node = SimNode(id="test", position=(50.0, 50.0, 0.0))

    pattern.step(node, GIANT_DT_US)

    _assert_in_bounds(node)


@pytest.mark.timeout(10)
def test_group_mobility_giant_dt_sub_us_legs_terminates() -> None:
    pattern = GroupMobility(
        area_bounds=(0, 100, 0, 100),
        speed_m_s=1e9,
        pause_time_us=0,
        group_size=3,
        group_radius_m=5.0,
        seed=42,
    )
    anchor = SimNode(id="anchor", position=(50.0, 50.0, 0.0))
    pattern.add_member(anchor)
    for i in range(1, 3):
        pattern.add_member(SimNode(id=f"member-{i}", position=(50.0, 50.0, 0.0)))

    pattern.step(anchor, GIANT_DT_US)

    for member in pattern._members:
        _assert_in_bounds(member)


@pytest.mark.timeout(10)
def test_group_mobility_giant_dt_tiny_jitter_update_terminates() -> None:
    # jitter_update_us=1 with a giant dt used to drive ~dt redraw
    # iterations in _update_jitter (RNG + trig per member per pass),
    # outside the movement-loop iteration cap.
    pattern = GroupMobility(
        area_bounds=(0, 100, 0, 100),
        speed_m_s=1.0,
        pause_time_us=0,
        group_size=3,
        group_radius_m=5.0,
        jitter_m=2.0,
        jitter_update_us=1,
        seed=42,
    )
    anchor = SimNode(id="anchor", position=(50.0, 50.0, 0.0))
    pattern.add_member(anchor)
    for i in range(1, 3):
        pattern.add_member(SimNode(id=f"member-{i}", position=(50.0, 50.0, 0.0)))

    pattern.step(anchor, GIANT_DT_US)

    for member in pattern._members:
        _assert_in_bounds(member)


@pytest.mark.timeout(10)
def test_rpgm_giant_dt_sub_us_legs_terminates() -> None:
    pattern = RPGM(
        area_bounds=(0, 100, 0, 100),
        speed_m_s=1e9,
        pause_time_us=0,
        max_offset_m=5.0,
        seed=42,
    )
    anchor = SimNode(id="anchor", position=(50.0, 50.0, 0.0))
    pattern.add_member(anchor)
    pattern.add_member(SimNode(id="member-1", position=(50.0, 50.0, 0.0)))

    pattern.step(anchor, GIANT_DT_US)

    for member in pattern._members:
        _assert_in_bounds(member)


@pytest.mark.timeout(10)
def test_manhattan_grid_giant_dt_sub_us_legs_terminates() -> None:
    # 0.5 m spacing at 1e6 m/s = 0.5 us per grid leg: the intersection
    # arrival consumed 0 us per iteration and looped forever.
    pattern = ManhattanGrid(
        area_bounds=(0, 100, 0, 100),
        spacing_m=0.5,
        speed_m_s=1e6,
        seed=42,
    )
    node = SimNode(id="test", position=(23.0, 47.0, 0.0))

    pattern.step(node, GIANT_DT_US)

    _assert_in_bounds(node)
