# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the RPGM (Reference Point Group Mobility) pattern."""

from __future__ import annotations

import math

import pytest

from lichen.sim.mobility import RPGM, MobilityManager, WaypointState
from lichen.sim.node import SimNode


def make_group_members(count: int, position: tuple[float, float, float]) -> list[SimNode]:
    """Create count SimNodes at the same starting position."""
    return [SimNode(id=f"node-{i}", position=position) for i in range(count)]


class TestRPGM:
    """Tests for the RPGM mobility pattern."""

    def make_pattern(
        self,
        area_bounds: tuple[float, float, float, float] = (0, 1000, 0, 1000),
        speed_m_s: float = 10.0,
        pause_time_us: int = 0,
        seed: int | None = 42,
        z: float = 0.0,
        max_offset_m: float = 25.0,
    ) -> RPGM:
        return RPGM(
            area_bounds=area_bounds,
            speed_m_s=speed_m_s,
            pause_time_us=pause_time_us,
            seed=seed,
            z=z,
            max_offset_m=max_offset_m,
        )

    def test_initial_state_is_paused(self) -> None:
        pattern = self.make_pattern()
        assert pattern._state == WaypointState.PAUSED
        assert pattern._target is None
        assert pattern._center is None
        assert pattern._members == []
        assert pattern._offsets == []

    def test_rejects_bad_speed(self) -> None:
        for bad_speed in (0.0, -1.0):
            with pytest.raises(ValueError, match="speed_m_s"):
                RPGM(area_bounds=(0, 100, 0, 100), speed_m_s=bad_speed)

    def test_rejects_bad_pause_time(self) -> None:
        with pytest.raises(ValueError, match="pause_time_us"):
            RPGM(area_bounds=(0, 100, 0, 100), pause_time_us=-1)

    def test_rejects_bad_bounds(self) -> None:
        with pytest.raises(ValueError, match="area_bounds"):
            RPGM(area_bounds=(100, 0, 0, 100))
        with pytest.raises(ValueError, match="area_bounds"):
            RPGM(area_bounds=(0, 100, 50, 50))

    def test_rejects_bad_max_offset(self) -> None:
        with pytest.raises(ValueError, match="max_offset_m"):
            RPGM(area_bounds=(0, 100, 0, 100), max_offset_m=-1.0)
        # Offset diameter 2 * 51 = 102 exceeds the 100m area
        with pytest.raises(ValueError, match="too large"):
            RPGM(area_bounds=(0, 100, 0, 100), max_offset_m=51.0)
        # Diameter exactly equal to the area fits
        RPGM(area_bounds=(0, 100, 0, 100), max_offset_m=50.0)

    def test_offsets_bounded_and_drawn_once(self) -> None:
        max_offset_m = 25.0
        pattern = self.make_pattern(max_offset_m=max_offset_m)
        members = make_group_members(3, (500.0, 500.0, 0.0))
        for member in members:
            pattern.add_member(member)

        for _ in range(50):
            pattern.step(members[0], dt_us=100_000)
            assert pattern._center is not None
            for member, (ox, oy) in zip(members, pattern._offsets, strict=True):
                dx = member.position[0] - pattern._center[0] - ox
                dy = member.position[1] - pattern._center[1] - oy
                assert math.hypot(dx, dy) == pytest.approx(0.0, abs=1e-9)
            for ox, oy in pattern._offsets:
                assert math.hypot(ox, oy) <= max_offset_m + 1e-9

    def test_members_track_reference_point(self) -> None:
        pattern = self.make_pattern()
        members = make_group_members(3, (500.0, 500.0, 0.0))
        for member in members:
            pattern.add_member(member)

        for _ in range(20):
            pattern.step(members[0], dt_us=100_000)
            assert pattern._center is not None
            cx, cy = pattern._center
            for member, (ox, oy) in zip(members, pattern._offsets, strict=True):
                assert member.position[0] == pytest.approx(cx + ox, abs=1e-9)
                assert member.position[1] == pytest.approx(cy + oy, abs=1e-9)
                assert member.position[2] == 0.0

    def test_reference_point_moves_random_waypoint_style(self) -> None:
        pattern = self.make_pattern()
        members = make_group_members(2, (500.0, 500.0, 0.0))
        for member in members:
            pattern.add_member(member)

        min_offset = pattern.max_offset_m
        prev_center = None
        moved = False
        for _ in range(20):
            pattern.step(members[0], dt_us=100_000)
            assert pattern._center is not None
            cx, cy = pattern._center
            # Reference point stays within the max_offset inset
            assert min_offset - 1e-9 <= cx <= 1000 - min_offset + 1e-9
            assert min_offset - 1e-9 <= cy <= 1000 - min_offset + 1e-9
            if prev_center is not None:
                dist = math.hypot(cx - prev_center[0], cy - prev_center[1])
                # At most speed * dt per step; center does travel overall
                assert dist <= 10.0 * 0.1 + 1e-9
                moved = moved or dist > 0.0
            prev_center = (cx, cy)
        assert moved

    def test_reference_point_starts_clamped_into_inset(self) -> None:
        pattern = self.make_pattern(max_offset_m=10.0)
        (member,) = make_group_members(1, (0.0, 0.0, 0.0))
        pattern.add_member(member)

        pattern.step(member, dt_us=0)

        assert pattern._center == (10.0, 10.0)

    def test_members_stay_within_bounds(self) -> None:
        bounds = (100, 400, 200, 500)
        pattern = RPGM(
            area_bounds=bounds,
            speed_m_s=1000.0,
            pause_time_us=0,
            seed=12345,
            max_offset_m=30.0,
        )
        members = make_group_members(3, (250.0, 350.0, 0.0))
        for member in members:
            pattern.add_member(member)

        for _ in range(100):
            pattern.step(members[0], dt_us=100_000)
            for member in members:
                x, y, _ = member.position
                assert bounds[0] <= x <= bounds[1]
                assert bounds[2] <= y <= bounds[3]

    def test_z_coordinate_propagates_to_members(self) -> None:
        pattern = self.make_pattern(z=50.0)
        members = make_group_members(2, (500.0, 500.0, 100.0))
        for member in members:
            pattern.add_member(member)

        pattern.step(members[0], dt_us=1_000_000)

        assert members[0].position[2] == 50.0
        assert members[1].position[2] == 50.0

    def test_step_without_members_is_noop(self) -> None:
        pattern = self.make_pattern()
        anchor = SimNode(id="anchor", position=(50.0, 50.0, 0.0))

        pattern.step(anchor, dt_us=1_000_000)

        assert anchor.position == (50.0, 50.0, 0.0)
        assert pattern._center is None

    def test_reset_clears_membership_and_state(self) -> None:
        pattern = self.make_pattern()
        members = make_group_members(2, (500.0, 500.0, 0.0))
        for member in members:
            pattern.add_member(member)
        for _ in range(5):
            pattern.step(members[0], dt_us=500_000)

        pattern.reset()

        assert pattern._state == WaypointState.PAUSED
        assert pattern._target is None
        assert pattern._pause_remaining_us == 0
        assert pattern._center is None
        assert pattern._members == []
        assert pattern._offsets == []

    def test_seed_reproducibility(self) -> None:
        """Same seed should produce same offsets and same trajectories."""
        members1 = make_group_members(3, (500.0, 500.0, 0.0))
        members2 = make_group_members(3, (500.0, 500.0, 0.0))
        pattern1 = self.make_pattern()
        pattern2 = self.make_pattern()
        for member in members1:
            pattern1.add_member(member)
        for member in members2:
            pattern2.add_member(member)

        assert pattern1._offsets == pattern2._offsets

        for _ in range(10):
            pattern1.step(members1[0], dt_us=100_000)
            pattern2.step(members2[0], dt_us=100_000)

        for m1, m2 in zip(members1, members2, strict=True):
            assert m1.position == m2.position

    def test_unseeded_pattern_runs(self) -> None:
        pattern = self.make_pattern(seed=None)
        members = make_group_members(2, (500.0, 500.0, 0.0))
        for member in members:
            pattern.add_member(member)

        for _ in range(10):
            pattern.step(members[0], dt_us=100_000)

        for member in members:
            x, y, _ = member.position
            assert 0.0 <= x <= 1000.0
            assert 0.0 <= y <= 1000.0

    def test_pauses_at_waypoint(self) -> None:
        pattern = RPGM(
            area_bounds=(10, 11, 10, 11),  # Waypoints all ~at (10.x, 10.y)
            speed_m_s=1000.0,
            pause_time_us=2_000_000,
            seed=42,
            max_offset_m=0.0,
        )
        (member,) = make_group_members(1, (0.0, 0.0, 0.0))
        pattern.add_member(member)

        pattern.step(member, dt_us=1_000_000)

        assert pattern._state == WaypointState.PAUSED
        assert pattern._pause_remaining_us > 0


class TestRPGMManager:
    """Tests for RPGM registration via MobilityManager."""

    def test_attach_and_step_all(self) -> None:
        manager = MobilityManager()
        pattern = RPGM(
            area_bounds=(0, 500, 0, 500),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
            max_offset_m=20.0,
        )
        members = make_group_members(3, (250.0, 250.0, 0.0))
        for member in members:
            pattern.add_member(member)
        nodes = {f"node-{i}": m for i, m in enumerate(members)}

        manager.attach("node-0", pattern)
        assert manager.get_pattern("node-0") is pattern

        manager.step_all(nodes, dt_us=1_000_000)

        assert pattern._center is not None
        cx, cy = pattern._center
        for member, (ox, oy) in zip(members, pattern._offsets, strict=True):
            assert member.position[0] == pytest.approx(cx + ox, abs=1e-9)
            assert member.position[1] == pytest.approx(cy + oy, abs=1e-9)
