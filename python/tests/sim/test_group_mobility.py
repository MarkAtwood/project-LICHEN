# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the GroupMobility pattern."""

from __future__ import annotations

import math

import pytest

from lichen.sim.mobility import GroupMobility, MobilityManager, WaypointState
from lichen.sim.node import SimNode


def make_group_members(count: int, position: tuple[float, float, float]) -> list[SimNode]:
    """Create count SimNodes at the same starting position."""
    return [SimNode(id=f"node-{i}", position=position) for i in range(count)]


class TestGroupMobility:
    """Tests for GroupMobility mobility pattern."""

    def test_initial_state_is_paused(self) -> None:
        pattern = GroupMobility(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=1.0,
            pause_time_us=1_000_000,
            seed=42,
            group_size=3,
            group_radius_m=10.0,
        )
        assert pattern._state == WaypointState.PAUSED
        assert pattern._target is None
        assert pattern._center is None
        assert pattern._members == []

    def test_rejects_bad_group_size(self) -> None:
        for bad_size in (0, -1):
            with pytest.raises(ValueError, match="group_size"):
                GroupMobility(area_bounds=(0, 100, 0, 100), group_size=bad_size)

    def test_rejects_bad_speed(self) -> None:
        for bad_speed in (0.0, -1.0):
            with pytest.raises(ValueError, match="speed_m_s"):
                GroupMobility(area_bounds=(0, 100, 0, 100), speed_m_s=bad_speed)

    def test_rejects_bad_pause_time(self) -> None:
        with pytest.raises(ValueError, match="pause_time_us"):
            GroupMobility(area_bounds=(0, 100, 0, 100), pause_time_us=-1)

    def test_rejects_bad_bounds(self) -> None:
        with pytest.raises(ValueError, match="area_bounds"):
            GroupMobility(area_bounds=(100, 0, 0, 100))
        with pytest.raises(ValueError, match="area_bounds"):
            GroupMobility(area_bounds=(0, 100, 50, 50))

    def test_rejects_bad_radius(self) -> None:
        with pytest.raises(ValueError, match="group_radius_m"):
            GroupMobility(area_bounds=(0, 100, 0, 100), group_radius_m=-1.0)
        # Group diameter 2 * 51 = 102 exceeds the 100m area
        with pytest.raises(ValueError, match="too large"):
            GroupMobility(area_bounds=(0, 100, 0, 100), group_radius_m=51.0)
        # Diameter exactly equal to the area fits
        GroupMobility(area_bounds=(0, 100, 0, 100), group_radius_m=50.0)

    def test_center_waypoint_movement_advances_members_by_offsets(self) -> None:
        pattern = GroupMobility(
            area_bounds=(0, 1000, 0, 1000),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
            group_size=3,
            group_radius_m=20.0,
        )
        m0, m1, m2 = make_group_members(3, (500.0, 500.0, 0.0))
        pattern.add_member(m0)
        pattern.add_member(m1)
        pattern.add_member(m2)

        pattern.step(m0, dt_us=1_000_000)

        # Center moved from its start
        x0, y0, z0 = m0.position
        assert (x0, y0) != (500.0, 500.0)

        # Member 1 offset: (+20, 0); member 2 offset: (-20, 0)
        x1, y1, z1 = m1.position
        x2, y2, z2 = m2.position
        assert x1 == pytest.approx(x0 + 20.0)
        assert y1 == pytest.approx(y0)
        assert x2 == pytest.approx(x0 - 20.0)
        assert y2 == pytest.approx(y0)
        assert math.hypot(x1 - x0, y1 - y0) == pytest.approx(20.0)
        assert math.hypot(x2 - x0, y2 - y0) == pytest.approx(20.0)
        assert z0 == z1 == z2 == 0.0

    def test_registration_does_not_move_members(self) -> None:
        pattern = GroupMobility(
            area_bounds=(0, 100, 0, 100),
            group_size=2,
            group_radius_m=10.0,
            seed=42,
        )
        m0, m1 = make_group_members(2, (50.0, 50.0, 0.0))

        pattern.add_member(m0)
        pattern.add_member(m1)

        assert m0.position == (50.0, 50.0, 0.0)
        assert m1.position == (50.0, 50.0, 0.0)

    def test_offsets_preserved_across_steps(self) -> None:
        pattern = GroupMobility(
            area_bounds=(0, 1000, 0, 1000),
            speed_m_s=5.0,
            pause_time_us=0,
            seed=7,
            group_size=4,
            group_radius_m=25.0,
        )
        members = make_group_members(4, (500.0, 500.0, 0.0))
        for member in members:
            pattern.add_member(member)

        pattern.step(members[0], dt_us=100_000)
        x0, y0, _ = members[0].position
        expected_deltas = [(m.position[0] - x0, m.position[1] - y0) for m in members]

        for _ in range(20):
            pattern.step(members[0], dt_us=100_000)
            x0, y0, _ = members[0].position
            deltas = [(m.position[0] - x0, m.position[1] - y0) for m in members]
            for got, want in zip(deltas, expected_deltas, strict=True):
                assert got[0] == pytest.approx(want[0], abs=1e-9)
                assert got[1] == pytest.approx(want[1], abs=1e-9)

    def test_members_stay_within_bounds(self) -> None:
        bounds = (100, 400, 200, 500)
        pattern = GroupMobility(
            area_bounds=bounds,
            speed_m_s=1000.0,
            pause_time_us=0,
            seed=12345,
            group_size=3,
            group_radius_m=30.0,
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

    def test_group_of_one_tracks_center(self) -> None:
        pattern = GroupMobility(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
        )
        (m0,) = make_group_members(1, (50.0, 50.0, 0.0))
        pattern.add_member(m0)

        pattern.step(m0, dt_us=1_000_000)

        assert m0.position == (pattern._center[0], pattern._center[1], 0.0)

    def test_z_coordinate_propagates_to_members(self) -> None:
        pattern = GroupMobility(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
            z=50.0,
            group_size=2,
            group_radius_m=10.0,
        )
        m0, m1 = make_group_members(2, (50.0, 50.0, 100.0))
        pattern.add_member(m0)
        pattern.add_member(m1)

        pattern.step(m0, dt_us=1_000_000)

        assert m0.position[2] == 50.0
        assert m1.position[2] == 50.0

    def test_add_member_beyond_group_size_raises(self) -> None:
        pattern = GroupMobility(area_bounds=(0, 100, 0, 100), group_size=2, seed=42)
        members = make_group_members(3, (50.0, 50.0, 0.0))

        pattern.add_member(members[0])
        pattern.add_member(members[1])
        with pytest.raises(ValueError, match="group is full"):
            pattern.add_member(members[2])

    def test_step_without_members_is_noop(self) -> None:
        pattern = GroupMobility(area_bounds=(0, 100, 0, 100), speed_m_s=10.0, seed=42)
        anchor = SimNode(id="anchor", position=(50.0, 50.0, 0.0))

        pattern.step(anchor, dt_us=1_000_000)

        assert anchor.position == (50.0, 50.0, 0.0)
        assert pattern._center is None

    def test_reset_clears_membership_and_state(self) -> None:
        pattern = GroupMobility(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
            group_size=2,
            group_radius_m=10.0,
        )
        m0, m1 = make_group_members(2, (50.0, 50.0, 0.0))
        pattern.add_member(m0)
        pattern.add_member(m1)
        for _ in range(5):
            pattern.step(m0, dt_us=500_000)

        pattern.reset()

        assert pattern._state == WaypointState.PAUSED
        assert pattern._target is None
        assert pattern._pause_remaining_us == 0
        assert pattern._center is None
        assert pattern._members == []
        assert pattern._offsets == []

    def test_seed_reproducibility(self) -> None:
        """Same seed should produce same group movement."""
        members1 = make_group_members(3, (500.0, 500.0, 0.0))
        members2 = make_group_members(3, (500.0, 500.0, 0.0))
        pattern1 = GroupMobility(
            area_bounds=(0, 1000, 0, 1000),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
            group_size=3,
            group_radius_m=20.0,
        )
        pattern2 = GroupMobility(
            area_bounds=(0, 1000, 0, 1000),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
            group_size=3,
            group_radius_m=20.0,
        )
        for member in members1:
            pattern1.add_member(member)
        for member in members2:
            pattern2.add_member(member)

        for _ in range(10):
            pattern1.step(members1[0], dt_us=100_000)
            pattern2.step(members2[0], dt_us=100_000)

        for m1, m2 in zip(members1, members2, strict=True):
            assert m1.position == m2.position

    def test_unseeded_pattern_runs(self) -> None:
        pattern = GroupMobility(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=None,
            group_size=2,
            group_radius_m=10.0,
        )
        m0, m1 = make_group_members(2, (50.0, 50.0, 0.0))
        pattern.add_member(m0)
        pattern.add_member(m1)

        for _ in range(10):
            pattern.step(m0, dt_us=100_000)

        x0, y0, _ = m0.position
        x1, y1, _ = m1.position
        assert math.hypot(x1 - x0, y1 - y0) == pytest.approx(10.0)


class TestGroupMobilityManager:
    """Tests for GroupMobility registration via MobilityManager."""

    def test_attach_and_step_all(self) -> None:
        manager = MobilityManager()
        pattern = GroupMobility(
            area_bounds=(0, 500, 0, 500),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
            group_size=3,
            group_radius_m=20.0,
        )
        m0, m1, m2 = make_group_members(3, (250.0, 250.0, 0.0))
        pattern.add_member(m0)
        pattern.add_member(m1)
        pattern.add_member(m2)
        nodes = {"node-0": m0, "node-1": m1, "node-2": m2}

        manager.attach("node-0", pattern)
        assert manager.get_pattern("node-0") is pattern

        manager.step_all(nodes, dt_us=1_000_000)

        x0, y0, _ = m0.position
        assert (x0, y0) != (250.0, 250.0)
        x1, y1, _ = m1.position
        x2, y2, _ = m2.position
        assert x1 == pytest.approx(x0 + 20.0)
        assert x2 == pytest.approx(x0 - 20.0)
        assert y1 == pytest.approx(y0)
        assert y2 == pytest.approx(y0)

    def test_step_all_moves_group_once_per_step(self) -> None:
        manager = MobilityManager()
        pattern = GroupMobility(
            area_bounds=(0, 500, 0, 500),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
            group_size=3,
            group_radius_m=20.0,
        )
        m0, m1, m2 = make_group_members(3, (250.0, 250.0, 0.0))
        pattern.add_member(m0)
        pattern.add_member(m1)
        pattern.add_member(m2)
        nodes = {"node-0": m0, "node-1": m1, "node-2": m2}

        manager.attach("node-0", pattern)
        manager.step_all(nodes, dt_us=1_000_000)
        x0, y0, _ = m0.position

        manager.step_all(nodes, dt_us=1_000_000)

        # Speed 10 m/s over 1s: exactly 10m per step, two steps total
        traveled = math.hypot(m0.position[0] - 250.0, m0.position[1] - 250.0)
        assert traveled == pytest.approx(20.0, abs=0.01)
        assert (x0, y0) != (m0.position[0], m0.position[1])

    def test_detach(self) -> None:
        manager = MobilityManager()
        pattern = GroupMobility(area_bounds=(0, 100, 0, 100), seed=42)

        manager.attach("node-0", pattern)
        removed = manager.detach("node-0")

        assert removed is pattern
        assert manager.get_pattern("node-0") is None


class TestGroupMobilityJitter:
    """Tests for GroupMobility offset jitter."""

    # Golden trajectories generated from the pre-jitter GroupMobility
    # implementation (git 4921cfd8f4) with the exact configs below.
    GOLDEN_PAUSE0 = [
        (516.8991967707072, 442.42902512111766, 0.0),
        (536.8991967707072, 442.42902512111766, 0.0),
        (496.89919677070725, 442.42902512111766, 0.0),
    ]
    GOLDEN_PAUSE1M = [
        (501.68991967707063, 494.24290251211187, 0.0),
        (521.6899196770706, 494.24290251211187, 0.0),
        (481.68991967707063, 494.24290251211187, 0.0),
    ]

    def make_jittered_group(
        self, jitter_m: float, jitter_update_us: int, seed: int = 42
    ) -> tuple[GroupMobility, list[SimNode]]:
        pattern = GroupMobility(
            area_bounds=(0, 1000, 0, 1000),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=seed,
            group_size=3,
            group_radius_m=20.0,
            jitter_m=jitter_m,
            jitter_update_us=jitter_update_us,
        )
        members = make_group_members(3, (500.0, 500.0, 0.0))
        for member in members:
            pattern.add_member(member)
        return pattern, members

    def test_jitter_off_reproduces_pre_change_trajectory(self) -> None:
        """jitter_m=0.0 must be trajectory-identical to pre-jitter GroupMobility."""
        for pause_time_us, dt_us, golden in (
            (0, 1_000_000, self.GOLDEN_PAUSE0),
            (1_000_000, 100_000, self.GOLDEN_PAUSE1M),
        ):
            pattern = GroupMobility(
                area_bounds=(0, 1000, 0, 1000),
                speed_m_s=10.0,
                pause_time_us=pause_time_us,
                seed=42,
                group_size=3,
                group_radius_m=20.0,
            )
            members = make_group_members(3, (500.0, 500.0, 0.0))
            for member in members:
                pattern.add_member(member)

            for _ in range(6):
                pattern.step(members[0], dt_us=dt_us)

            for member, expected in zip(members, golden, strict=True):
                assert member.position[0] == pytest.approx(expected[0], abs=1e-9)
                assert member.position[1] == pytest.approx(expected[1], abs=1e-9)
                assert member.position[2] == expected[2]

    def test_jitter_changes_trajectory(self) -> None:
        pattern, members = self.make_jittered_group(jitter_m=10.0, jitter_update_us=500_000)

        for _ in range(6):
            pattern.step(members[0], dt_us=1_000_000)

        # Same seed, same waypoints, but jitter displaces members off the ring
        assert members[0].position[0] != pytest.approx(
            self.GOLDEN_PAUSE0[0][0], abs=1e-6
        ) or members[0].position[1] != pytest.approx(self.GOLDEN_PAUSE0[0][1], abs=1e-6)

    def test_jitter_displacement_bounded(self) -> None:
        jitter_m = 5.0
        pattern, members = self.make_jittered_group(jitter_m=jitter_m, jitter_update_us=500_000)
        base_offsets = [(0.0, 0.0), (20.0, 0.0), (-20.0, 0.0)]

        for _ in range(200):
            pattern.step(members[0], dt_us=100_000)
            assert pattern._center is not None
            for member, (ox, oy) in zip(members, base_offsets, strict=True):
                dx = member.position[0] - pattern._center[0] - ox
                dy = member.position[1] - pattern._center[1] - oy
                assert math.hypot(dx, dy) <= jitter_m + 1e-9

    def test_jitter_transitions_are_smooth(self) -> None:
        jitter_m = 8.0
        dt_us = 100_000
        jitter_update_us = 500_000
        pattern, members = self.make_jittered_group(
            jitter_m=jitter_m, jitter_update_us=jitter_update_us
        )
        base_offsets = [(0.0, 0.0), (20.0, 0.0), (-20.0, 0.0)]
        max_step = jitter_m * dt_us / jitter_update_us

        def displacements() -> list[tuple[float, float]]:
            assert pattern._center is not None
            return [
                (
                    m.position[0] - pattern._center[0] - ox,
                    m.position[1] - pattern._center[1] - oy,
                )
                for m, (ox, oy) in zip(members, base_offsets, strict=True)
            ]

        for _ in range(50):
            pattern.step(members[0], dt_us=dt_us)
            before = displacements()
            pattern.step(members[0], dt_us=dt_us)
            after = displacements()
            for (bx, by), (ax, ay) in zip(before, after, strict=True):
                assert math.hypot(ax - bx, ay - by) <= max_step + 1e-9

    def test_jitter_maintains_cohesion(self) -> None:
        group_radius_m = 20.0
        jitter_m = 5.0
        pattern, members = self.make_jittered_group(jitter_m=jitter_m, jitter_update_us=500_000)
        max_spread = 2 * (group_radius_m + jitter_m)

        for _ in range(100):
            pattern.step(members[0], dt_us=100_000)
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    dist = math.hypot(
                        members[i].position[0] - members[j].position[0],
                        members[i].position[1] - members[j].position[1],
                    )
                    assert dist <= max_spread + 1e-9

    def test_jitter_members_stay_within_bounds(self) -> None:
        bounds = (0, 100, 0, 100)
        pattern = GroupMobility(
            area_bounds=bounds,
            speed_m_s=1000.0,
            pause_time_us=0,
            seed=12345,
            group_size=3,
            group_radius_m=10.0,
            jitter_m=5.0,
            jitter_update_us=500_000,
        )
        members = make_group_members(3, (50.0, 50.0, 0.0))
        for member in members:
            pattern.add_member(member)

        for _ in range(100):
            pattern.step(members[0], dt_us=100_000)
            for member in members:
                x, y, _ = member.position
                assert bounds[0] <= x <= bounds[1]
                assert bounds[2] <= y <= bounds[3]

    def test_jitter_validation(self) -> None:
        with pytest.raises(ValueError, match="jitter_m"):
            GroupMobility(area_bounds=(0, 100, 0, 100), jitter_m=-1.0)
        with pytest.raises(ValueError, match="jitter_update_us"):
            GroupMobility(area_bounds=(0, 100, 0, 100), jitter_update_us=0)
        with pytest.raises(ValueError, match="jitter_update_us"):
            GroupMobility(area_bounds=(0, 100, 0, 100), jitter_update_us=-5)
        # radius 45 + jitter 10 -> diameter 110 exceeds the 100m area
        with pytest.raises(ValueError, match="too large"):
            GroupMobility(area_bounds=(0, 100, 0, 100), group_radius_m=45.0, jitter_m=10.0)
        # radius 45 + jitter 5 -> diameter exactly 100 fits
        GroupMobility(area_bounds=(0, 100, 0, 100), group_radius_m=45.0, jitter_m=5.0)

    def test_jitter_determinism(self) -> None:
        pattern1, members1 = self.make_jittered_group(jitter_m=5.0, jitter_update_us=500_000)
        pattern2, members2 = self.make_jittered_group(jitter_m=5.0, jitter_update_us=500_000)

        for _ in range(20):
            pattern1.step(members1[0], dt_us=100_000)
            pattern2.step(members2[0], dt_us=100_000)

        for m1, m2 in zip(members1, members2, strict=True):
            assert m1.position == m2.position

    def test_jitter_update_frequency_controls_transition_rate(self) -> None:
        jitter_m = 10.0
        dt_us = 100_000
        # Update interval far longer than the test horizon: members only
        # glide a tiny fraction of the way toward their initial target.
        pattern, members = self.make_jittered_group(
            jitter_m=jitter_m, jitter_update_us=1_000_000_000
        )
        base_offsets = [(0.0, 0.0), (20.0, 0.0), (-20.0, 0.0)]
        max_total = jitter_m * (10 * dt_us) / 1_000_000_000

        for _ in range(10):
            pattern.step(members[0], dt_us=dt_us)

        assert pattern._center is not None
        for member, (ox, oy) in zip(members, base_offsets, strict=True):
            dx = member.position[0] - pattern._center[0] - ox
            dy = member.position[1] - pattern._center[1] - oy
            assert 0.0 < math.hypot(dx, dy) <= max_total + 1e-12
