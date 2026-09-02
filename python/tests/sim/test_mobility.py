# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for mobility patterns."""

from __future__ import annotations

import math

import pytest

from lichen.sim.mobility import (
    RPGM,
    GroupMobility,
    ManhattanGrid,
    MobilityManager,
    RandomWaypoint,
    WaypointState,
)
from lichen.sim.node import SimNode


class TestRandomWaypoint:
    """Tests for RandomWaypoint mobility pattern."""

    def test_initial_state_is_paused(self) -> None:
        pattern = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=1.0,
            pause_time_us=1_000_000,
            seed=42,
        )
        assert pattern._state == WaypointState.PAUSED

    def test_step_picks_waypoint_and_moves(self) -> None:
        pattern = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,  # 10 m/s
            pause_time_us=0,  # No pause
            seed=42,
        )
        node = SimNode(id="test", position=(50.0, 50.0, 0.0))

        # Step 1 second - should move toward a waypoint
        pattern.step(node, dt_us=1_000_000)

        # Node should have moved from starting position
        x, y, z = node.position
        assert (x, y) != (50.0, 50.0)
        assert z == 0.0

    def test_step_respects_speed(self) -> None:
        pattern = RandomWaypoint(
            area_bounds=(0, 1000, 0, 1000),
            speed_m_s=10.0,  # 10 m/s
            pause_time_us=0,
            seed=42,
        )
        node = SimNode(id="test", position=(0.0, 0.0, 0.0))

        # Step 1 second - should move exactly 10 meters
        pattern.step(node, dt_us=1_000_000)

        x, y, _ = node.position
        distance = math.sqrt(x * x + y * y)
        assert abs(distance - 10.0) < 0.01

    def test_pauses_at_waypoint(self) -> None:
        # Degenerate bounds (10,10,10,10) are invalid under the new
        # min<max validation; use a tiny valid area that the fast pattern
        # crosses within one step. The 1-meter area also keeps every
        # waypoint within reach of a single 1-second step at 100 m/s.
        pattern = RandomWaypoint(
            area_bounds=(9.0, 10.0, 9.0, 10.0),
            speed_m_s=100.0,  # Fast
            pause_time_us=2_000_000,  # 2 second pause
            seed=42,
        )
        node = SimNode(id="test", position=(9.0, 9.0, 0.0))

        # Waypoints now vary within the 1x1 area (seeded RNG), so assert
        # pause behavior rather than a fixed corner: step until PAUSED with a
        # nonzero pause budget, then verify the node rests inside bounds.
        # (A single-step assertion is not reliable here since the waypoint is
        # drawn at random within the area.)
        for _ in range(200):
            pattern.step(node, dt_us=1_000_000)
            if pattern._state == WaypointState.PAUSED and pattern._pause_remaining_us > 0:
                break

        x, y, _ = node.position
        assert 9.0 <= x <= 10.0
        assert 9.0 <= y <= 10.0
        assert pattern._state == WaypointState.PAUSED
        assert pattern._pause_remaining_us > 0

        # Pattern should now be paused
        assert pattern._state == WaypointState.PAUSED
        assert pattern._pause_remaining_us > 0

    def test_stays_within_bounds(self) -> None:
        """Verify waypoints are picked within bounds."""
        bounds = (100, 200, 300, 400)
        pattern = RandomWaypoint(
            area_bounds=bounds,
            speed_m_s=1000.0,  # Very fast
            pause_time_us=0,
            seed=12345,
        )
        node = SimNode(id="test", position=(150.0, 350.0, 0.0))

        # Run many steps to test multiple waypoints
        for _ in range(100):
            pattern.step(node, dt_us=100_000)
            x, y, _ = node.position
            # Node should stay within or very close to bounds
            # (may slightly exceed during final approach)
            assert bounds[0] - 1 <= x <= bounds[1] + 1
            assert bounds[2] - 1 <= y <= bounds[3] + 1

    def test_z_coordinate_preserved(self) -> None:
        pattern = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
            z=50.0,  # Fixed altitude
        )
        node = SimNode(id="test", position=(0.0, 0.0, 100.0))

        pattern.step(node, dt_us=1_000_000)

        _, _, z = node.position
        assert z == 50.0

    def test_reset_restores_initial_state(self) -> None:
        pattern = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
        )
        node = SimNode(id="test", position=(50.0, 50.0, 0.0))

        # Run several steps to change state
        for _ in range(5):
            pattern.step(node, dt_us=500_000)

        # Reset
        pattern.reset()

        assert pattern._state == WaypointState.PAUSED
        assert pattern._target is None
        assert pattern._pause_remaining_us == 0

    def test_seed_reproducibility(self) -> None:
        """Same seed should produce same movement."""
        node1 = SimNode(id="test1", position=(50.0, 50.0, 0.0))
        node2 = SimNode(id="test2", position=(50.0, 50.0, 0.0))

        pattern1 = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
        )
        pattern2 = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
        )

        for _ in range(10):
            pattern1.step(node1, dt_us=100_000)
            pattern2.step(node2, dt_us=100_000)

        assert node1.position == node2.position


class TestMobilityManager:
    """Tests for MobilityManager."""

    def test_attach_and_step(self) -> None:
        manager = MobilityManager()
        pattern = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
        )
        node = SimNode(id="node-0", position=(50.0, 50.0, 0.0))
        nodes = {"node-0": node}

        manager.attach("node-0", pattern)
        manager.step_all(nodes, dt_us=1_000_000)

        x, y, _ = node.position
        assert (x, y) != (50.0, 50.0)

    def test_step_ignores_missing_nodes(self) -> None:
        manager = MobilityManager()
        pattern = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
        )

        manager.attach("missing-node", pattern)
        # Should not raise
        manager.step_all({}, dt_us=1_000_000)

    def test_detach(self) -> None:
        manager = MobilityManager()
        pattern = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
        )

        manager.attach("node-0", pattern)
        removed = manager.detach("node-0")

        assert removed is pattern
        assert manager.get_pattern("node-0") is None

    def test_detach_missing_returns_none(self) -> None:
        manager = MobilityManager()
        assert manager.detach("missing") is None

    def test_get_pattern(self) -> None:
        manager = MobilityManager()
        pattern = RandomWaypoint(
            area_bounds=(0, 100, 0, 100),
            speed_m_s=10.0,
            pause_time_us=0,
            seed=42,
        )

        manager.attach("node-0", pattern)
        assert manager.get_pattern("node-0") is pattern
        assert manager.get_pattern("missing") is None

    def test_clear(self) -> None:
        manager = MobilityManager()
        pattern1 = RandomWaypoint(area_bounds=(0, 100, 0, 100), seed=1)
        pattern2 = RandomWaypoint(area_bounds=(0, 100, 0, 100), seed=2)

        manager.attach("node-0", pattern1)
        manager.attach("node-1", pattern2)
        manager.clear()

        assert manager.get_pattern("node-0") is None
        assert manager.get_pattern("node-1") is None

    def test_multiple_nodes(self) -> None:
        manager = MobilityManager()
        nodes = {
            "node-0": SimNode(id="node-0", position=(0.0, 0.0, 0.0)),
            "node-1": SimNode(id="node-1", position=(100.0, 100.0, 0.0)),
        }

        manager.attach(
            "node-0",
            RandomWaypoint(area_bounds=(0, 50, 0, 50), speed_m_s=10.0, seed=1),
        )
        manager.attach(
            "node-1",
            RandomWaypoint(area_bounds=(50, 100, 50, 100), speed_m_s=5.0, seed=2),
        )

        initial_pos = {nid: n.position for nid, n in nodes.items()}
        manager.step_all(nodes, dt_us=1_000_000)

        # Both nodes should have moved
        for nid, node in nodes.items():
            assert node.position != initial_pos[nid]


class TestFiniteConfigValidation:
    """NaN/inf must fail construction, not poison geometry silently."""

    @pytest.mark.parametrize("speed", [float("nan"), float("inf"), float("-inf"), -1.0, 0.0])
    def test_random_waypoint_rejects_bad_speed(self, speed: float) -> None:
        with pytest.raises(ValueError, match="speed_m_s"):
            RandomWaypoint(area_bounds=(0, 100, 0, 100), speed_m_s=speed)

    @pytest.mark.parametrize(
        "bounds",
        [
            (float("nan"), 100, 0, 100),
            (0, float("inf"), 0, 100),
            (0, 100, float("nan"), 100),
            (0, 100, 0, -float("inf")),
            (10, 10, 10, 10),  # degenerate: min == max
        ],
    )
    def test_random_waypoint_rejects_bad_bounds(self, bounds: tuple[float, ...]) -> None:
        with pytest.raises(ValueError, match="area_bounds"):
            RandomWaypoint(area_bounds=bounds, speed_m_s=1.0)  # type: ignore[arg-type]

    def test_random_waypoint_rejects_negative_pause(self) -> None:
        with pytest.raises(ValueError, match="pause_time_us"):
            RandomWaypoint(area_bounds=(0, 100, 0, 100), pause_time_us=-1)

    def test_nan_bounds_poisoned_geometry_is_now_rejected(self) -> None:
        # Regression pin for the codereview finding: NaN bounds previously
        # constructed cleanly (nan <= 0 is False) and wrote NaN into
        # set_position; construction must now fail closed.
        with pytest.raises(ValueError, match="finite"):
            RandomWaypoint(
                area_bounds=(float("nan"), float("nan"), 0.0, 100.0), speed_m_s=1.0
            )

    def test_group_mobility_rejects_nan_speed(self) -> None:
        with pytest.raises(ValueError, match="speed_m_s"):
            GroupMobility(
                area_bounds=(0, 100, 0, 100),
                speed_m_s=float("nan"),
                group_size=3,
            )

    def test_rpgm_rejects_inf_speed(self) -> None:
        with pytest.raises(ValueError, match="speed_m_s"):
            RPGM(area_bounds=(0, 100, 0, 100), speed_m_s=float("inf"))

    def test_manhattan_grid_rejects_nan_spacing(self) -> None:
        with pytest.raises(ValueError, match="spacing_m"):
            ManhattanGrid(area_bounds=(0, 100, 0, 100), spacing_m=float("nan"))

    @pytest.mark.parametrize("speed", [float("nan"), float("inf"), 0.0, -1.0])
    def test_manhattan_grid_rejects_bad_speed(self, speed: float) -> None:
        # Wave-4 addendum (bead e1ct): ManhattanGrid speed_m_s=NaN passes bare
        # comparisons and poisons positions via ratio math; must be rejected.
        with pytest.raises(ValueError, match="speed_m_s"):
            ManhattanGrid(area_bounds=(0, 100, 0, 100), speed_m_s=speed)
