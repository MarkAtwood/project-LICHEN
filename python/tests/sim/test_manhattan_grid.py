# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the ManhattanGrid mobility pattern."""

from __future__ import annotations

import math

import pytest

from lichen.sim.mobility import ManhattanGrid, MobilityManager
from lichen.sim.node import SimNode


class TestManhattanGrid:
    """Tests for the ManhattanGrid mobility pattern."""

    def make_pattern(
        self,
        area_bounds: tuple[float, float, float, float] = (0, 100, 0, 100),
        spacing_m: float = 10.0,
        speed_m_s: float = 1.0,
        seed: int | None = 42,
        z: float = 0.0,
    ) -> ManhattanGrid:
        return ManhattanGrid(
            area_bounds=area_bounds,
            spacing_m=spacing_m,
            speed_m_s=speed_m_s,
            seed=seed,
            z=z,
        )

    def test_snap_to_grid(self) -> None:
        pattern = self.make_pattern()

        assert pattern.snap_to_grid(23.0, 47.0) == (20.0, 50.0)
        assert pattern.snap_to_grid(14.9, 25.1) == (10.0, 30.0)
        assert pattern.snap_to_grid(6.0, 7.0) == (10.0, 10.0)
        assert pattern.snap_to_grid(0.0, 100.0) == (0.0, 100.0)
        assert pattern.snap_to_grid(50.0, 50.0) == (50.0, 50.0)

    def test_snap_to_grid_clamps_into_bounds(self) -> None:
        pattern = self.make_pattern()

        # Nearest grid points beyond the bounds are clamped to edge grid points
        assert pattern.snap_to_grid(150.0, -5.0) == (100.0, 0.0)
        assert pattern.snap_to_grid(-20.0, 105.0) == (0.0, 100.0)

    def test_snap_to_grid_partial_last_cell(self) -> None:
        # Bounds not divisible by spacing: last grid line at 90, not 95
        pattern = self.make_pattern(area_bounds=(0, 95, 0, 95))
        assert pattern.snap_to_grid(94.0, 94.0) == (90.0, 90.0)

    def test_rejects_bad_spacing(self) -> None:
        for bad_spacing in (0.0, -1.0):
            with pytest.raises(ValueError, match="spacing_m"):
                ManhattanGrid(area_bounds=(0, 100, 0, 100), spacing_m=bad_spacing)

    def test_rejects_bad_speed(self) -> None:
        with pytest.raises(ValueError, match="speed_m_s"):
            ManhattanGrid(area_bounds=(0, 100, 0, 100), speed_m_s=0.0)

    def test_rejects_bad_bounds(self) -> None:
        with pytest.raises(ValueError, match="area_bounds"):
            ManhattanGrid(area_bounds=(100, 0, 0, 100))
        with pytest.raises(ValueError, match="area_bounds"):
            ManhattanGrid(area_bounds=(0, 100, 50, 50))

    def test_initial_placement_on_grid(self) -> None:
        pattern = self.make_pattern()
        node = SimNode(id="test", position=(23.0, 47.0, 5.0))

        # A zero-length step performs the initial grid placement only
        pattern.step(node, dt_us=0)

        assert node.position == (20.0, 50.0, 0.0)
        assert pattern._current == (2, 5)

    def test_axis_locked_movement(self) -> None:
        pattern = self.make_pattern(speed_m_s=1.0)
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))

        # 0.1s steps at 1 m/s cover 0.1m per step: ~100 steps per 10m leg
        for _ in range(200):
            pattern.step(node, dt_us=100_000)
            x, y, _ = node.position
            # Node stays on grid lines: at least one coordinate is on-grid
            assert x == pytest.approx(round(x / 10.0) * 10.0, abs=1e-9) or y == pytest.approx(
                round(y / 10.0) * 10.0, abs=1e-9
            )

    def test_movement_speed_along_grid_line(self) -> None:
        pattern = self.make_pattern(speed_m_s=2.0)
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))

        pattern.step(node, dt_us=0)  # snap onto grid at (0, 0)
        start = node.position

        pattern.step(node, dt_us=500_000)  # 0.5s at 2 m/s = 1.0m

        traveled = math.hypot(node.position[0] - start[0], node.position[1] - start[1])
        assert traveled == pytest.approx(1.0, abs=1e-9)

    def test_visits_intersections(self) -> None:
        pattern = self.make_pattern(speed_m_s=1.0)
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))
        pattern.step(node, dt_us=0)

        visited = 0
        prev_current = pattern._current
        for _ in range(250):
            pattern.step(node, dt_us=100_000)
            if pattern._current != prev_current:
                visited += 1
                prev_current = pattern._current

        # ~25m of travel at 1 m/s over 10m legs crosses >= 2 intersections
        assert visited >= 2
        # Current cell always tracks a real grid index within bounds
        assert pattern._current is not None
        ci, cj = pattern._current
        assert 0 <= ci <= 10
        assert 0 <= cj <= 10

    def test_stays_within_bounds(self) -> None:
        bounds = (10, 60, 20, 70)
        pattern = self.make_pattern(
            area_bounds=bounds, spacing_m=10.0, speed_m_s=1000.0, seed=12345
        )
        node = SimNode(id="test", position=(35.0, 45.0, 0.0))

        for _ in range(200):
            pattern.step(node, dt_us=100_000)
            x, y, _ = node.position
            assert bounds[0] <= x <= bounds[1]
            assert bounds[2] <= y <= bounds[3]

    def test_z_coordinate_propagates(self) -> None:
        pattern = self.make_pattern(z=42.0)
        node = SimNode(id="test", position=(23.0, 47.0, 100.0))

        pattern.step(node, dt_us=1_000_000)

        assert node.position[2] == 42.0

    def test_degenerate_grid_single_point(self) -> None:
        # Spacing exceeds both extents: a single grid point at (0, 0)
        pattern = self.make_pattern(area_bounds=(0, 5, 0, 5), spacing_m=10.0)
        node = SimNode(id="test", position=(3.0, 4.0, 0.0))

        pattern.step(node, dt_us=1_000_000)

        assert node.position == (0.0, 0.0, 0.0)
        # Further steps neither move the node nor raise
        pattern.step(node, dt_us=1_000_000)
        assert node.position == (0.0, 0.0, 0.0)

    def test_reset_restores_initial_state(self) -> None:
        pattern = self.make_pattern()
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))
        for _ in range(5):
            pattern.step(node, dt_us=500_000)

        pattern.reset()

        assert pattern._current is None
        assert pattern._target_cell is None

        # After reset the node is re-snapped on the next step
        pattern.step(node, dt_us=0)
        assert node.position == (0.0, 0.0, 0.0)

    def test_seed_reproducibility(self) -> None:
        """Same seed should produce same grid movement."""
        node1 = SimNode(id="test1", position=(5.0, 5.0, 0.0))
        node2 = SimNode(id="test2", position=(5.0, 5.0, 0.0))
        pattern1 = self.make_pattern()
        pattern2 = self.make_pattern()

        for _ in range(50):
            pattern1.step(node1, dt_us=100_000)
            pattern2.step(node2, dt_us=100_000)

        assert node1.position == node2.position

    def test_unseeded_pattern_runs(self) -> None:
        pattern = self.make_pattern(seed=None)
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))

        for _ in range(50):
            pattern.step(node, dt_us=100_000)
            x, y, _ = node.position
            assert 0.0 <= x <= 100.0
            assert 0.0 <= y <= 100.0


class TestManhattanGridManager:
    """Tests for ManhattanGrid registration via MobilityManager."""

    def test_attach_and_step(self) -> None:
        manager = MobilityManager()
        pattern = ManhattanGrid(
            area_bounds=(0, 100, 0, 100),
            spacing_m=10.0,
            speed_m_s=10.0,
            seed=42,
        )
        node = SimNode(id="node-0", position=(50.0, 50.0, 0.0))
        nodes = {"node-0": node}

        manager.attach("node-0", pattern)
        assert manager.get_pattern("node-0") is pattern

        manager.step_all(nodes, dt_us=1_000_000)

        # Snapped onto the grid at (50, 50) and moved along one axis
        assert node.position != (50.0, 50.0, 0.0)
        assert node.position[0] == pytest.approx(50.0, abs=1e-9) or node.position[1] == (
            pytest.approx(50.0, abs=1e-9)
        )
