# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the ManhattanGrid mobility pattern."""

from __future__ import annotations

import math
import random
from collections.abc import Sequence
from typing import Any

import pytest

from lichen.sim.mobility import (
    GridDirection,
    ManhattanGrid,
    MobilityManager,
    WaypointState,
)
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


class TestManhattanGridDirections:
    """Tests for intersection detection and direction selection."""

    def make_pattern(
        self,
        area_bounds: tuple[float, float, float, float] = (0, 100, 0, 100),
        spacing_m: float = 10.0,
        seed: int | None = 42,
    ) -> ManhattanGrid:
        return ManhattanGrid(area_bounds=area_bounds, spacing_m=spacing_m, seed=seed)

    def test_detect_intersection_at_grid_points(self) -> None:
        pattern = self.make_pattern()

        assert pattern.detect_intersection(0.0, 0.0)
        assert pattern.detect_intersection(20.0, 50.0)
        assert pattern.detect_intersection(50.0, 50.0)
        assert pattern.detect_intersection(100.0, 100.0)  # boundary corner

    def test_detect_intersection_mid_segment(self) -> None:
        pattern = self.make_pattern()

        # On an x grid line but between y grid lines
        assert not pattern.detect_intersection(20.0, 45.0)
        # On a y grid line but between x grid lines
        assert not pattern.detect_intersection(25.0, 50.0)
        # Off both grid lines
        assert not pattern.detect_intersection(23.0, 47.0)

    def test_detect_intersection_tolerance(self) -> None:
        pattern = self.make_pattern()

        # Within 1e-9 m of a grid point counts as on it
        assert pattern.detect_intersection(20.0 + 1e-10, 50.0 - 1e-10)
        # Clearly off the grid line does not
        assert not pattern.detect_intersection(20.0 + 1e-6, 50.0)

    def test_pick_never_reverses_when_alternatives_exist(self) -> None:
        for seed in range(50):
            pattern = self.make_pattern(seed=seed)
            pattern._current = (5, 5)
            pattern._direction = GridDirection.UP
            pattern._pick_next_cell()

            assert pattern._direction is not None
            assert pattern._direction is not GridDirection.DOWN
            assert pattern._target_cell is not None
            di, dj = pattern._direction.value
            assert pattern._target_cell == (5 + di, 5 + dj)

    def test_no_reverse_along_one_wide_corridor(self) -> None:
        # Bounds narrower than one spacing: a single column of grid points
        pattern = self.make_pattern(area_bounds=(0, 5, 0, 100))
        assert pattern._grid_size(0) == 0

        pattern._current = (0, 5)
        pattern._direction = GridDirection.UP
        pattern._pick_next_cell()

        # DOWN is the reverse and there is no lateral option: keep going UP
        assert pattern._direction is GridDirection.UP
        assert pattern._target_cell == (0, 6)

    def test_forced_u_turn_at_dead_end(self) -> None:
        # Top of a one-wide corridor: the only in-bounds move is the reverse
        pattern = self.make_pattern(area_bounds=(0, 5, 0, 100))

        pattern._current = (0, 10)
        pattern._direction = GridDirection.UP
        pattern._pick_next_cell()

        assert pattern._direction is GridDirection.DOWN
        assert pattern._target_cell == (0, 9)

    def test_corner_excludes_reverse(self) -> None:
        # Arriving at the bottom-left corner moving LEFT: only UP remains
        pattern = self.make_pattern()

        pattern._current = (0, 0)
        pattern._direction = GridDirection.LEFT
        pattern._pick_next_cell()

        assert pattern._direction is GridDirection.UP
        assert pattern._target_cell == (0, 1)

    def test_corner_first_visit_two_candidates(self) -> None:
        pattern = self.make_pattern()

        pattern._current = (0, 0)
        pattern._direction = None
        pattern._pick_next_cell()

        assert pattern._direction in (GridDirection.RIGHT, GridDirection.UP)

    def test_edge_candidate_set(self) -> None:
        # Bottom edge (not a corner): right, left, up - never down
        pattern = self.make_pattern()
        seen: set[GridDirection] = set()

        for seed in range(40):
            pattern._rng = random.Random(seed)
            pattern._current = (5, 0)
            pattern._direction = None
            pattern._pick_next_cell()
            assert pattern._direction is not None
            seen.add(pattern._direction)

        assert seen == {GridDirection.RIGHT, GridDirection.LEFT, GridDirection.UP}

    def test_interior_first_visit_four_candidates(self) -> None:
        pattern = self.make_pattern()
        seen: set[GridDirection] = set()

        for seed in range(40):
            pattern._rng = random.Random(seed)
            pattern._current = (5, 5)
            pattern._direction = None
            pattern._pick_next_cell()
            assert pattern._direction is not None
            seen.add(pattern._direction)

        assert seen == set(GridDirection)

    def test_direction_state_persists_across_steps(self) -> None:
        pattern = self.make_pattern(seed=42)
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))

        for _ in range(200):
            pattern.step(node, dt_us=100_000)
            # Whenever a leg is in flight, _direction matches it
            if pattern._target_cell is not None and pattern._current is not None:
                ci, cj = pattern._current
                ti, tj = pattern._target_cell
                assert pattern._direction is not None
                di, dj = pattern._direction.value
                assert (ci + di, cj + dj) == (ti, tj)

        # Direction survives step boundaries (persists while between legs)
        assert pattern._direction is not None

    def test_reset_clears_direction(self) -> None:
        pattern = self.make_pattern(seed=42)
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))
        pattern.step(node, dt_us=500_000)
        assert pattern._direction is not None

        pattern.reset()

        assert pattern._direction is None
        assert pattern._target_cell is None


class _DrawCountingRandom(random.Random):
    """Random that counts random() (Bernoulli) and choice() draws.

    getrandbits() is overridden too: without it, Random._randbelow
    falls back to random() for choice() draws, which would tangle the
    Bernoulli counter with the direction-pick counter.
    """

    def __init__(self, seed: int | None) -> None:
        super().__init__(seed)
        self.random_draws = 0
        self.choice_draws = 0
        self.getrandbits_draws = 0

    def random(self) -> float:
        self.random_draws += 1
        return super().random()

    def getrandbits(self, k: int) -> int:
        self.getrandbits_draws += 1
        return super().getrandbits(k)

    def choice(self, seq: Sequence[Any]) -> Any:
        self.choice_draws += 1
        return super().choice(seq)


class TestManhattanGridPause:
    """Tests for pause behavior at ManhattanGrid intersections.

    Analytic timeline used by several tests (independent oracle): with
    spacing_m=10, speed_m_s=1.0, dt_us=100_000 every leg takes exactly
    10s (100 steps), so over 300 steps (30s) the node makes its first
    pick at t=0 and arrives at intersections at t=10s and t=22s. With
    pause_probability=1.0 and pause_time_us=2_000_000 the pauses span
    [10, 12) and [22, 24), leaving exactly 26s (26m) of travel.
    """

    # Analytic timeline constants (see class docstring)
    PAUSE_US = 2_000_000
    STEP_US = 100_000

    def make_pattern(self, **kwargs: object) -> ManhattanGrid:
        params: dict[str, object] = {
            "area_bounds": (0, 100, 0, 100),
            "spacing_m": 10.0,
            "speed_m_s": 1.0,
            "seed": 42,
        }
        params.update(kwargs)
        return ManhattanGrid(**params)  # type: ignore[arg-type]

    @staticmethod
    def _run(
        pattern: ManhattanGrid, steps: int, dt_us: int = 100_000
    ) -> tuple[SimNode, list[tuple[float, float]], list[WaypointState]]:
        """Step a fresh node through the standard timeline, recording samples.

        A zero-length pre-step performs the initial grid snap so that
        every recorded sample delta corresponds to exactly one step of
        movement (per-step float rounding may shift an arrival across a
        sample boundary by one step; the tests below assert only
        drift-robust invariants).
        """
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))
        pattern.step(node, 0)
        positions: list[tuple[float, float]] = [
            (node.position[0], node.position[1])
        ]
        states: list[WaypointState] = [pattern._state]
        for _ in range(steps):
            pattern.step(node, dt_us)
            positions.append((node.position[0], node.position[1]))
            states.append(pattern._state)
        return node, positions, states

    @staticmethod
    def _path_length(positions: list[tuple[float, float]]) -> float:
        """Total distance covered across consecutive position samples."""
        return sum(
            math.hypot(b[0] - a[0], b[1] - a[1])
            for a, b in zip(positions, positions[1:], strict=False)
        )

    @staticmethod
    def _stationary_runs(positions: list[tuple[float, float]]) -> list[int]:
        """Lengths of maximal runs of identical consecutive positions."""
        runs: list[int] = []
        current = 1
        for a, b in zip(positions, positions[1:], strict=False):
            if a == b:
                current += 1
            else:
                runs.append(current)
                current = 1
        runs.append(current)
        return runs

    def test_rejects_bad_pause_probability(self) -> None:
        for bad in (-0.1, 1.1, 2.0, math.nan):
            with pytest.raises(ValueError, match="pause_probability"):
                ManhattanGrid(area_bounds=(0, 100, 0, 100), pause_probability=bad)

    def test_rejects_bad_pause_time(self) -> None:
        with pytest.raises(ValueError, match="pause_time_us"):
            ManhattanGrid(area_bounds=(0, 100, 0, 100), pause_time_us=-1)

    def test_pause_probability_zero_draws_no_rng(self) -> None:
        """Default config must add zero RNG draws over the base pattern."""
        pattern = self.make_pattern()
        pattern._rng = _DrawCountingRandom(42)

        _, positions, _ = self._run(pattern, steps=250)

        # 3 direction picks (initial + arrivals at t=10 and t=20; the
        # 25s window cannot contain a third drift-shifted arrival),
        # and zero Bernoulli draws
        assert isinstance(pattern._rng, _DrawCountingRandom)
        assert pattern._rng.choice_draws == 3
        assert pattern._rng.random_draws == 0
        # And the node traveled the full 25s worth of distance
        assert self._path_length(positions) == pytest.approx(25.0, abs=1e-6)

    def test_pause_probability_zero_trajectory_ignores_pause_time(self) -> None:
        """With p=0.0 the pause duration must not affect the trajectory."""
        finals = []
        for pause_us in (5_000_000, 999_999_999):
            pattern = self.make_pattern(pause_time_us=pause_us)
            node, _, _ = self._run(pattern, steps=300)
            finals.append(node.position)

        assert finals[0] == finals[1]

    def test_pause_fires_with_probability_one(self) -> None:
        pattern = self.make_pattern(pause_probability=1.0, pause_time_us=2_000_000)

        node, positions, states = self._run(pattern, steps=300)

        # Pauses actually happened, at intersections
        assert WaypointState.PAUSED in states
        paused = [p for p, s in zip(positions, states, strict=True) if s is WaypointState.PAUSED]
        assert paused
        for x, y in paused:
            assert pattern.detect_intersection(x, y)
        # 30s sim - 2 pauses x 2s = 26s of travel at 1 m/s
        assert self._path_length(positions) == pytest.approx(26.0, abs=1e-6)

    def test_pause_state_transitions_and_duration(self) -> None:
        pattern = self.make_pattern(pause_probability=1.0, pause_time_us=2_000_000)

        _, positions, states = self._run(pattern, steps=300)

        # Exactly two arrivals in 30s -> two MOVING->PAUSED->MOVING cycles
        to_paused = sum(
            1
            for a, b in zip(states, states[1:], strict=False)
            if a is WaypointState.MOVING and b is WaypointState.PAUSED
        )
        to_moving = sum(
            1
            for a, b in zip(states, states[1:], strict=False)
            if a is WaypointState.PAUSED and b is WaypointState.MOVING
        )
        assert to_paused == 2
        assert to_moving == 2

        # Each stationary run lasts exactly pause_time_us: 2s / 0.1s = 20
        # pause steps, plus the arrival sample itself when the arrival
        # lands exactly on a sample boundary (21 vs 20 is float drift).
        # Movement runs are always longer than the pause window.
        runs = self._stationary_runs(positions)
        min_pause_run = self.PAUSE_US // self.STEP_US
        pause_runs = [r for r in runs if min_pause_run <= r <= min_pause_run + 1]
        assert len(pause_runs) == 2

        # Total travel time is conserved regardless of drift:
        # 30s sim - 2 pauses x 2s = 26s at 1 m/s
        assert self._path_length(positions) == pytest.approx(26.0, abs=1e-6)

    def test_zero_duration_pause_never_enters_paused(self) -> None:
        """pause_time_us=0 must not create a 0us PAUSED<->MOVING loop."""
        pattern = self.make_pattern(pause_probability=1.0, pause_time_us=0)

        node, _, states = self._run(pattern, steps=300)

        assert all(s is WaypointState.MOVING for s in states)
        assert pattern._pause_remaining_us == 0
        # The node still traveled the full 30m (no pause time consumed)
        x, y = node.position[0], node.position[1]
        assert math.hypot(x, y) > 0.0

    def test_pause_persists_across_step_boundary(self) -> None:
        pattern = self.make_pattern(pause_probability=1.0, pause_time_us=2_000_000)
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))

        # One step exactly one leg long: arrival lands at the step end,
        # the pause must be entered and survive into the next step
        pattern.step(node, dt_us=10_000_000)
        assert pattern._state is WaypointState.PAUSED
        assert pattern._pause_remaining_us == 2_000_000
        assert pattern.detect_intersection(node.position[0], node.position[1])

        # Pause consumes the next step; the node does not move
        before = node.position
        pattern.step(node, dt_us=100_000)
        assert node.position == before
        assert pattern._pause_remaining_us == 1_900_000

    def test_reset_clears_pause_state(self) -> None:
        pattern = self.make_pattern(pause_probability=1.0, pause_time_us=2_000_000)
        node = SimNode(id="test", position=(5.0, 5.0, 0.0))
        pattern.step(node, dt_us=10_000_000)
        assert pattern._state is WaypointState.PAUSED

        pattern.reset()

        assert pattern._state is WaypointState.MOVING
        assert pattern._pause_remaining_us == 0


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
