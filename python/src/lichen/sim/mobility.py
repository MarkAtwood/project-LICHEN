# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Mobility patterns for LICHEN simulator.

Provides gradual node movement patterns as an alternative to instant
teleportation via set_position(). Each pattern implements step(node, dt)
to advance node position over time.

Example usage:
    from lichen.sim.mobility import RandomWaypoint

    # Create pattern: 500m x 500m area, 1 m/s speed, 5s pause
    pattern = RandomWaypoint(
        area_bounds=(0, 500, 0, 500),
        speed_m_s=1.0,
        pause_time_us=5_000_000,
        seed=42,
    )

    # In simulation loop:
    pattern.step(node, dt_us=1_000_000)  # 1 second step
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lichen.sim.node import SimNode

# Upper bound on state transitions (waypoint arrivals, intersection visits)
# within a single step() call. Guards against giant-dt steps combined with
# sub-microsecond leg times turning step() into a near-infinite loop.
_MAX_STEP_ITERATIONS = 100_000


def _require_finite(name: str, value: float, *, allow_zero: bool = False) -> None:
    """Reject NaN/inf config values that would poison position geometry.

    NaN silently defeats ``<= 0`` comparisons (nan <= 0 is False) and
    propagates through distance/sqrt arithmetic; inf turns arrival charging
    into a no-op (distance/inf == 0) and burns the step-iteration cap.
    """
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value}")
    if not allow_zero and value <= 0:
        raise ValueError(f"{name} must be > 0, got {value}")


def _require_finite_bounds(name: str, bounds: tuple[float, float, float, float]) -> None:
    """Reject non-finite or inverted area bounds."""
    for component in bounds:
        _require_finite(name, component, allow_zero=True)
    min_x, max_x, min_y, max_y = bounds
    if min_x >= max_x or min_y >= max_y:
        raise ValueError(f"{name} must have min < max, got {bounds}")


class MobilityPattern(ABC):
    """Base class for node mobility patterns.

    Subclasses implement step() to update node position over time.
    Patterns maintain their own state (destination, pause timer, etc).
    """

    @abstractmethod
    def step(self, node: SimNode, dt_us: int) -> None:
        """Advance the node's position by dt_us microseconds.

        Args:
            node: The SimNode to move.
            dt_us: Time step in microseconds.
        """
        ...

    @abstractmethod
    def reset(self) -> None:
        """Reset pattern state for reuse or reattachment to new node."""
        ...


class WaypointState(Enum):
    """State of a RandomWaypoint pattern."""

    MOVING = auto()
    PAUSED = auto()


@dataclass
class RandomWaypoint(MobilityPattern):
    """Random waypoint mobility pattern.

    Node picks a random destination within bounds, moves toward it at
    constant speed, pauses for a duration, then picks a new destination.

    Attributes:
        area_bounds: (min_x, max_x, min_y, max_y) in meters.
        speed_m_s: Movement speed in meters per second.
        pause_time_us: Pause duration at each waypoint in microseconds.
        seed: Random seed for reproducibility (None for random).
        z: Fixed altitude in meters (nodes stay at this height).
    """

    area_bounds: tuple[float, float, float, float]
    speed_m_s: float = 1.0
    pause_time_us: int = 5_000_000
    seed: int | None = None
    z: float = 0.0

    # Internal state
    _rng: random.Random = field(init=False, repr=False)
    _state: WaypointState = field(init=False, default=WaypointState.PAUSED)
    _target: tuple[float, float] | None = field(init=False, default=None)
    _pause_remaining_us: float = field(init=False, default=0)

    def __post_init__(self) -> None:
        _require_finite("speed_m_s", self.speed_m_s)
        if self.pause_time_us < 0:
            raise ValueError(f"pause_time_us must be >= 0, got {self.pause_time_us}")
        _require_finite_bounds("area_bounds", self.area_bounds)
        self._rng = random.Random(self.seed)
        self._state = WaypointState.PAUSED
        self._target = None
        self._pause_remaining_us = 0

    def reset(self) -> None:
        """Reset pattern to initial state."""
        self._rng = random.Random(self.seed)
        self._state = WaypointState.PAUSED
        self._target = None
        self._pause_remaining_us = 0

    def step(self, node: SimNode, dt_us: int) -> None:
        """Advance node position by dt_us microseconds.

        Args:
            node: The SimNode to move.
            dt_us: Time step in microseconds.
        """
        remaining_us: float = dt_us

        iterations = 0
        while remaining_us > 0:
            iterations += 1
            if iterations > _MAX_STEP_ITERATIONS:
                break
            if self._state == WaypointState.PAUSED:
                remaining_us = self._handle_paused(node, remaining_us)
            else:
                remaining_us = self._handle_moving(node, remaining_us)

    def _handle_paused(self, node: SimNode, remaining_us: float) -> float:
        """Handle pause state, returns remaining time after state change."""
        if self._pause_remaining_us > 0:
            if remaining_us <= self._pause_remaining_us:
                self._pause_remaining_us -= remaining_us
                return 0
            remaining_us -= self._pause_remaining_us
            self._pause_remaining_us = 0

        # Pause complete - pick new destination and start moving
        self._target = self._pick_waypoint()
        self._state = WaypointState.MOVING
        return remaining_us

    def _handle_moving(self, node: SimNode, remaining_us: float) -> float:
        """Handle moving state, returns remaining time after state change."""
        if self._target is None:
            # No target - go to pause state
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            return remaining_us

        x, y, _ = node.position
        tx, ty = self._target

        dx = tx - x
        dy = ty - y
        distance = math.sqrt(dx * dx + dy * dy)

        if distance < 1e-6:
            # Arrived at waypoint - enter pause
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us

        # Calculate how far we can move in remaining time
        time_s = remaining_us / 1_000_000.0
        max_distance = self.speed_m_s * time_s

        if max_distance >= distance:
            # We arrive this step
            node.set_position(tx, ty, self.z)
            time_used_us = distance / self.speed_m_s * 1_000_000
            if time_used_us >= 1.0:
                time_used_us = float(int(time_used_us))
            # else: sub-microsecond leg. int() would truncate to 0, consuming
            # no time and stalling the loop; charging the true float value
            # keeps time-to-motion accounting exact. Termination is
            # guaranteed by the iteration cap, not strict decrease (a tiny
            # charge can be absorbed by float ULP).
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us - time_used_us

        # Move toward target
        ratio = max_distance / distance
        new_x = x + dx * ratio
        new_y = y + dy * ratio
        node.set_position(new_x, new_y, self.z)
        return 0

    def _pick_waypoint(self) -> tuple[float, float]:
        """Pick a random waypoint within bounds."""
        min_x, max_x, min_y, max_y = self.area_bounds
        x = self._rng.uniform(min_x, max_x)
        y = self._rng.uniform(min_y, max_y)
        return (x, y)


@dataclass
class GroupMobility(MobilityPattern):
    """Group mobility pattern.

    A virtual group center navigates random waypoints within the area,
    while member nodes hold fixed offsets relative to the center. The
    first registered member sits at the center; remaining members are
    evenly spaced on a ring of radius group_radius_m around it.

    Center waypoints are picked within the bounds inset by
    group_radius_m, and the initial center is clamped into that inset,
    so every member stays inside area_bounds at all times.

    Attach the pattern to MobilityManager under one representative node
    id; step() moves all registered members. Attach one pattern instance
    per group only (attaching the same instance to multiple node ids
    would step the group once per attachment).

    Attributes:
        area_bounds: (min_x, max_x, min_y, max_y) in meters.
        speed_m_s: Group center movement speed in meters per second.
        pause_time_us: Pause duration at each waypoint in microseconds.
        seed: Random seed for reproducibility (None for random).
        z: Fixed altitude in meters (members stay at this height).
        group_size: Maximum number of member nodes in the group.
        group_radius_m: Distance from the center to ring members in meters.
        jitter_m: Maximum per-member offset jitter magnitude in meters.
            0.0 (default) disables jitter entirely and reproduces the
            exact fixed-ring formation.
        jitter_update_us: Interval in microseconds between draws of new
            jitter targets for all members.

    When jitter_m > 0, each member carries a random displacement of
    magnitude at most jitter_m around its fixed base offset. New jitter
    targets are drawn every jitter_update_us and members glide toward
    them at up to jitter_m per interval, so transitions are smooth (no
    teleporting) while center + offset + jitter always stays within
    area_bounds (center waypoints are inset by group_radius_m + jitter_m).

    Raises:
        ValueError: If group_size < 1, speed_m_s <= 0, pause_time_us < 0,
            area_bounds min/max are inverted, group_radius_m is negative,
            jitter_m is negative, jitter_update_us is not positive, or
            group_radius_m + jitter_m is too large for the group to fit
            within bounds.
    """

    area_bounds: tuple[float, float, float, float]
    speed_m_s: float = 1.0
    pause_time_us: int = 5_000_000
    seed: int | None = None
    z: float = 0.0
    group_size: int = 1
    group_radius_m: float = 0.0
    jitter_m: float = 0.0
    jitter_update_us: int = 5_000_000

    # Internal state
    _rng: random.Random = field(init=False, repr=False)
    _state: WaypointState = field(init=False, default=WaypointState.PAUSED)
    _target: tuple[float, float] | None = field(init=False, default=None)
    _pause_remaining_us: float = field(init=False, default=0)
    _center: tuple[float, float] | None = field(init=False, default=None)
    _members: list[SimNode] = field(init=False, repr=False, default_factory=list)
    _offsets: list[tuple[float, float]] = field(init=False, repr=False, default_factory=list)
    _jitter_current: list[tuple[float, float]] = field(init=False, repr=False, default_factory=list)
    _jitter_target: list[tuple[float, float]] = field(init=False, repr=False, default_factory=list)
    _jitter_elapsed_us: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        if self.group_size < 1:
            raise ValueError(f"group_size must be >= 1, got {self.group_size}")
        _require_finite("speed_m_s", self.speed_m_s)
        if self.pause_time_us < 0:
            raise ValueError(f"pause_time_us must be >= 0, got {self.pause_time_us}")
        _require_finite_bounds("area_bounds", self.area_bounds)
        if self.group_radius_m < 0:
            raise ValueError(f"group_radius_m must be >= 0, got {self.group_radius_m}")
        if self.jitter_m < 0:
            raise ValueError(f"jitter_m must be >= 0, got {self.jitter_m}")
        if self.jitter_update_us <= 0:
            raise ValueError(f"jitter_update_us must be > 0, got {self.jitter_update_us}")
        _min_x, max_x, _min_y, max_y = self.area_bounds
        if 2 * (self.group_radius_m + self.jitter_m) > min(max_x - _min_x, max_y - _min_y):
            raise ValueError(
                f"group_radius_m {self.group_radius_m} + jitter_m {self.jitter_m}"
                f" too large for area_bounds"
            )
        self._init_state()

    def _init_state(self) -> None:
        self._rng = random.Random(self.seed)
        self._state = WaypointState.PAUSED
        self._target = None
        self._pause_remaining_us = 0
        self._center = None
        self._members = []
        self._offsets = []
        self._jitter_current = []
        self._jitter_target = []
        self._jitter_elapsed_us = 0

    def reset(self) -> None:
        """Reset pattern state, clearing group membership."""
        self._init_state()

    def add_member(self, node: SimNode) -> None:
        """Register a node as a group member.

        The member receives a base offset relative to the group center:
        the first member sits at the center, later members are evenly
        spaced on a ring of radius group_radius_m. When jitter_m > 0 the
        member additionally starts with zero jitter displacement and an
        initial jitter target of magnitude at most jitter_m, which it
        glides toward from the next step() on. The node's position is
        not changed until the next step().

        Args:
            node: The SimNode to add to the group.

        Raises:
            ValueError: If the group already has group_size members.
        """
        if len(self._members) >= self.group_size:
            raise ValueError(f"group is full at group_size={self.group_size}")
        self._members.append(node)
        self._offsets.append(self._offset_for(len(self._members) - 1))
        if self.jitter_m > 0.0:
            self._jitter_current.append((0.0, 0.0))
            self._jitter_target.append(self._draw_jitter())

    def step(self, node: SimNode, dt_us: int) -> None:
        """Advance the group center and reposition all members.

        The center navigates waypoints as in RandomWaypoint; after the
        step each member is placed at center + its base offset (plus its
        current jitter displacement when jitter_m > 0). Does nothing
        until at least one member is registered; the center then starts
        at the first member's position. The node argument is the
        attachment anchor used by MobilityManager and is moved only if
        registered as a member.

        Args:
            node: The SimNode the pattern is attached to.
            dt_us: Time step in microseconds.
        """
        if not self._members:
            return

        if self._center is None:
            x, y, _ = self._members[0].position
            min_x, max_x, min_y, max_y = self.area_bounds
            inset = self.group_radius_m + self.jitter_m
            self._center = (
                min(max(x, min_x + inset), max_x - inset),
                min(max(y, min_y + inset), max_y - inset),
            )

        remaining_us: float = dt_us
        iterations = 0
        while remaining_us > 0:
            iterations += 1
            if iterations > _MAX_STEP_ITERATIONS:
                break
            if self._state == WaypointState.PAUSED:
                remaining_us = self._handle_paused(remaining_us)
            else:
                remaining_us = self._handle_moving(remaining_us)

        self._update_jitter(dt_us)
        self._place_members()

    def _offset_for(self, index: int) -> tuple[float, float]:
        """Return the fixed offset for the member registered at index."""
        if index == 0:
            return (0.0, 0.0)
        angle = 2.0 * math.pi * (index - 1) / (self.group_size - 1)
        return (self.group_radius_m * math.cos(angle), self.group_radius_m * math.sin(angle))

    def _draw_jitter(self) -> tuple[float, float]:
        """Draw a random jitter displacement of magnitude at most jitter_m."""
        magnitude = self._rng.uniform(0.0, self.jitter_m)
        angle = self._rng.uniform(0.0, 2.0 * math.pi)
        return (magnitude * math.cos(angle), magnitude * math.sin(angle))

    def _update_jitter(self, dt_us: int) -> None:
        """Advance jitter state: retarget on timer and glide toward targets.

        Members move toward their jitter target at up to jitter_m per
        jitter_update_us, so displacement changes smoothly across steps
        and never exceeds jitter_m in magnitude.
        """
        if self.jitter_m <= 0.0:
            return
        self._jitter_elapsed_us += dt_us
        redraws = 0
        while self._jitter_elapsed_us >= self.jitter_update_us:
            self._jitter_elapsed_us -= self.jitter_update_us
            redraws += 1
            if redraws > _MAX_STEP_ITERATIONS:
                # Giant dt with a tiny update interval: cap the redraw
                # churn the same way step() caps leg transitions. Only
                # the last-drawn targets matter for the glide.
                self._jitter_elapsed_us = 0
                break
            self._jitter_target = [self._draw_jitter() for _ in self._members]
        progress = min(1.0, dt_us / self.jitter_update_us)
        max_step = self.jitter_m * progress
        self._jitter_current = [
            self._move_toward(current, target, max_step)
            for current, target in zip(self._jitter_current, self._jitter_target, strict=True)
        ]

    @staticmethod
    def _move_toward(
        current: tuple[float, float], target: tuple[float, float], max_step: float
    ) -> tuple[float, float]:
        """Move current toward target by at most max_step (Euclidean)."""
        dx = target[0] - current[0]
        dy = target[1] - current[1]
        distance = math.sqrt(dx * dx + dy * dy)
        if distance <= max_step:
            return target
        ratio = max_step / distance
        return (current[0] + dx * ratio, current[1] + dy * ratio)

    def _handle_paused(self, remaining_us: float) -> float:
        """Handle pause state, returns remaining time after state change."""
        if self._pause_remaining_us > 0:
            if remaining_us <= self._pause_remaining_us:
                self._pause_remaining_us -= remaining_us
                return 0
            remaining_us -= self._pause_remaining_us
            self._pause_remaining_us = 0

        self._target = self._pick_waypoint()
        self._state = WaypointState.MOVING
        return remaining_us

    def _handle_moving(self, remaining_us: float) -> float:
        """Handle moving state, returns remaining time after state change."""
        if self._target is None or self._center is None:
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us

        cx, cy = self._center
        tx, ty = self._target

        dx = tx - cx
        dy = ty - cy
        distance = math.sqrt(dx * dx + dy * dy)

        if distance < 1e-6:
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us

        time_s = remaining_us / 1_000_000.0
        max_distance = self.speed_m_s * time_s

        if max_distance >= distance:
            self._center = (tx, ty)
            time_used_us = distance / self.speed_m_s * 1_000_000
            if time_used_us >= 1.0:
                time_used_us = float(int(time_used_us))
            # else: sub-microsecond leg. int() would truncate to 0, consuming
            # no time and stalling the PAUSED<->MOVING cycle; charging the
            # true float value keeps time-to-motion accounting exact.
            # Termination is guaranteed by the iteration cap, not strict
            # decrease (a tiny charge can be absorbed by float ULP).
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us - time_used_us

        ratio = max_distance / distance
        self._center = (cx + dx * ratio, cy + dy * ratio)
        return 0

    def _pick_waypoint(self) -> tuple[float, float]:
        """Pick a random waypoint within the bounds inset by group radius + jitter."""
        min_x, max_x, min_y, max_y = self.area_bounds
        inset = self.group_radius_m + self.jitter_m
        x = self._rng.uniform(min_x + inset, max_x - inset)
        y = self._rng.uniform(min_y + inset, max_y - inset)
        return (x, y)

    def _place_members(self) -> None:
        """Place each member at the center plus its offset (and jitter)."""
        if self._center is None:
            return
        cx, cy = self._center
        if self.jitter_m <= 0.0:
            for member, (ox, oy) in zip(self._members, self._offsets, strict=True):
                member.set_position(cx + ox, cy + oy, self.z)
            return
        for member, (ox, oy), (jx, jy) in zip(
            self._members, self._offsets, self._jitter_current, strict=True
        ):
            member.set_position(cx + ox + jx, cy + oy + jy, self.z)


@dataclass
class RPGM(MobilityPattern):
    """Reference Point Group Mobility (RPGM) pattern.

    A reference point (the group center) navigates random waypoints
    within the area exactly as in RandomWaypoint, while member nodes
    keep individual random offsets relative to it. Each member draws
    its offset once at add_member() time, uniformly within a disk of
    radius max_offset_m around the reference point; member positions
    are recomputed as center + offset on every step, so members track
    the reference point with fixed relative geometry.

    Reference-point waypoints are picked within the bounds inset by
    max_offset_m, and the initial reference point is clamped into that
    inset, so every member stays inside area_bounds at all times.

    Attach the pattern to MobilityManager under one representative node
    id; step() moves all registered members. The node argument is the
    attachment anchor used by MobilityManager and is moved only if
    registered as a member.

    Attributes:
        area_bounds: (min_x, max_x, min_y, max_y) in meters.
        speed_m_s: Reference point movement speed in meters per second.
        pause_time_us: Pause duration at each waypoint in microseconds.
        seed: Random seed for reproducibility (None for random).
        z: Fixed altitude in meters (members stay at this height).
        max_offset_m: Maximum member offset magnitude from the reference
            point in meters (the bound on offset variance).

    Raises:
        ValueError: If speed_m_s <= 0, pause_time_us < 0, area_bounds
            min/max are inverted, or max_offset_m is negative or too
            large for members to fit within bounds.
    """

    area_bounds: tuple[float, float, float, float]
    speed_m_s: float = 1.0
    pause_time_us: int = 5_000_000
    seed: int | None = None
    z: float = 0.0
    max_offset_m: float = 0.0

    # Internal state
    _rng: random.Random = field(init=False, repr=False)
    _state: WaypointState = field(init=False, default=WaypointState.PAUSED)
    _target: tuple[float, float] | None = field(init=False, default=None)
    _pause_remaining_us: float = field(init=False, default=0)
    _center: tuple[float, float] | None = field(init=False, default=None)
    _members: list[SimNode] = field(init=False, repr=False, default_factory=list)
    _offsets: list[tuple[float, float]] = field(init=False, repr=False, default_factory=list)

    def __post_init__(self) -> None:
        _require_finite("speed_m_s", self.speed_m_s)
        if self.pause_time_us < 0:
            raise ValueError(f"pause_time_us must be >= 0, got {self.pause_time_us}")
        _require_finite_bounds("area_bounds", self.area_bounds)
        if self.max_offset_m < 0:
            raise ValueError(f"max_offset_m must be >= 0, got {self.max_offset_m}")
        _min_x, max_x, _min_y, max_y = self.area_bounds
        if 2 * self.max_offset_m > min(max_x - _min_x, max_y - _min_y):
            raise ValueError(f"max_offset_m {self.max_offset_m} too large for area_bounds")
        self._init_state()

    def _init_state(self) -> None:
        self._rng = random.Random(self.seed)
        self._state = WaypointState.PAUSED
        self._target = None
        self._pause_remaining_us = 0
        self._center = None
        self._members = []
        self._offsets = []

    def reset(self) -> None:
        """Reset pattern state, clearing group membership."""
        self._init_state()

    def add_member(self, node: SimNode) -> None:
        """Register a node as a group member.

        The member draws a random offset once, uniformly within a disk
        of radius max_offset_m around the reference point; it keeps that
        offset for the lifetime of the pattern. The node's position is
        not changed until the next step().

        Args:
            node: The SimNode to add to the group.
        """
        self._members.append(node)
        self._offsets.append(self._draw_offset())

    def step(self, node: SimNode, dt_us: int) -> None:
        """Advance the reference point and reposition all members.

        The reference point navigates waypoints as in RandomWaypoint;
        after the step each member is placed at center + its random
        offset. Does nothing until at least one member is registered;
        the reference point then starts at the first member's position,
        clamped into the max_offset_m inset.

        Args:
            node: The SimNode the pattern is attached to.
            dt_us: Time step in microseconds.
        """
        if not self._members:
            return

        if self._center is None:
            x, y, _ = self._members[0].position
            min_x, max_x, min_y, max_y = self.area_bounds
            self._center = (
                min(max(x, min_x + self.max_offset_m), max_x - self.max_offset_m),
                min(max(y, min_y + self.max_offset_m), max_y - self.max_offset_m),
            )

        remaining_us: float = dt_us
        iterations = 0
        while remaining_us > 0:
            iterations += 1
            if iterations > _MAX_STEP_ITERATIONS:
                break
            if self._state == WaypointState.PAUSED:
                remaining_us = self._handle_paused(remaining_us)
            else:
                remaining_us = self._handle_moving(remaining_us)

        self._place_members()

    def _draw_offset(self) -> tuple[float, float]:
        """Draw a random offset uniformly within the max_offset_m disk."""
        magnitude = self.max_offset_m * math.sqrt(self._rng.random())
        angle = 2.0 * math.pi * self._rng.random()
        return (magnitude * math.cos(angle), magnitude * math.sin(angle))

    def _handle_paused(self, remaining_us: float) -> float:
        """Handle pause state, returns remaining time after state change."""
        if self._pause_remaining_us > 0:
            if remaining_us <= self._pause_remaining_us:
                self._pause_remaining_us -= remaining_us
                return 0
            remaining_us -= self._pause_remaining_us
            self._pause_remaining_us = 0

        self._target = self._pick_waypoint()
        self._state = WaypointState.MOVING
        return remaining_us

    def _handle_moving(self, remaining_us: float) -> float:
        """Handle moving state, returns remaining time after state change."""
        if self._target is None or self._center is None:
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us

        cx, cy = self._center
        tx, ty = self._target

        dx = tx - cx
        dy = ty - cy
        distance = math.sqrt(dx * dx + dy * dy)

        if distance < 1e-6:
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us

        time_s = remaining_us / 1_000_000.0
        max_distance = self.speed_m_s * time_s

        if max_distance >= distance:
            self._center = (tx, ty)
            time_used_us = distance / self.speed_m_s * 1_000_000
            if time_used_us >= 1.0:
                time_used_us = float(int(time_used_us))
            # else: sub-microsecond leg. int() would truncate to 0, consuming
            # no time and stalling the PAUSED<->MOVING cycle; charging the
            # true float value keeps time-to-motion accounting exact.
            # Termination is guaranteed by the iteration cap, not strict
            # decrease (a tiny charge can be absorbed by float ULP).
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us - time_used_us

        ratio = max_distance / distance
        self._center = (cx + dx * ratio, cy + dy * ratio)
        return 0

    def _pick_waypoint(self) -> tuple[float, float]:
        """Pick a random waypoint within the bounds inset by max offset."""
        min_x, max_x, min_y, max_y = self.area_bounds
        x = self._rng.uniform(min_x + self.max_offset_m, max_x - self.max_offset_m)
        y = self._rng.uniform(min_y + self.max_offset_m, max_y - self.max_offset_m)
        return (x, y)

    def _place_members(self) -> None:
        """Place each member at the reference point plus its random offset."""
        if self._center is None:
            return
        cx, cy = self._center
        for member, (ox, oy) in zip(self._members, self._offsets, strict=True):
            member.set_position(cx + ox, cy + oy, self.z)


_GRID_EPSILON = 1e-9


class GridDirection(Enum):
    """Cardinal movement directions along a Manhattan grid.

    Values are (di, dj) grid-index steps. Member order matches the
    historical candidate scan order so that the first direction draw
    from a fresh pattern consumes the RNG identically to the original
    unfiltered implementation.
    """

    RIGHT = (1, 0)
    LEFT = (-1, 0)
    UP = (0, 1)
    DOWN = (0, -1)

    def reverse(self) -> GridDirection:
        """Return the opposite direction."""
        di, dj = self.value
        return GridDirection((-di, -dj))


@dataclass
class ManhattanGrid(MobilityPattern):
    """Manhattan grid mobility pattern.

    Nodes move along the lines of a square street grid anchored at
    (min_x, min_y) with configurable spacing_m, advancing at constant
    speed and choosing a random new direction at each intersection
    (grid point). Movement is always along one grid axis at a time.
    The reverse of the current direction is excluded from the choice
    unless no other direction is available (dead end), in which case
    the node performs a forced U-turn.

    On the first step() the node is snapped onto the nearest grid point
    (initial placement on grid); snap_to_grid() exposes the same
    alignment for arbitrary positions. Grid points lie at
    (min_x + i * spacing_m, min_y + j * spacing_m) for all indices
    that fit inside area_bounds.

    After arriving at an intersection the node pauses for
    pause_time_us with probability pause_probability before picking
    its next direction. Pauses use a fixed duration, matching the
    RandomWaypoint convention of a single fixed pause_time_us;
    random-within-range durations are intentionally not modeled. The
    default pause_probability of 0.0 disables pausing entirely and
    draws no randomness, preserving no-pause trajectories exactly.

    Attributes:
        area_bounds: (min_x, max_x, min_y, max_y) in meters.
        spacing_m: Distance between adjacent grid lines in meters.
        speed_m_s: Movement speed in meters per second.
        pause_time_us: Fixed pause duration at each intersection in
            microseconds.
        pause_probability: Probability of pausing at each intersection,
            between 0.0 (never pause, the default) and 1.0 (always
            pause).
        seed: Random seed for reproducibility (None for random).
        z: Fixed altitude in meters (nodes stay at this height).

    Raises:
        ValueError: If speed_m_s <= 0, spacing_m <= 0, pause_time_us
            < 0, pause_probability is outside [0.0, 1.0], or
            area_bounds min/max are inverted.
    """

    area_bounds: tuple[float, float, float, float]
    spacing_m: float = 10.0
    speed_m_s: float = 1.0
    pause_time_us: int = 5_000_000
    pause_probability: float = 0.0
    seed: int | None = None
    z: float = 0.0

    # Internal state
    _rng: random.Random = field(init=False, repr=False)
    _state: WaypointState = field(init=False, default=WaypointState.MOVING)
    _current: tuple[int, int] | None = field(init=False, default=None)
    _target_cell: tuple[int, int] | None = field(init=False, default=None)
    _direction: GridDirection | None = field(init=False, default=None)
    _pause_remaining_us: float = field(init=False, default=0)

    def __post_init__(self) -> None:
        _require_finite("spacing_m", self.spacing_m)
        _require_finite("speed_m_s", self.speed_m_s)
        if self.pause_time_us < 0:
            raise ValueError(f"pause_time_us must be >= 0, got {self.pause_time_us}")
        if not 0.0 <= self.pause_probability <= 1.0:
            raise ValueError(
                f"pause_probability must be between 0.0 and 1.0, got {self.pause_probability}"
            )
        _require_finite_bounds("area_bounds", self.area_bounds)
        self._init_state()

    def _init_state(self) -> None:
        self._rng = random.Random(self.seed)
        self._state = WaypointState.MOVING
        self._current = None
        self._target_cell = None
        self._direction = None
        self._pause_remaining_us = 0

    def reset(self) -> None:
        """Reset pattern to initial state."""
        self._init_state()

    def snap_to_grid(self, x: float, y: float) -> tuple[float, float]:
        """Snap a position onto the nearest grid point.

        Args:
            x: X coordinate in meters.
            y: Y coordinate in meters.

        Returns:
            The nearest on-grid (x, y) clamped within area_bounds.
        """
        return (
            self._axis_value(self._snap_axis_index(x, 0), 0),
            self._axis_value(self._snap_axis_index(y, 1), 1),
        )

    def detect_intersection(self, x: float, y: float) -> bool:
        """Check whether a position lies on a grid intersection.

        A position is at an intersection when both coordinates sit on
        grid lines, i.e. it coincides with a grid point. A position on
        only one grid line (mid-segment along the other axis) is not an
        intersection.

        Args:
            x: X coordinate in meters.
            y: Y coordinate in meters.

        Returns:
            True if (x, y) lies on both an x and a y grid line (within
            floating point tolerance), False otherwise.
        """
        return self._on_grid_line(x, 0) and self._on_grid_line(y, 1)

    def _on_grid_line(self, value: float, axis: int) -> bool:
        """Return True if value lies on a grid line along axis."""
        lo = self.area_bounds[2 * axis]
        k = (value - lo) / self.spacing_m
        return abs(k - round(k)) * self.spacing_m <= _GRID_EPSILON

    def step(self, node: SimNode, dt_us: int) -> None:
        """Advance the node along grid lines by dt_us microseconds.

        On the first call the node is snapped onto the nearest grid
        point. The node then moves linearly toward the next grid point
        along one axis. On arriving at an intersection it may pause for
        pause_time_us with probability pause_probability, then picks a
        random new direction that is not the reverse of its current
        direction unless no other direction is available. On a
        degenerate grid (a single grid point) the node stays where it
        is.

        Args:
            node: The SimNode to move.
            dt_us: Time step in microseconds.
        """
        if self._current is None:
            i = self._snap_axis_index(node.position[0], 0)
            j = self._snap_axis_index(node.position[1], 1)
            self._current = (i, j)
            node.set_position(self._axis_value(i, 0), self._axis_value(j, 1), self.z)

        remaining_us: float = dt_us
        iterations = 0
        while remaining_us > 0:
            iterations += 1
            if iterations > _MAX_STEP_ITERATIONS:
                break
            if self._state == WaypointState.PAUSED:
                remaining_us = self._handle_paused(remaining_us)
                continue
            if self._target_cell is None:
                self._pick_next_cell()
                if self._target_cell is None:
                    return
            ti, tj = self._target_cell
            tx = self._axis_value(ti, 0)
            ty = self._axis_value(tj, 1)
            x, y, _ = node.position
            dx = tx - x
            dy = ty - y
            distance = math.sqrt(dx * dx + dy * dy)

            time_s = remaining_us / 1_000_000.0
            max_distance = self.speed_m_s * time_s

            if max_distance >= distance:
                node.set_position(tx, ty, self.z)
                time_used_us = distance / self.speed_m_s * 1_000_000
                if time_used_us >= 1.0:
                    time_used_us = float(int(time_used_us))
                # else: sub-microsecond leg. int() would truncate to 0,
                # consuming no time and stalling the loop; charging the true
                # float value keeps time-to-motion accounting exact.
                # Termination is guaranteed by the iteration cap, not strict
                # decrease (a tiny charge can be absorbed by float ULP).
                self._current = (ti, tj)
                self._target_cell = None
                remaining_us -= time_used_us
                self._maybe_start_pause(tx, ty)
            else:
                ratio = max_distance / distance
                node.set_position(x + dx * ratio, y + dy * ratio, self.z)
                return

    def _handle_paused(self, remaining_us: float) -> float:
        """Handle pause state, returns remaining time after state change."""
        if self._pause_remaining_us > 0:
            if remaining_us <= self._pause_remaining_us:
                self._pause_remaining_us -= remaining_us
                return 0
            remaining_us -= self._pause_remaining_us
            self._pause_remaining_us = 0

        self._state = WaypointState.MOVING
        return remaining_us

    def _maybe_start_pause(self, x: float, y: float) -> None:
        """Start a pause at an intersection if the pause coin fires.

        Draws the Bernoulli coin only when pause_probability is > 0.0,
        so the default configuration consumes no extra RNG draws and
        reproduces the no-pause trajectories exactly. A zero-length
        pause duration never enters the PAUSED state, which keeps every
        PAUSED visit carrying a strictly positive remaining duration.
        """
        if self.pause_probability <= 0.0:
            return
        if not self.detect_intersection(x, y):
            return
        if self._rng.random() >= self.pause_probability:
            return
        if self.pause_time_us <= 0:
            return
        self._state = WaypointState.PAUSED
        self._pause_remaining_us = self.pause_time_us

    def _grid_size(self, axis: int) -> int:
        """Return the maximum grid index along axis (0=x, 1=y)."""
        lo, hi = self.area_bounds[2 * axis], self.area_bounds[2 * axis + 1]
        return int(math.floor((hi - lo) / self.spacing_m))

    def _snap_axis_index(self, value: float, axis: int) -> int:
        """Return the nearest grid index along axis, clamped into bounds."""
        lo = self.area_bounds[2 * axis]
        k = round((value - lo) / self.spacing_m)
        return max(0, min(k, self._grid_size(axis)))

    def _axis_value(self, index: int, axis: int) -> float:
        """Return the coordinate of grid index along axis."""
        return self.area_bounds[2 * axis] + index * self.spacing_m

    def _pick_next_cell(self) -> None:
        """Choose a random adjacent grid cell as the next movement target.

        The reverse of the current direction is excluded from the draw
        when another in-bounds direction exists, so nodes never double
        back over the leg they just traversed. When the reverse is the
        only candidate (dead end) a forced U-turn is performed.
        """
        if self._current is None:
            return
        ci, cj = self._current
        candidates = []
        for direction in GridDirection:
            di, dj = direction.value
            ni, nj = ci + di, cj + dj
            if 0 <= ni <= self._grid_size(0) and 0 <= nj <= self._grid_size(1):
                candidates.append(direction)
        if not candidates:
            self._target_cell = None
            return
        if self._direction is not None:
            reverse = self._direction.reverse()
            forward = [d for d in candidates if d is not reverse]
            if forward:
                candidates = forward
        chosen = self._rng.choice(candidates)
        self._direction = chosen
        di, dj = chosen.value
        self._target_cell = (ci + di, cj + dj)


@dataclass
class MobilityManager:
    """Manages mobility patterns for multiple nodes.

    Convenience class for attaching patterns to nodes and stepping
    all patterns together.
    """

    _patterns: dict[str, MobilityPattern] = field(default_factory=dict)

    def attach(self, node_id: str, pattern: MobilityPattern) -> None:
        """Attach a mobility pattern to a node.

        Args:
            node_id: The node ID to attach the pattern to.
            pattern: The MobilityPattern instance.
        """
        self._patterns[node_id] = pattern

    def detach(self, node_id: str) -> MobilityPattern | None:
        """Detach and return the pattern from a node.

        Args:
            node_id: The node ID to detach from.

        Returns:
            The detached pattern, or None if not found.
        """
        return self._patterns.pop(node_id, None)

    def step_all(self, nodes: dict[str, SimNode], dt_us: int) -> None:
        """Step all attached patterns.

        Args:
            nodes: Dict mapping node_id to SimNode.
            dt_us: Time step in microseconds.
        """
        for node_id, pattern in self._patterns.items():
            node = nodes.get(node_id)
            if node is not None:
                pattern.step(node, dt_us)

    def get_pattern(self, node_id: str) -> MobilityPattern | None:
        """Get the pattern attached to a node.

        Args:
            node_id: The node ID.

        Returns:
            The pattern, or None if not found.
        """
        return self._patterns.get(node_id)

    def clear(self) -> None:
        """Remove all attached patterns."""
        self._patterns.clear()
