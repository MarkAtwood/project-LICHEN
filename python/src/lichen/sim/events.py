"""Event queue system for the LICHEN simulator.

Provides a priority queue of simulation events ordered by time, with
tie-breaking by insertion order to ensure deterministic behavior.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterator
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Event:
    """Base class for simulation events.

    All times are in microseconds (int) for precision without floating-point issues.
    """

    time_us: int


@dataclass(frozen=True)
class TxStartEvent(Event):
    """A node begins transmitting a packet."""

    node_id: str
    transmission_id: str


@dataclass(frozen=True)
class TxEndEvent(Event):
    """A node finishes transmitting a packet."""

    node_id: str
    transmission_id: str


@dataclass(frozen=True)
class RxTimeoutEvent(Event):
    """A node's receive timeout expires."""

    node_id: str


@dataclass(order=True)
class _PrioritizedEvent:
    """Wrapper for heap ordering: (time_us, insertion_order, event)."""

    time_us: int
    insertion_order: int
    event: Event = field(compare=False)


class EventQueue:
    """Priority queue of simulation events ordered by time.

    Events are sorted by time_us, with ties broken by insertion order
    (FIFO for events at the same time). Uses a heap for O(log n) push/pop.
    """

    def __init__(self) -> None:
        self._heap: list[_PrioritizedEvent] = []
        self._counter: int = 0

    def push(self, event: Event) -> None:
        """Add an event to the queue."""
        entry = _PrioritizedEvent(
            time_us=event.time_us,
            insertion_order=self._counter,
            event=event,
        )
        self._counter += 1
        heapq.heappush(self._heap, entry)

    def pop(self) -> Event:
        """Remove and return the earliest event.

        Raises:
            IndexError: If the queue is empty.
        """
        if not self._heap:
            raise IndexError("pop from empty EventQueue")
        entry = heapq.heappop(self._heap)
        return entry.event

    def peek(self) -> Event | None:
        """Return the earliest event without removing it, or None if empty."""
        if not self._heap:
            return None
        return self._heap[0].event

    def is_empty(self) -> bool:
        """Return True if the queue has no events."""
        return len(self._heap) == 0

    def __len__(self) -> int:
        """Return the number of events in the queue."""
        return len(self._heap)

    def __iter__(self) -> Iterator[Event]:
        """Iterate over events in time order (destructive)."""
        while self._heap:
            yield self.pop()

    def __repr__(self) -> str:
        return f"EventQueue(len={len(self)})"

    def remove_events_for_node(self, node_id: str) -> int:
        """Remove all events associated with a specific node.

        This is useful when a node is removed from the simulation to prevent
        orphan events from accumulating.

        Args:
            node_id: ID of the node whose events should be removed.

        Returns:
            Number of events removed.
        """
        original_len = len(self._heap)
        self._heap = [
            entry for entry in self._heap
            if not (hasattr(entry.event, "node_id") and entry.event.node_id == node_id)
        ]
        heapq.heapify(self._heap)
        return original_len - len(self._heap)
