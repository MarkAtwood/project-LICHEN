"""Tests for the LICHEN simulator event queue system."""

import pytest

from lichen.sim.events import (
    Event,
    EventQueue,
    RxTimeoutEvent,
    TxEndEvent,
    TxStartEvent,
)


class TestEventDataclasses:
    """Test event dataclass definitions."""

    def test_event_has_time_us(self) -> None:
        """Base Event stores time in microseconds."""
        event = Event(time_us=1000)
        assert event.time_us == 1000

    def test_tx_start_event_fields(self) -> None:
        """TxStartEvent has time, node_id, and transmission_id."""
        event = TxStartEvent(time_us=100, node_id="node1", transmission_id="tx001")
        assert event.time_us == 100
        assert event.node_id == "node1"
        assert event.transmission_id == "tx001"

    def test_tx_end_event_fields(self) -> None:
        """TxEndEvent has time, node_id, and transmission_id."""
        event = TxEndEvent(time_us=200, node_id="node2", transmission_id="tx002")
        assert event.time_us == 200
        assert event.node_id == "node2"
        assert event.transmission_id == "tx002"

    def test_rx_timeout_event_fields(self) -> None:
        """RxTimeoutEvent has time and node_id."""
        event = RxTimeoutEvent(time_us=300, node_id="node3")
        assert event.time_us == 300
        assert event.node_id == "node3"

    def test_events_are_frozen(self) -> None:
        """Events are immutable (frozen dataclasses)."""
        event = TxStartEvent(time_us=100, node_id="n1", transmission_id="tx1")
        with pytest.raises(AttributeError):
            event.time_us = 200  # type: ignore[misc]


class TestEventQueueBasics:
    """Test basic EventQueue operations."""

    def test_new_queue_is_empty(self) -> None:
        """A new queue has no events."""
        queue = EventQueue()
        assert queue.is_empty()
        assert len(queue) == 0

    def test_push_makes_queue_nonempty(self) -> None:
        """Pushing an event makes the queue non-empty."""
        queue = EventQueue()
        queue.push(Event(time_us=100))
        assert not queue.is_empty()
        assert len(queue) == 1

    def test_pop_returns_pushed_event(self) -> None:
        """Pop returns the event that was pushed."""
        queue = EventQueue()
        event = TxStartEvent(time_us=100, node_id="n1", transmission_id="tx1")
        queue.push(event)
        popped = queue.pop()
        assert popped == event

    def test_pop_removes_event(self) -> None:
        """Pop removes the event from the queue."""
        queue = EventQueue()
        queue.push(Event(time_us=100))
        queue.pop()
        assert queue.is_empty()
        assert len(queue) == 0

    def test_pop_empty_raises_index_error(self) -> None:
        """Pop from empty queue raises IndexError."""
        queue = EventQueue()
        with pytest.raises(IndexError, match="pop from empty EventQueue"):
            queue.pop()

    def test_peek_returns_event_without_removing(self) -> None:
        """Peek returns earliest event but leaves it in queue."""
        queue = EventQueue()
        event = Event(time_us=100)
        queue.push(event)
        peeked = queue.peek()
        assert peeked == event
        assert len(queue) == 1  # Still there

    def test_peek_empty_returns_none(self) -> None:
        """Peek on empty queue returns None."""
        queue = EventQueue()
        assert queue.peek() is None


class TestEventQueueOrdering:
    """Test EventQueue ordering by time."""

    def test_pop_returns_earliest_event(self) -> None:
        """Events are popped in time order (earliest first)."""
        queue = EventQueue()
        queue.push(Event(time_us=300))
        queue.push(Event(time_us=100))
        queue.push(Event(time_us=200))

        assert queue.pop().time_us == 100
        assert queue.pop().time_us == 200
        assert queue.pop().time_us == 300

    def test_mixed_event_types_ordered_by_time(self) -> None:
        """Different event types are ordered by time regardless of type."""
        queue = EventQueue()
        tx_end = TxEndEvent(time_us=150, node_id="n1", transmission_id="tx1")
        tx_start = TxStartEvent(time_us=100, node_id="n1", transmission_id="tx1")
        rx_timeout = RxTimeoutEvent(time_us=200, node_id="n2")

        queue.push(tx_end)
        queue.push(rx_timeout)
        queue.push(tx_start)

        assert queue.pop() == tx_start  # 100
        assert queue.pop() == tx_end  # 150
        assert queue.pop() == rx_timeout  # 200


class TestEventQueueTieBreaking:
    """Test tie-breaking by insertion order."""

    def test_same_time_fifo_order(self) -> None:
        """Events at the same time are returned in insertion order (FIFO)."""
        queue = EventQueue()
        event1 = TxStartEvent(time_us=100, node_id="n1", transmission_id="tx1")
        event2 = TxStartEvent(time_us=100, node_id="n2", transmission_id="tx2")
        event3 = TxStartEvent(time_us=100, node_id="n3", transmission_id="tx3")

        queue.push(event1)
        queue.push(event2)
        queue.push(event3)

        assert queue.pop() == event1
        assert queue.pop() == event2
        assert queue.pop() == event3

    def test_interleaved_times_with_ties(self) -> None:
        """Correct ordering with mix of different times and ties."""
        queue = EventQueue()
        # Push in scrambled order
        e1 = Event(time_us=100)  # First at t=100
        e2 = Event(time_us=200)  # First at t=200
        e3 = Event(time_us=100)  # Second at t=100
        e4 = Event(time_us=200)  # Second at t=200
        e5 = Event(time_us=150)  # Only at t=150

        queue.push(e1)
        queue.push(e2)
        queue.push(e3)
        queue.push(e4)
        queue.push(e5)

        assert queue.pop() == e1  # t=100, first
        assert queue.pop() == e3  # t=100, second
        assert queue.pop() == e5  # t=150
        assert queue.pop() == e2  # t=200, first
        assert queue.pop() == e4  # t=200, second

    def test_peek_respects_ordering(self) -> None:
        """Peek returns the same event that pop would return."""
        queue = EventQueue()
        event_later = Event(time_us=200)
        event_earlier = Event(time_us=100)

        queue.push(event_later)
        queue.push(event_earlier)

        assert queue.peek() == event_earlier
        assert queue.pop() == event_earlier
        assert queue.peek() == event_later


class TestEventQueueIteration:
    """Test EventQueue iteration."""

    def test_iterate_pops_all_events(self) -> None:
        """Iterating yields events in order and empties the queue."""
        queue = EventQueue()
        queue.push(Event(time_us=300))
        queue.push(Event(time_us=100))
        queue.push(Event(time_us=200))

        times = [e.time_us for e in queue]

        assert times == [100, 200, 300]
        assert queue.is_empty()

    def test_repr(self) -> None:
        """Queue has a useful repr."""
        queue = EventQueue()
        assert repr(queue) == "EventQueue(len=0)"
        queue.push(Event(time_us=100))
        queue.push(Event(time_us=200))
        assert repr(queue) == "EventQueue(len=2)"

    def test_remove_events_for_node(self) -> None:
        """remove_events_for_node removes only events for that node."""
        queue = EventQueue()
        queue.push(TxEndEvent(time_us=100, node_id="node1", transmission_id="tx1"))
        queue.push(RxTimeoutEvent(time_us=200, node_id="node2"))
        queue.push(TxEndEvent(time_us=300, node_id="node1", transmission_id="tx2"))
        queue.push(RxTimeoutEvent(time_us=400, node_id="node3"))

        assert len(queue) == 4

        removed = queue.remove_events_for_node("node1")

        assert removed == 2
        assert len(queue) == 2
        # Remaining events should be for node2 and node3
        e1 = queue.pop()
        e2 = queue.pop()
        assert e1.node_id == "node2"  # type: ignore[union-attr]
        assert e2.node_id == "node3"  # type: ignore[union-attr]

    def test_remove_events_for_node_preserves_order(self) -> None:
        """After removal, remaining events maintain time order."""
        queue = EventQueue()
        queue.push(TxEndEvent(time_us=100, node_id="keep", transmission_id="tx1"))
        queue.push(TxEndEvent(time_us=200, node_id="remove", transmission_id="tx2"))
        queue.push(TxEndEvent(time_us=300, node_id="keep", transmission_id="tx3"))
        queue.push(TxEndEvent(time_us=400, node_id="remove", transmission_id="tx4"))
        queue.push(TxEndEvent(time_us=500, node_id="keep", transmission_id="tx5"))

        queue.remove_events_for_node("remove")

        times = [queue.pop().time_us for _ in range(3)]
        assert times == [100, 300, 500]

    def test_remove_events_for_nonexistent_node(self) -> None:
        """Removing events for nonexistent node returns 0."""
        queue = EventQueue()
        queue.push(TxEndEvent(time_us=100, node_id="node1", transmission_id="tx1"))

        removed = queue.remove_events_for_node("nonexistent")

        assert removed == 0
        assert len(queue) == 1
