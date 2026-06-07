"""Tests for duty cycle tracking."""

import pytest

from lichen.sim.duty_cycle import DutyCycleTracker


class TestDutyCycleTracker:
    """Tests for DutyCycleTracker class."""

    def test_init_defaults(self) -> None:
        """Default configuration matches EU 868MHz regulations."""
        tracker = DutyCycleTracker()
        assert tracker.limit_percent == 1.0
        assert tracker.window_seconds == 3600

    def test_init_custom(self) -> None:
        """Custom limit and window are respected."""
        tracker = DutyCycleTracker(limit_percent=0.1, window_seconds=1800)
        assert tracker.limit_percent == 0.1
        assert tracker.window_seconds == 1800

    def test_empty_tracker_zero_usage(self) -> None:
        """Empty tracker reports zero usage."""
        tracker = DutyCycleTracker()
        assert tracker.get_usage(time_us=1_000_000) == 0.0

    def test_empty_tracker_can_transmit(self) -> None:
        """Empty tracker allows transmission."""
        tracker = DutyCycleTracker()
        assert tracker.can_transmit(airtime_us=1000, time_us=0)

    def test_record_and_get_usage(self) -> None:
        """Recording TX updates usage calculation."""
        # 1% of 3600s = 36s = 36_000_000us max airtime
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)

        # Record 3.6s TX (10% of limit)
        tracker.record_tx(airtime_us=3_600_000, time_us=0)

        usage = tracker.get_usage(time_us=0)
        assert usage == pytest.approx(0.1, rel=1e-6)

    def test_multiple_transmissions_accumulate(self) -> None:
        """Multiple transmissions sum correctly."""
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)

        # Record 5 transmissions of 3.6s each (50% of limit total)
        for i in range(5):
            tracker.record_tx(airtime_us=3_600_000, time_us=i * 1_000_000)

        usage = tracker.get_usage(time_us=5_000_000)
        assert usage == pytest.approx(0.5, rel=1e-6)

    def test_window_expiration(self) -> None:
        """Old transmissions are dropped after TX end falls outside window."""
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)
        window_us = 3600 * 1_000_000
        airtime_us = 3_600_000  # 3.6 seconds

        # Record TX at time 0
        tracker.record_tx(airtime_us=airtime_us, time_us=0)

        # TX ends at airtime_us. While end is in window, TX counts.
        # At time window_us, cutoff=0, TX ends at 3.6s > 0, so still counts.
        usage = tracker.get_usage(time_us=window_us)
        assert usage == pytest.approx(0.1, rel=1e-6)

        # After window_us + airtime_us, TX end falls outside window
        usage = tracker.get_usage(time_us=window_us + airtime_us)
        assert usage == 0.0

    def test_can_transmit_within_limit(self) -> None:
        """can_transmit returns True when within limit."""
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)

        # Use 50% of limit
        tracker.record_tx(airtime_us=18_000_000, time_us=0)

        # Adding 40% should be allowed (total 90%)
        assert tracker.can_transmit(airtime_us=14_400_000, time_us=0)

    def test_can_transmit_at_exact_limit(self) -> None:
        """can_transmit returns True at exactly the limit."""
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)

        # Use 50% of limit
        tracker.record_tx(airtime_us=18_000_000, time_us=0)

        # Adding exactly 50% should be allowed (total 100%)
        assert tracker.can_transmit(airtime_us=18_000_000, time_us=0)

    def test_can_transmit_exceeds_limit(self) -> None:
        """can_transmit returns False when would exceed limit."""
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)

        # Use 50% of limit
        tracker.record_tx(airtime_us=18_000_000, time_us=0)

        # Adding 51% should be rejected (total 101%)
        assert not tracker.can_transmit(airtime_us=18_360_000, time_us=0)

    def test_can_transmit_after_expiration(self) -> None:
        """can_transmit allowed after old TX fully expires."""
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)
        window_us = 3600 * 1_000_000
        airtime_us = 36_000_000  # 36 seconds (100% of 1% duty cycle)

        # Max out the limit
        tracker.record_tx(airtime_us=airtime_us, time_us=0)

        # Should be blocked immediately
        assert not tracker.can_transmit(airtime_us=1, time_us=0)

        # TX ends at 36s. After window_us + airtime_us, it's fully expired
        assert tracker.can_transmit(airtime_us=36_000_000, time_us=window_us + airtime_us)

    def test_usage_can_exceed_one(self) -> None:
        """Usage can exceed 1.0 if limit was violated."""
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)

        # Record 2x the limit (simulating forced TX)
        tracker.record_tx(airtime_us=72_000_000, time_us=0)

        usage = tracker.get_usage(time_us=0)
        assert usage == pytest.approx(2.0, rel=1e-6)

    def test_custom_limit_percent(self) -> None:
        """Custom limit_percent affects calculations correctly."""
        # 10% duty cycle
        tracker = DutyCycleTracker(limit_percent=10.0, window_seconds=3600)

        # 10% of 3600s = 360s = 360_000_000us max
        # Record 36s (10% of limit)
        tracker.record_tx(airtime_us=36_000_000, time_us=0)

        usage = tracker.get_usage(time_us=0)
        assert usage == pytest.approx(0.1, rel=1e-6)

    def test_shorter_window(self) -> None:
        """Shorter window affects expiration correctly."""
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=60)
        window_us = 60 * 1_000_000

        airtime_us = 600_000  # 0.6 seconds
        tracker.record_tx(airtime_us=airtime_us, time_us=0)

        # Still in window (TX ends at 0.6s, which is > cutoff at window_us)
        assert tracker.get_usage(time_us=window_us) > 0

        # Fully expired after window_us + airtime_us
        assert tracker.get_usage(time_us=window_us + airtime_us) == 0.0

    def test_prune_on_record(self) -> None:
        """Recording prunes entries whose end time falls outside window."""
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)
        window_us = 3600 * 1_000_000
        airtime_us = 1000

        # Record at time 0
        tracker.record_tx(airtime_us=airtime_us, time_us=0)
        assert len(tracker._transmissions) == 1

        # Record after window + airtime - old entry is now fully outside window
        tracker.record_tx(airtime_us=airtime_us, time_us=window_us + airtime_us)
        assert len(tracker._transmissions) == 1
        assert tracker._transmissions[0][0] == window_us + airtime_us

    def test_boundary_spanning_tx_prorated(self) -> None:
        """TX spanning window boundary is prorated correctly.

        A 10-second TX starting 1 second before the window cutoff should
        contribute 9 seconds to the window (not 0 or 10).
        """
        tracker = DutyCycleTracker(limit_percent=1.0, window_seconds=3600)
        window_us = 3600 * 1_000_000

        # TX of 10 seconds starting at time 0
        tx_duration = 10_000_000  # 10 seconds
        tracker.record_tx(airtime_us=tx_duration, time_us=0)

        # At time window_us + 1s, cutoff = 1s
        # TX from 0-10s, portion in window [1s, 3601s] is 9s
        query_time = window_us + 1_000_000
        usage = tracker.get_usage(time_us=query_time)

        # 9 seconds out of 36 seconds allowed (1% of 3600s)
        expected_usage = 9_000_000 / (window_us * 0.01)
        assert usage == pytest.approx(expected_usage, rel=1e-6)
