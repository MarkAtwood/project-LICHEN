"""Duty cycle tracking for LoRa transmissions.

EU 868MHz regulations require 1% duty cycle (36 seconds per hour).
This module provides a sliding window tracker for compliance monitoring.
"""

from __future__ import annotations


class DutyCycleTracker:
    """Track transmit duty cycle over a sliding time window.

    Maintains a history of transmissions and calculates usage as a
    fraction of the configured limit. Used by the simulator to enforce
    regulatory duty cycle constraints.

    Attributes:
        limit_percent: Maximum allowed duty cycle as percentage (default 1.0%).
        window_seconds: Sliding window duration in seconds (default 3600).
    """

    def __init__(
        self,
        limit_percent: float = 1.0,
        window_seconds: int = 3600,
    ) -> None:
        """Initialize duty cycle tracker.

        Args:
            limit_percent: Maximum duty cycle as percentage (e.g., 1.0 for 1%).
            window_seconds: Duration of sliding window in seconds.
        """
        self.limit_percent = limit_percent
        self.window_seconds = window_seconds
        self._window_us = window_seconds * 1_000_000
        self._limit_ratio = limit_percent / 100.0
        self._transmissions: list[tuple[int, int]] = []

    def _prune(self, time_us: int) -> None:
        """Remove transmissions that ended before the window.

        Args:
            time_us: Current time in microseconds.
        """
        cutoff = time_us - self._window_us
        # Keep TXs where end time (t + d) > cutoff
        self._transmissions = [
            (t, d) for t, d in self._transmissions if t + d > cutoff
        ]

    def _airtime_in_window(self, time_us: int) -> int:
        """Calculate total airtime within the current window.

        For transmissions spanning the window boundary, only counts
        the portion within the window.

        Args:
            time_us: Current time in microseconds.

        Returns:
            Total airtime in microseconds within the window.
        """
        cutoff = time_us - self._window_us
        total = 0
        for t, d in self._transmissions:
            if t >= cutoff:
                # TX entirely within window
                total += d
            else:
                # TX spans boundary - only count portion after cutoff
                total += (t + d) - cutoff
        return total

    def record_tx(self, airtime_us: int, time_us: int) -> None:
        """Record a transmission.

        Args:
            airtime_us: Duration of transmission in microseconds.
            time_us: Timestamp when transmission started in microseconds.
        """
        self._prune(time_us)
        self._transmissions.append((time_us, airtime_us))

    def get_usage(self, time_us: int) -> float:
        """Get current duty cycle usage as a ratio.

        Args:
            time_us: Current time in microseconds.

        Returns:
            Usage as a ratio from 0.0 to 1.0, where 1.0 means the limit
            has been reached. Can exceed 1.0 if over limit.
        """
        self._prune(time_us)
        if not self._transmissions:
            return 0.0

        total_airtime = self._airtime_in_window(time_us)
        max_airtime = self._window_us * self._limit_ratio
        return total_airtime / max_airtime

    def can_transmit(self, airtime_us: int, time_us: int) -> bool:
        """Check if a transmission would exceed the duty cycle limit.

        Args:
            airtime_us: Duration of proposed transmission in microseconds.
            time_us: Current time in microseconds.

        Returns:
            True if transmission would stay within duty cycle limit.
        """
        self._prune(time_us)
        total_airtime = self._airtime_in_window(time_us)
        max_airtime = self._window_us * self._limit_ratio
        return (total_airtime + airtime_us) <= max_airtime
