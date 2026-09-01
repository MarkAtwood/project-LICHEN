# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""DAO origination TX scheduling (spec 09-packets-timing.md §14.2).

Consumes the cross-language timing oracle in :mod:`lichen.timing.dao`
(R-09-017..019) so a node runtime can drive DAO emission: one random
initial DAO 0-2 s after joining, exponential retry backoff 4/8/16 s
while unacknowledged, and periodic refresh re-emission every 15 minutes
(half the 30-minute soft-state lifetime). All deadlines derive from the
shared constants; nothing here redefines them.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from lichen.timing.dao import (
    DAO_REFRESH_S,
    dao_initial_delay,
    dao_retry_delay,
    dao_retry_exhausted,
)

__all__ = ["DaoTxPhase", "DaoTxScheduler"]


class DaoTxPhase(Enum):
    """Origination side of the DAO exchange for one DODAG membership."""

    IDLE = "idle"  # not joined; nothing scheduled
    INITIAL_PENDING = "initial_pending"  # joined; waiting out the 0-2 s delay
    RETRY_PENDING = "retry_pending"  # sent unacked; backoff until next retry
    REFRESH_PENDING = "refresh_pending"  # last exchange acked; refresh due later
    EXHAUSTED = "exhausted"  # retries exhausted; parent unresponsive


@dataclass
class DaoTxScheduler:
    """Deterministic DAO TX state machine driven by an injected clock.

    The runtime polls :attr:`deadline` / :attr:`phase` (or the DaoManager
    delegating methods) and reports sends and ACKs; every deadline is
    computed from the :mod:`lichen.timing.dao` oracle.
    """

    clock: Callable[[], float] | None = None
    rng: random.Random | None = None
    phase: DaoTxPhase = field(default=DaoTxPhase.IDLE, init=False)
    deadline: float | None = field(default=None, init=False, repr=False)
    _unacked_sends: int = field(default=0, init=False, repr=False)

    def _now(self, now_seconds: float | None) -> float:
        if now_seconds is not None:
            if type(now_seconds) not in (int, float) or isinstance(now_seconds, bool):
                raise TypeError("now_seconds must be a number")
            return float(now_seconds)
        if self.clock is None:
            raise ValueError("now_seconds required when no clock is configured")
        return self.clock()

    def _set(self, phase: DaoTxPhase, deadline: float | None) -> None:
        self.phase = phase
        self.deadline = deadline

    def on_join(self, now_seconds: float | None = None) -> float:
        """Enter a DODAG: schedule the initial DAO 0-2 s out (R-09-017)."""
        now = self._now(now_seconds)
        delay_ms = dao_initial_delay(self.rng)
        self._unacked_sends = 0
        self._set(DaoTxPhase.INITIAL_PENDING, now + delay_ms / 1000.0)
        assert self.deadline is not None
        return self.deadline

    def on_sent(self, now_seconds: float | None = None) -> float | None:
        """Record a DAO transmission; schedule retry or exhaust (R-09-018)."""
        now = self._now(now_seconds)
        if self.phase in (DaoTxPhase.IDLE, DaoTxPhase.EXHAUSTED):
            raise RuntimeError(f"on_sent is invalid in phase {self.phase.value}")
        self._unacked_sends += 1
        if dao_retry_exhausted(self._unacked_sends - 1):
            # Retries done == unacked sends - 1; exhausted once the initial
            # send plus every retry delay in DAO_RETRY_DELAYS_MS is used up.
            self._set(DaoTxPhase.EXHAUSTED, None)
            return None
        delay_s = dao_retry_delay(self._unacked_sends - 1)
        assert delay_s is not None
        self._set(DaoTxPhase.RETRY_PENDING, now + delay_s / 1000.0)
        assert self.deadline is not None
        return self.deadline

    def on_ack(self, now_seconds: float | None = None) -> float:
        """DAO-ACK received: reset retries, schedule refresh (R-09-019)."""
        if self.phase is DaoTxPhase.IDLE:
            raise RuntimeError("on_ack is invalid in phase idle (no DAO sent)")
        now = self._now(now_seconds)
        self._unacked_sends = 0
        self._set(DaoTxPhase.REFRESH_PENDING, now + DAO_REFRESH_S)
        assert self.deadline is not None
        return self.deadline

    def on_due(self, now_seconds: float | None = None) -> bool:
        """True once the pending deadline has passed (exclusive of not-yet)."""
        now = self._now(now_seconds)
        return self.deadline is not None and now >= self.deadline
