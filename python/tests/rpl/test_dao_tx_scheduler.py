# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""DAO TX scheduler tests: spec 09 §14.2 R-09-017..019 wired into DaoManager."""

from __future__ import annotations

import random
from types import SimpleNamespace

import pytest

from lichen.rpl.dao import DaoManager
from lichen.rpl.dao_tx_scheduler import DaoTxPhase, DaoTxScheduler
from lichen.timing.dao import (
    DAO_INITIAL_DELAY_MAX_MS,
    DAO_INITIAL_DELAY_MIN_MS,
    DAO_REFRESH_S,
    DAO_RETRY_DELAYS_MS,
)


def stub_rng(value_ms: int) -> SimpleNamespace:
    """Randint stub pinning the initial delay draw to ``value_ms``."""
    return SimpleNamespace(randint=lambda low, high: value_ms)


def test_initial_delay_uses_oracle_window() -> None:
    low = DaoTxScheduler(rng=stub_rng(DAO_INITIAL_DELAY_MIN_MS))
    assert low.on_join(1000.0) == 1000.0 + DAO_INITIAL_DELAY_MIN_MS / 1000.0
    assert low.phase is DaoTxPhase.INITIAL_PENDING

    high = DaoTxScheduler(rng=stub_rng(DAO_INITIAL_DELAY_MAX_MS))
    assert high.on_join(1000.0) == 1000.0 + DAO_INITIAL_DELAY_MAX_MS / 1000.0


def test_initial_delay_with_seeded_rng_stays_in_window() -> None:
    scheduler = DaoTxScheduler(rng=random.Random(20260831))
    deadline = scheduler.on_join(0.0)
    assert 0.0 <= deadline - 0.0 <= DAO_INITIAL_DELAY_MAX_MS / 1000.0


def test_retry_sequence_matches_oracle_then_exhausts() -> None:
    scheduler = DaoTxScheduler(rng=stub_rng(0))
    scheduler.on_join(0.0)
    now = DAO_INITIAL_DELAY_MAX_MS / 1000.0
    assert scheduler.on_due(now)
    for delay in DAO_RETRY_DELAYS_MS:
        expected_deadline = now + delay / 1000.0
        assert scheduler.on_sent(now) == expected_deadline
        assert scheduler.phase is DaoTxPhase.RETRY_PENDING
        assert scheduler.deadline == expected_deadline
        now = expected_deadline
    # Initial send plus every retry delay is used up: fourth send exhausts.
    assert scheduler.on_sent(now) is None
    assert scheduler.phase is DaoTxPhase.EXHAUSTED
    assert scheduler.deadline is None


def test_sent_after_exhaustion_fails_closed() -> None:
    scheduler = DaoTxScheduler(rng=stub_rng(0))
    scheduler.on_join(0.0)
    for _ in range(len(DAO_RETRY_DELAYS_MS) + 1):
        scheduler.on_sent(float(len(DAO_RETRY_DELAYS_MS)))
    assert scheduler.phase is DaoTxPhase.EXHAUSTED
    with pytest.raises(RuntimeError, match="exhausted"):
        scheduler.on_sent(9999.0)


def test_ack_schedules_refresh_and_resets_backoff() -> None:
    scheduler = DaoTxScheduler(rng=stub_rng(0))
    scheduler.on_join(0.0)
    assert scheduler.on_sent(0.0) == DAO_RETRY_DELAYS_MS[0] / 1000.0
    refresh_deadline = scheduler.on_ack(10.0)
    assert refresh_deadline == 10.0 + DAO_REFRESH_S
    assert scheduler.phase is DaoTxPhase.REFRESH_PENDING
    # A refresh send that goes unacknowledged retries from the first delay.
    assert scheduler.on_sent(refresh_deadline) == refresh_deadline + DAO_RETRY_DELAYS_MS[0] / 1000.0
    assert scheduler.phase is DaoTxPhase.RETRY_PENDING


def test_ack_recovers_exhausted_scheduler() -> None:
    scheduler = DaoTxScheduler(rng=stub_rng(0))
    scheduler.on_join(0.0)
    for tick in range(len(DAO_RETRY_DELAYS_MS) + 1):
        scheduler.on_sent(float(tick))
    assert scheduler.phase is DaoTxPhase.EXHAUSTED
    assert scheduler.on_ack(500.0) == 500.0 + DAO_REFRESH_S
    assert scheduler.phase is DaoTxPhase.REFRESH_PENDING


def test_ack_and_sent_invalid_in_idle() -> None:
    scheduler = DaoTxScheduler(rng=stub_rng(0))
    with pytest.raises(RuntimeError, match="idle"):
        scheduler.on_ack(0.0)
    with pytest.raises(RuntimeError, match="idle"):
        scheduler.on_sent(0.0)
    assert scheduler.phase is DaoTxPhase.IDLE


def test_on_due_boundary_is_inclusive() -> None:
    scheduler = DaoTxScheduler(rng=stub_rng(0))
    scheduler.on_join(0.0)
    deadline = scheduler.deadline
    assert deadline is not None
    assert not scheduler.on_due(deadline - 0.001)
    assert scheduler.on_due(deadline)


def test_clock_injection_and_missing_time_fails_closed() -> None:
    ticks = iter([42.0])
    scheduler = DaoTxScheduler(rng=stub_rng(5), clock=lambda: next(ticks))
    assert scheduler.on_join() == 42.005
    with pytest.raises(ValueError, match="now_seconds"):
        DaoTxScheduler().on_join()


def test_now_seconds_type_validation() -> None:
    scheduler = DaoTxScheduler(rng=stub_rng(0))
    for bad in (True, "1", None.__class__):
        if bad is None:
            continue
        with pytest.raises(TypeError):
            scheduler.on_join(bad)  # type: ignore[arg-type]


def test_dao_manager_delegates_tx_scheduling() -> None:
    clock = {"now": 100.0}
    manager = DaoManager(
        node_address="fd00::1",
        clock=lambda: clock["now"],
    )
    deadline = manager.on_dao_tx_join()
    assert 100.0 <= deadline <= 100.0 + DAO_INITIAL_DELAY_MAX_MS / 1000.0
    assert manager.dao_tx_phase is DaoTxPhase.INITIAL_PENDING

    clock["now"] = deadline
    assert manager.dao_tx_due()

    retry = manager.on_dao_tx_sent()
    assert retry == deadline + DAO_RETRY_DELAYS_MS[0] / 1000.0
    assert manager.dao_tx_phase is DaoTxPhase.RETRY_PENDING

    refresh = manager.on_dao_tx_ack(retry)
    assert refresh == retry + DAO_REFRESH_S
    assert manager.dao_tx_deadline == refresh
    assert manager.dao_tx_phase is DaoTxPhase.REFRESH_PENDING
    assert not manager.dao_tx_due(retry)
    assert manager.dao_tx_due(refresh)
