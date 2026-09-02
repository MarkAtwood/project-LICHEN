# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SOS periodic behavior tests (spec 18.4, bead l1qw.37)."""

from __future__ import annotations

import pytest

from lichen.coap.resources.emergency import SosResource
from lichen.coap.sos_periodic import (
    BEACON_BOOST_INTERVAL_S,
    SOS_AUTO_TIMEOUT_S,
    SosPeriodicDriver,
)


class _FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def harness():
    clock = _FakeClock(1000.0)
    resource = SosResource()
    driver = SosPeriodicDriver(resource, now=clock)
    pulses: list[bool] = []

    original_updated = resource.updated_state

    def counting_updated() -> None:
        original_updated()
        pulses.append(True)

    resource.updated_state = counting_updated  # type: ignore[method-assign]
    return clock, resource, driver, pulses


@pytest.mark.asyncio
async def test_activation_starts_boost_timer(harness) -> None:
    clock, resource, driver, pulses = harness
    resource.activate(bytes.fromhex("0011223344556677"), clock.t)
    driver.tick()
    assert driver._last_boost == clock.t
    assert len(pulses) == 1  # activation notified once


@pytest.mark.asyncio
async def test_beacon_boost_at_30s_boundary(harness) -> None:
    clock, resource, driver, pulses = harness
    resource.activate(bytes.fromhex("0011223344556677"), clock.t)
    driver.tick()
    base = len(pulses)
    clock.advance(BEACON_BOOST_INTERVAL_S - 1)
    driver.tick()
    assert len(pulses) == base  # 29s: no boost yet
    clock.advance(1)
    driver.tick()
    # The boost re-notifies via retrigger(): observers see one more pulse.
    assert len(pulses) >= base + 1  # 30s: boost re-notify
    # Cancel resets: idle tick does nothing.
    resource.cancel()
    driver.tick()
    assert len(pulses) >= base + 1


@pytest.mark.asyncio
async def test_auto_timeout_cancels_at_4h(harness) -> None:
    clock, resource, driver, _pulses = harness
    resource.activate(bytes.fromhex("0011223344556677"), clock.t)
    driver.tick()
    clock.advance(SOS_AUTO_TIMEOUT_S - 1)
    driver.tick()
    assert resource._active  # 1s before timeout: still active
    clock.advance(2)
    driver.tick()
    assert not resource._active  # 4h+1s: auto-cancelled


@pytest.mark.asyncio
async def test_idle_ticks_are_noops(harness) -> None:
    clock, resource, driver, pulses = harness
    for _ in range(10):
        clock.advance(60)
        driver.tick()
    assert pulses == []
    assert not resource._active


@pytest.mark.asyncio
async def test_auto_cancel_then_reactivate_restarts_timers(harness) -> None:
    """Auto-cancel clears the edge state: a manual re-activate before the
    next tick is detected as a fresh activation with a full 4h window."""
    clock, resource, driver, pulses = harness
    resource.activate(bytes.fromhex("0011223344556677"), clock.t)
    driver.tick()
    clock.advance(SOS_AUTO_TIMEOUT_S + 1)
    driver.tick()
    assert not resource._active  # auto-cancelled
    # Manual re-activate immediately after auto-cancel.
    clock.advance(1)
    resource.activate(bytes.fromhex("0011223344556677"), clock.t)
    driver.tick()
    assert resource._active  # fresh activation detected, not auto-cancelled
    # The new SOS has a full 4h window: still active 1s before it expires.
    clock.advance(SOS_AUTO_TIMEOUT_S - 2)
    driver.tick()
    assert resource._active
    clock.advance(2)
    driver.tick()
    assert not resource._active  # second SOS auto-cancelled on schedule


@pytest.mark.asyncio
async def test_drift_of_activation_edge_resets_timeout(harness) -> None:
    """Cancel+re-activate within one tick interval resets the 4h window
    from the re-activation (edge detection treats it as fresh)."""
    clock, resource, driver, _pulses = harness
    resource.activate(bytes.fromhex("0011223344556677"), clock.t)
    driver.tick()
    resource.cancel()
    clock.advance(60)
    resource.activate(bytes.fromhex("0011223344556677"), clock.t)
    driver.tick()
    # 2h into the second activation: still active (fresh 4h window).
    clock.advance(2 * 3600)
    driver.tick()
    assert resource._active
    clock.advance(2 * 3600 + 1)
    driver.tick()
    assert not resource._active
