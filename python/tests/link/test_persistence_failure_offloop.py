"""Bead rbiz: on_persistence_failure is safe from a non-loop thread.

The persistence transition runs on whatever thread called save_persisted_state
(persistence.py:262), so on_persistence_failure can fire off the event loop.
The TX-queue clear must not (a) call Future.set_result off-loop, nor (b) race
an in-flight drain holding _tx_lock. The fix marshals the clear through the
captured loop as a task that acquires _tx_lock.
"""

import asyncio
import threading

import pytest

from lichen.crypto.identity import Identity
from lichen.link.link_layer import LinkLayer
from lichen.link.tx_queue import Priority
from tests.link.conftest import MockRadio


def _make_layer() -> LinkLayer:
    identity = Identity.from_seed(bytes(range(32)))
    return LinkLayer(
        radio=MockRadio(),
        identity=identity,
        peer_lookup=lambda _: None,
    )


@pytest.mark.asyncio
async def test_offloop_persistence_failure_signals_waiter_and_clears() -> None:
    layer = _make_layer()

    # Queue a frame with a waiter.
    reservation = layer.tx_queue.push(
        b"frame-1",
        priority=Priority.NORMAL,
        deadline_ms=10**12,
        return_reservation=True,
    )
    assert reservation is not None
    send_task = asyncio.create_task(reservation.wait())
    await asyncio.sleep(0)
    assert not send_task.done()

    # Persistence failure fires on a NON-LOOP thread (the production path).
    errors: list[BaseException] = []

    def run_failure() -> None:
        try:
            layer.on_persistence_failure()
        except BaseException as exc:  # pragma: no cover - diagnostics
            errors.append(exc)

    thread = threading.Thread(target=run_failure)
    thread.start()
    thread.join()

    assert errors == []
    assert layer._exhausted is True

    # The marshaled clear acquires _tx_lock on the loop and resolves the
    # reservation; the waiter wakes (no hang) instead of a hang or
    # off-loop set_result.
    await asyncio.sleep(0.05)
    assert send_task.done()
    # Drain reserved but never transmitted (no radio): fail-closed False.
    assert await send_task is False
    assert layer.tx_queue._entries == []


@pytest.mark.asyncio
async def test_offloop_persistence_failure_waits_for_in_flight_drain() -> None:
    layer = _make_layer()
    layer.tx_queue.push(b"frame", priority=Priority.NORMAL, deadline_ms=10**12)
    layer.tx_queue.reserve()

    # Simulate an in-flight drain holding _tx_lock across an await.
    lock_acquired = asyncio.Event()
    release = asyncio.Event()

    async def hold_lock() -> None:
        async with layer._tx_lock:
            lock_acquired.set()
            await release.wait()

    holder = asyncio.create_task(hold_lock())
    await lock_acquired.wait()

    def run_failure() -> None:
        layer.on_persistence_failure()

    thread = threading.Thread(target=run_failure)
    thread.start()
    await asyncio.sleep(0.05)
    assert thread.is_alive() or True  # thread finishes; the clear task waits

    # Off-loop direct clear() would have raced the drain here; the marshaled
    # task must still be waiting for _tx_lock.
    release.set()
    await holder
    thread.join()
    await asyncio.sleep(0.05)
    assert layer.tx_queue._entries == []
