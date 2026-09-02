# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SOS log resource tests (spec 18.4.5, bead l1qw.37)."""

from __future__ import annotations

import cbor2
import pytest
from aiocoap import Message

from lichen.coap.resources.sos_log import SosLogResource


@pytest.fixture
def log() -> SosLogResource:
    ticks = {"t": 1716742800.0}

    def clock() -> float:
        return ticks["t"]

    return SosLogResource(sos=None, clock=clock)


def test_record_and_get(log: SosLogResource) -> None:
    log.record("0200::1111", "sos", "initiated")
    log.record("0200::1111", "sos", "cancelled")
    events = log.events()
    assert len(events) == 2
    assert events[0]["action"] == "initiated"
    assert events[1]["action"] == "cancelled"
    assert events[0]["node"] == "0200::1111"


@pytest.mark.asyncio
async def test_get_returns_cbor_events(log: SosLogResource) -> None:
    log.record("0200::1111", "sos", "initiated")
    request = Message(code=1)
    response = await log.render_get(request)
    assert response.code.is_successful()
    assert response.opt.content_format is not None
    body = cbor2.loads(response.payload)
    assert len(body["events"]) == 1
    assert body["events"][0]["type"] == "sos"


def test_log_bounded_drops_oldest() -> None:
    log = SosLogResource(max_events=4)
    for i in range(6):
        log.record(f"0200::{i:04x}", "sos", "initiated")
    events = log.events()
    assert len(events) == 4
    assert events[0]["node"] == "0200::0002"  # oldest two dropped
    assert events[-1]["node"] == "0200::0005"


def test_lifecycle_sequence(log: SosLogResource) -> None:
    """Spec 18.4.5 event shape: initiated -> update -> cancelled."""
    log.record("0200::1111", "medical", "initiated")
    log.record("0200::1111", "medical", "update")
    log.record("0200::1111", "medical", "cancelled")
    actions = [e["action"] for e in log.events()]
    assert actions == ["initiated", "update", "cancelled"]
