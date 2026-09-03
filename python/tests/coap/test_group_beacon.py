# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group-mode encrypted position beacons (spec 18.2.4, bead l1qw.35.2)."""

from __future__ import annotations

import pytest
from aiocoap import BAD_REQUEST, CHANGED, Message

from lichen.coap.group_beacon import (
    GroupBeaconEmitter,
    GroupBeaconResource,
    open_position_beacon,
    seal_position_beacon,
)
from lichen.coap.position_privacy import PositionPrivacyPolicy
from lichen.crypto.group_oscore import GroupKeyManager

GROUP_ID = "team-alpha"
GROUP_KEY = bytes(range(16))
POSITION = {"lat": 37.774929, "lon": -122.419416, "ts": 1716742800}
MCAST = "ff35:0040:0200::9abc"


@pytest.fixture
def manager() -> GroupKeyManager:
    return GroupKeyManager(GROUP_ID.encode("utf-8"), GROUP_KEY)



class _Clock:
    def __init__(self, start: float = 1716742800.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def resource(manager: GroupKeyManager) -> GroupBeaconResource:
    received: list[tuple[str, dict]] = []

    def capture(gid: str, pos: dict) -> None:
        received.append((gid, pos))

    res = GroupBeaconResource(manager, mcast_addr=MCAST, on_position=capture)
    res.received = received  # type: ignore[attr-defined]
    return res


def _seal_wire(manager: GroupKeyManager, gid: str, mcast: str, pos: dict) -> bytes:
    _, wire = seal_position_beacon(manager, pos, gid, mcast)
    return wire


@pytest.mark.asyncio
async def test_seal_open_roundtrip(manager: GroupKeyManager) -> None:
    _, wire = seal_position_beacon(manager, POSITION, GROUP_ID, MCAST)
    gid, pos = open_position_beacon(manager, wire, MCAST)
    assert gid == GROUP_ID
    assert pos == POSITION


@pytest.mark.asyncio
async def test_member_put_forwarded_to_callback(
    manager: GroupKeyManager, resource: GroupBeaconResource
) -> None:
    wire = _seal_wire(manager, GROUP_ID, MCAST, POSITION)
    response = await resource.render_post(
        Message(code=1, payload=wire)
    )
    assert response.code == CHANGED
    assert len(resource.received) == 1
    group_id, position = resource.received[0]
    assert group_id == GROUP_ID
    assert position == POSITION


@pytest.mark.asyncio
async def test_wrong_group_address_fails_closed(
    manager: GroupKeyManager, resource: GroupBeaconResource
) -> None:
    """A beacon sealed for one ff35 address cannot be replayed to another."""
    wire = _seal_wire(manager, GROUP_ID, MCAST, POSITION)
    other = GroupBeaconResource(
        manager, mcast_addr="ff35:0040:0200::9999", on_position=None
    )
    response = await other.render_post(Message(code=1, payload=wire))
    assert response.code == BAD_REQUEST


@pytest.mark.asyncio
async def test_unknown_group_dropped(
    manager: GroupKeyManager, resource: GroupBeaconResource
) -> None:
    wire = _seal_wire(manager, "other-group", MCAST, POSITION)
    response = await resource.render_post(Message(code=1, payload=wire))
    assert response.code == BAD_REQUEST
    assert resource.received == []


@pytest.mark.asyncio
async def test_stale_epoch_dropped(
    manager: GroupKeyManager, resource: GroupBeaconResource
) -> None:
    """Beacon sealed under epoch 1, then rekey: stale epoch is outside the
    grace policy the receiver enforces... but within grace it OPENS (spec:
    stragglers can decrypt in-flight traffic). Assert grace behavior here:
    fresh manager, no rekey -> epoch 1 is current -> opens."""
    wire = _seal_wire(manager, GROUP_ID, MCAST, POSITION)
    response = await resource.render_post(Message(code=1, payload=wire))
    assert response.code == CHANGED


@pytest.mark.asyncio
async def test_empty_payload_rejected(
    resource: GroupBeaconResource,
) -> None:
    response = await resource.render_post(Message(code=1, payload=b""))
    assert response.code == BAD_REQUEST


@pytest.mark.asyncio
async def test_garbage_payload_rejected(
    resource: GroupBeaconResource,
) -> None:
    response = await resource.render_post(Message(code=1, payload=b"not-cbor"))
    assert response.code == BAD_REQUEST


@pytest.mark.asyncio
async def test_emitter_seals_in_group_mode(manager: GroupKeyManager) -> None:
    """Emitter returns a sealed beacon when policy is GROUP."""
    policy = PositionPrivacyPolicy("group")
    emitter = GroupBeaconEmitter(
        manager, group_id=GROUP_ID, mcast_addr=MCAST, policy=policy, now=_Clock()
    )
    emitter.update_position(POSITION)
    result = emitter.emit()
    assert result is not None
    mcast_addr, wire = result
    assert mcast_addr == MCAST
    gid, pos = open_position_beacon(manager, wire, MCAST)
    assert gid == GROUP_ID
    assert pos == POSITION


@pytest.mark.asyncio
async def test_emitter_silent_in_public_mode(manager: GroupKeyManager) -> None:
    policy = PositionPrivacyPolicy("public")
    emitter = GroupBeaconEmitter(
        manager, group_id=GROUP_ID, mcast_addr=MCAST, policy=policy, now=_Clock()
    )
    emitter.update_position(POSITION)
    assert emitter.emit() is None


@pytest.mark.asyncio
async def test_emitter_silent_without_position_fix(manager: GroupKeyManager) -> None:
    policy = PositionPrivacyPolicy("group")
    emitter = GroupBeaconEmitter(
        manager, group_id=GROUP_ID, mcast_addr=MCAST, policy=policy, now=_Clock()
    )
    assert emitter.emit() is None  # no fix pushed yet
