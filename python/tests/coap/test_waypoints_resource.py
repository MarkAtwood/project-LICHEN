# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the /waypoints CoAP resource (spec 18.3)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest
from aiocoap import DELETE, GET, POST, PUT, Message

from lichen.coap.resources import StaticNodeInfo, WaypointDetailsResource, WaypointsResource
from lichen.coap.resources.site import build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

_CREATOR = "0200:1234:5678:abcd"
_WPT1 = {
    "name": "Rally Point Alpha",
    "lat": 37.774929,
    "lon": -122.419416,
    "icon": "flag",
    "notes": "Meet here at 1400",
}
_WPT2 = {
    "name": "Water Source",
    "lat": 37.78,
    "lon": -122.42,
    "icon": "water",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_waypoints_site(waypoints: WaypointsResource) -> aiocoap.resource.Site:
    """Build a site with waypoints resources."""
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info)
    site.add_resource(["waypoints"], waypoints)
    site.add_resource(["waypoints"], WaypointDetailsResource(waypoints))
    return site


async def _setup() -> tuple[aiocoap.Context, aiocoap.Context, WaypointsResource]:
    net = InMemoryNetwork()
    wpts = WaypointsResource(creator_id=_CREATOR)
    site = _build_waypoints_site(wpts)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, wpts


async def _setup_bounded(
    max_waypoints: int,
) -> tuple[aiocoap.Context, aiocoap.Context, WaypointsResource]:
    net = InMemoryNetwork()
    wpts = WaypointsResource(creator_id=_CREATOR, max_waypoints=max_waypoints)
    site = _build_waypoints_site(wpts)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, wpts


def _waypoints_list(payload: bytes) -> list[dict[str, object]]:
    decoded = cbor2.loads(payload)
    assert isinstance(decoded, dict)
    waypoints = decoded["waypoints"]
    assert isinstance(waypoints, list)
    return waypoints


# ---------------------------------------------------------------------------
# GET /waypoints
# ---------------------------------------------------------------------------


class TestWaypointsGet:
    async def test_empty_list(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/waypoints")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60  # CBOR
            assert _waypoints_list(resp.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_list_after_add(self) -> None:
        client, server, wpts = await _setup()
        try:
            wpts.add_waypoint({
                "id": "wpt-001",
                "name": "Rally Point Alpha",
                "lat": 37.774929,
                "lon": -122.419416,
                "created": 1716742800,
                "creator": _CREATOR,
            })
            resp = await client.request(Message(code=GET, uri="coap://srv/waypoints")).response
            wpt_list = _waypoints_list(resp.payload)
            assert len(wpt_list) == 1
            assert wpt_list[0]["name"] == "Rally Point Alpha"
            assert wpt_list[0]["lat"] == 37.774929
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_multiple_waypoints_in_order(self) -> None:
        client, server, wpts = await _setup()
        try:
            wpts.add_waypoint({
                "id": "wpt-001", "name": "First", "lat": 1.0, "lon": 2.0,
                "created": 1716742800, "creator": _CREATOR,
            })
            wpts.add_waypoint({
                "id": "wpt-002", "name": "Second", "lat": 3.0, "lon": 4.0,
                "created": 1716742801, "creator": _CREATOR,
            })
            resp = await client.request(Message(code=GET, uri="coap://srv/waypoints")).response
            wpt_list = _waypoints_list(resp.payload)
            assert len(wpt_list) == 2
            assert wpt_list[0]["name"] == "First"
            assert wpt_list[1]["name"] == "Second"
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# POST /waypoints
# ---------------------------------------------------------------------------


class TestWaypointsPost:
    async def test_create_waypoint(self) -> None:
        client, server, wpts = await _setup()
        try:
            payload = cbor2.dumps(_WPT1)
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.CREATED
            assert resp.opt.location_path == ("waypoints", "wpt-001")

            # Verify it was stored
            assert len(wpts.waypoints()) == 1
            wpt = wpts.waypoint("wpt-001")
            assert wpt is not None
            assert wpt["name"] == "Rally Point Alpha"
            assert wpt["lat"] == 37.774929
            assert wpt["creator"] == _CREATOR
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_create_with_all_optional_fields(self) -> None:
        client, server, wpts = await _setup()
        try:
            wpt_data = {
                "name": "Full Waypoint",
                "lat": 37.0,
                "lon": -122.0,
                "alt": 100.5,
                "icon": "camp",
                "color": "#00FF00",
                "notes": "Test notes",
                "expires": 1716829200,
            }
            payload = cbor2.dumps(wpt_data)
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.CREATED

            wpt = wpts.waypoint("wpt-001")
            assert wpt is not None
            assert wpt["alt"] == 100.5
            assert wpt["icon"] == "camp"
            assert wpt["color"] == "#00FF00"
            assert wpt["notes"] == "Test notes"
            assert wpt["expires"] == 1716829200
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_create_rejects_missing_name(self) -> None:
        client, server, _ = await _setup()
        try:
            payload = cbor2.dumps({"lat": 37.0, "lon": -122.0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_create_rejects_missing_lat(self) -> None:
        client, server, _ = await _setup()
        try:
            payload = cbor2.dumps({"name": "Test", "lon": -122.0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_create_rejects_missing_lon(self) -> None:
        client, server, _ = await _setup()
        try:
            payload = cbor2.dumps({"name": "Test", "lat": 37.0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_create_rejects_invalid_lat(self) -> None:
        client, server, _ = await _setup()
        try:
            payload = cbor2.dumps({"name": "Test", "lat": "invalid", "lon": -122.0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_create_rejects_empty_payload(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_create_rejects_invalid_cbor(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=b"\xff\xff")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_create_auto_increments_id(self) -> None:
        client, server, wpts = await _setup()
        try:
            for _ in range(3):
                payload = cbor2.dumps(_WPT1)
                await client.request(
                    Message(code=POST, uri="coap://srv/waypoints", payload=payload)
                ).response

            wpt_list = wpts.waypoints()
            assert len(wpt_list) == 3
            assert wpt_list[0]["id"] == "wpt-001"
            assert wpt_list[1]["id"] == "wpt-002"
            assert wpt_list[2]["id"] == "wpt-003"
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# GET /waypoints/{id}
# ---------------------------------------------------------------------------


class TestWaypointDetailGet:
    async def test_get_single_waypoint(self) -> None:
        client, server, wpts = await _setup()
        try:
            wpts.add_waypoint({
                "id": "wpt-001",
                "name": "Rally Point Alpha",
                "lat": 37.774929,
                "lon": -122.419416,
                "created": 1716742800,
                "creator": _CREATOR,
            })
            resp = await client.request(
                Message(code=GET, uri="coap://srv/waypoints/wpt-001")
            ).response
            assert resp.code == aiocoap.CONTENT
            wpt = cbor2.loads(resp.payload)
            assert wpt["id"] == "wpt-001"
            assert wpt["name"] == "Rally Point Alpha"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_get_nonexistent_returns_not_found(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/waypoints/wpt-999")
            ).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# PUT /waypoints/{id}
# ---------------------------------------------------------------------------


class TestWaypointDetailPut:
    async def test_update_waypoint(self) -> None:
        client, server, wpts = await _setup()
        try:
            wpts.add_waypoint({
                "id": "wpt-001",
                "name": "Old Name",
                "lat": 37.0,
                "lon": -122.0,
                "created": 1716742800,
                "creator": _CREATOR,
            })
            payload = cbor2.dumps({"name": "New Name", "notes": "Updated"})
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/waypoints/wpt-001", payload=payload)
            ).response
            assert resp.code == aiocoap.CHANGED

            wpt = wpts.waypoint("wpt-001")
            assert wpt is not None
            assert wpt["name"] == "New Name"
            assert wpt["notes"] == "Updated"
            # Ensure immutable fields are unchanged
            assert wpt["created"] == 1716742800
            assert wpt["creator"] == _CREATOR
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_update_coordinates(self) -> None:
        client, server, wpts = await _setup()
        try:
            wpts.add_waypoint({
                "id": "wpt-001",
                "name": "Test",
                "lat": 37.0,
                "lon": -122.0,
                "created": 1716742800,
                "creator": _CREATOR,
            })
            payload = cbor2.dumps({"lat": 38.0, "lon": -123.0, "alt": 50.0})
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/waypoints/wpt-001", payload=payload)
            ).response
            assert resp.code == aiocoap.CHANGED

            wpt = wpts.waypoint("wpt-001")
            assert wpt is not None
            assert wpt["lat"] == 38.0
            assert wpt["lon"] == -123.0
            assert wpt["alt"] == 50.0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_update_nonexistent_returns_not_found(self) -> None:
        client, server, _ = await _setup()
        try:
            payload = cbor2.dumps({"name": "New Name"})
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/waypoints/wpt-999", payload=payload)
            ).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_update_rejects_invalid_field_type(self) -> None:
        client, server, wpts = await _setup()
        try:
            wpts.add_waypoint({
                "id": "wpt-001",
                "name": "Test",
                "lat": 37.0,
                "lon": -122.0,
                "created": 1716742800,
                "creator": _CREATOR,
            })
            payload = cbor2.dumps({"lat": "invalid"})
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/waypoints/wpt-001", payload=payload)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# DELETE /waypoints/{id}
# ---------------------------------------------------------------------------


class TestWaypointDetailDelete:
    async def test_delete_waypoint(self) -> None:
        client, server, wpts = await _setup()
        try:
            wpts.add_waypoint({
                "id": "wpt-001",
                "name": "To Delete",
                "lat": 37.0,
                "lon": -122.0,
                "created": 1716742800,
                "creator": _CREATOR,
            })
            resp = await client.request(
                Message(code=DELETE, uri="coap://srv/waypoints/wpt-001")
            ).response
            assert resp.code == aiocoap.DELETED

            # Verify it was removed
            assert wpts.waypoint("wpt-001") is None
            assert len(wpts.waypoints()) == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_delete_nonexistent_returns_not_found(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=DELETE, uri="coap://srv/waypoints/wpt-999")
            ).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Capacity limits
# ---------------------------------------------------------------------------


class TestWaypointsCapacity:
    async def test_waypoints_capped_at_max(self) -> None:
        client, server, wpts = await _setup_bounded(max_waypoints=5)
        try:
            for i in range(5):
                payload = cbor2.dumps({"name": f"Waypoint {i}", "lat": float(i), "lon": float(-i)})
                resp = await client.request(
                    Message(code=POST, uri="coap://srv/waypoints", payload=payload)
                ).response
                assert resp.code == aiocoap.CREATED

            # Spec 18.3.2: 6th POST hits the global bound -> 5.03 with the
            # waypoint_limit diagnostic; nothing is evicted.
            payload = cbor2.dumps({"name": "Overflow", "lat": 1.0, "lon": -1.0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.SERVICE_UNAVAILABLE
            diagnostic = cbor2.loads(resp.payload)
            assert diagnostic["reason"] == "waypoint_limit"
            assert diagnostic["global"] == 5
            assert diagnostic["per_originator"] == 32

            wpt_list = wpts.waypoints()
            assert len(wpt_list) == 5
            # Nothing was evicted: the first five survive in creation order.
            assert wpt_list[0]["name"] == "Waypoint 0"
            assert wpt_list[-1]["name"] == "Waypoint 4"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_waypoints_reject_33rd_per_originator(self) -> None:
        client, server, wpts = await _setup()
        try:
            # Same creator: 32 accepted (spec per-originator bound), 33rd -> 5.03.
            for i in range(32):
                payload = cbor2.dumps({"name": f"W {i}", "lat": float(i), "lon": float(-i)})
                resp = await client.request(
                    Message(code=POST, uri="coap://srv/waypoints", payload=payload)
                ).response
                assert resp.code == aiocoap.CREATED

            payload = cbor2.dumps({"name": "Over per-originator", "lat": 9.0, "lon": -9.0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.SERVICE_UNAVAILABLE
            diagnostic = cbor2.loads(resp.payload)
            assert diagnostic["reason"] == "waypoint_limit"
            assert diagnostic["per_originator"] == 32
            assert diagnostic["global"] == 256
            assert len(wpts.waypoints()) == 32

            # A different creator still has headroom under the global bound.
            payload = cbor2.dumps(
                {"name": "Other", "lat": 2.0, "lon": -2.0, "creator": "0200:other:1"}
            )
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.CREATED
            assert len(wpts.waypoints()) == 33
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_readd_existing_id_at_per_originator_bound(self) -> None:
        client, server, wpts = await _setup()
        try:
            for i in range(32):
                payload = cbor2.dumps({"name": f"W {i}", "lat": float(i), "lon": float(-i)})
                await client.request(
                    Message(code=POST, uri="coap://srv/waypoints", payload=payload)
                ).response
            # Re-POST of an existing id replaces storage in place: it must
            # succeed even though this originator is at the 32 bound.
            payload = cbor2.dumps(
                {"id": "wpt-001", "name": "Updated", "lat": 5.0, "lon": -5.0}
            )
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.CREATED
            assert len(wpts.waypoints()) == 32
            assert wpts.waypoint("wpt-001")["name"] == "Updated"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_reattribution_to_full_creator_bucket_rejected(self) -> None:
        client, server, wpts = await _setup()
        try:
            # alice holds one waypoint; bob fills his own 32-slot bucket.
            payload = cbor2.dumps(
                {"id": "wpt-alice", "name": "Alice", "lat": 1.0, "lon": 1.0,
                 "creator": "alice"}
            )
            await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            for i in range(32):
                payload = cbor2.dumps(
                    {"name": f"B {i}", "lat": float(i), "lon": float(-i),
                     "creator": "bob"}
                )
                await client.request(
                    Message(code=POST, uri="coap://srv/waypoints", payload=payload)
                ).response
            # Re-attributing alice's waypoint to bob (at his 32 bound) must
            # be rejected with 5.03: the move consumes bob's headroom.
            payload = cbor2.dumps(
                {"id": "wpt-alice", "name": "Alice", "lat": 1.0, "lon": 1.0,
                 "creator": "bob"}
            )
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.SERVICE_UNAVAILABLE
            assert cbor2.loads(resp.payload)["reason"] == "waypoint_limit"
            # Table unchanged: still 33 entries, alice still owns hers.
            assert len(wpts.waypoints()) == 33
            assert wpts.waypoint("wpt-alice")["creator"] == "alice"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_delete_frees_per_originator_headroom(self) -> None:
        client, server, wpts = await _setup()
        try:
            for i in range(32):
                payload = cbor2.dumps({"name": f"W {i}", "lat": float(i), "lon": float(-i)})
                await client.request(
                    Message(code=POST, uri="coap://srv/waypoints", payload=payload)
                ).response
            # Full for this creator: delete one, then POST succeeds again.
            resp = await client.request(
                Message(code=DELETE, uri="coap://srv/waypoints/wpt-001")
            ).response
            assert resp.code == aiocoap.DELETED
            payload = cbor2.dumps({"name": "Refill", "lat": 4.0, "lon": -4.0})
            resp = await client.request(
                Message(code=POST, uri="coap://srv/waypoints", payload=payload)
            ).response
            assert resp.code == aiocoap.CREATED
            assert len(wpts.waypoints()) == 32
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_max_waypoints_validation(self) -> None:
        with pytest.raises(ValueError, match="positive integer"):
            WaypointsResource(max_waypoints=0)
        with pytest.raises(ValueError, match="positive integer"):
            WaypointsResource(max_waypoints=-1)
        with pytest.raises(ValueError, match="positive integer"):
            WaypointsResource(max_waypoints=True)
        with pytest.raises(ValueError, match="max_per_originator"):
            WaypointsResource(max_per_originator=0)

    async def test_readd_with_new_creator_moves_the_count(self) -> None:
        wpts = WaypointsResource(creator_id="cli")
        wpts.add_waypoint(
            {"id": "wpt-x", "name": "A", "lat": 1.0, "lon": 1.0, "creator": "alice"}
        )
        # Re-POST of the same id with a different creator must move the
        # count: alice freed, bob charged (spec 18.3.2 accounting).
        wpts.add_waypoint(
            {"id": "wpt-x", "name": "B", "lat": 2.0, "lon": 2.0, "creator": "bob"}
        )
        assert wpts._creator_counts == {"bob": 1}
        wpts.delete_waypoint("wpt-x")
        assert wpts._creator_counts == {}
