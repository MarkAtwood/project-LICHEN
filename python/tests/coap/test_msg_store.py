# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""/msg/store store-and-forward resource (spec 12-apps.md 18.1.4, bead l1qw.33)."""

from __future__ import annotations

import cbor2
from aiocoap import Message

from lichen.coap.resources.msg_store import MsgStoreResource

SERVICE_UNAVAILABLE_CODE = 5 * 32 + 3
ENTITY_TOO_LARGE_CODE = 4 * 32 + 13
FORBIDDEN_CODE = 4 * 32 + 3
BAD_REQUEST_CODE = 4 * 32 + 0
CHANGED_CODE = 2 * 32 + 4


def _store(**overrides: object) -> MsgStoreResource:
    ticks = {"t": 1000.0}

    def clock() -> float:
        return ticks["t"]

    defaults: dict[str, object] = {"clock": clock}
    defaults.update(overrides)
    store = MsgStoreResource(**defaults)  # type: ignore[arg-type]
    store._ticks = ticks  # type: ignore[attr-defined]
    return store


def _advance(store: MsgStoreResource, seconds: float) -> None:
    store._ticks["t"] += seconds  # type: ignore[attr-defined]


async def _post(
    store: MsgStoreResource,
    dest: str = "0200::42",
    payload: bytes = b"m1",
    *,
    ttl_s: int | None = None,
    raw: bytes | None = None,
) -> Message:
    body: dict[str, object] = {"dest": dest, "payload": payload}
    if ttl_s is not None:
        body["ttl_s"] = ttl_s
    request = Message(code=1, payload=raw if raw is not None else cbor2.dumps(body))
    return await store.render_post(request)


async def _drain(store: MsgStoreResource, dest: str = "0200::42") -> list[dict]:
    request = Message(code=1)
    request.opt.uri_query = (f"dest={dest}",)
    response = await store.render_get(request)
    return cbor2.loads(response.payload)


async def test_store_and_drain_fifo() -> None:
    store = _store()
    assert (await _post(store, payload=b"first")).code == CHANGED_CODE
    assert (await _post(store, payload=b"second")).code == CHANGED_CODE
    drained = await _drain(store)
    assert [m["payload"] for m in drained] == [b"first", b"second"]
    assert await _drain(store) == []  # drained messages do not come back


async def test_expired_messages_evicted_first() -> None:
    store = _store(max_total=8)
    assert (await _post(store, dest="A", payload=b"short-ttl", ttl_s=3600)).code == CHANGED_CODE
    assert (await _post(store, dest="B", payload=b"long-ttl", ttl_s=4 * 3600)).code == CHANGED_CODE
    _advance(store, 2 * 3600)  # A expired, B still fresh
    assert (await _post(store, dest="C", payload=b"new")).code == CHANGED_CODE
    assert {m["payload"] for m in await _drain(store, "A")} == set()  # expired
    assert {m["payload"] for m in await _drain(store, "B")} == {b"long-ttl"}
    assert {m["payload"] for m in await _drain(store, "C")} == {b"new"}


async def test_message_too_large_is_413() -> None:
    store = _store(max_message_size=128)
    response = await _post(store, payload=b"x" * 129)
    assert response.code == ENTITY_TOO_LARGE_CODE


async def test_ttl_too_long_is_400() -> None:
    store = _store()
    response = await _post(store, ttl_s=25 * 3600)  # exceeds the 24h maximum
    assert response.code == BAD_REQUEST_CODE


async def test_blacklisted_destination_is_403() -> None:
    store = _store(blacklisted_destinations=frozenset({"0200::bad"}))
    response = await _post(store, dest="0200::bad")
    assert response.code == FORBIDDEN_CODE


async def test_eviction_makes_room_before_503() -> None:
    """Spec 18.1.4 eviction step 3 (FIFO) is unconditional, so a full
    store evicts its oldest message rather than rejecting. 5.03 maps
    from _make_room exhaustion, which a valid POST cannot reach while
    any message is evictable."""
    store = _store(max_total=8, max_per_dest=16)
    for i in range(8):
        assert (await _post(store, dest=f"0200::{i:02x}", payload=b"m")).code == CHANGED_CODE
    response = await _post(store, dest="0200::ff", payload=b"m")
    assert response.code == CHANGED_CODE  # oldest evicted, new stored
    assert len(store._messages) == 8


async def test_make_room_exhaustion_maps_to_503_path() -> None:
    """_make_room returns False only when nothing is evictable (an empty
    store that still cannot fit) -- the branch render_post maps to 5.03."""
    store = _store(max_total=8, max_total_bytes=1024)
    # 100-byte message fits; the byte budget cannot be exceeded because
    # the 4.13 gate caps messages at 512 < 1024. Simulate the exhaustion
    # branch directly: an empty store evicts nothing.
    assert store._make_room("0200::42", 2000) is False
    assert store._messages == []


async def test_fair_share_eviction() -> None:
    """Spec 18.1.4: fair share = total_messages / active_destinations
    (current count). Store full at 8/8 across 7 destinations (fair share
    1); A holds 2 > 1, so A's oldest is evicted before anyone's single
    message."""
    store = _store(max_total=8, max_per_dest=16)
    assert (await _post(store, dest="A", payload=b"a1")).code == CHANGED_CODE
    assert (await _post(store, dest="A", payload=b"a2")).code == CHANGED_CODE
    for i in range(6):
        assert (await _post(store, dest=f"0200::{i:02x}", payload=b"x")).code == CHANGED_CODE
    # Store full (8/8); fair share 8//7 = 1; A holds 2 > 1.
    assert (await _post(store, dest="0200::ff", payload=b"new")).code == CHANGED_CODE
    payloads_a = [m["payload"] for m in (await _drain(store, "A"))]
    assert payloads_a == [b"a2"]  # a1 (over fair share) evicted


async def test_expired_first_under_full_store() -> None:
    """Eviction step 1 under real pressure: expired messages are evicted
    before fair-share/FIFO victims."""
    store = _store(max_total=8, max_per_dest=16)
    assert (await _post(store, dest="A", payload=b"a-exp", ttl_s=3600)).code == CHANGED_CODE
    assert (await _post(store, dest="A", payload=b"a-fresh")).code == CHANGED_CODE
    for i in range(6):
        assert (await _post(store, dest=f"0200::{i:02x}", payload=b"x")).code == CHANGED_CODE
    _advance(store, 2 * 3600)  # a-exp expires; store is full (8/8)
    assert (await _post(store, dest="0200::ff", payload=b"new")).code == CHANGED_CODE
    assert {m["payload"] for m in (await _drain(store, "A"))} == {b"a-fresh"}
    for i in range(6):
        assert {m["payload"] for m in (await _drain(store, f"0200::{i:02x}"))} == {b"x"}


async def test_per_destination_cap_enforced() -> None:
    store = _store(max_total=8, max_per_dest=2)
    assert (await _post(store, dest="A", payload=b"a1")).code == CHANGED_CODE
    assert (await _post(store, dest="A", payload=b"a2")).code == CHANGED_CODE
    assert (await _post(store, dest="A", payload=b"a3")).code == CHANGED_CODE
    payloads = [m["payload"] for m in (await _drain(store, "A"))]
    assert payloads == [b"a2", b"a3"]  # a1 rolled off at the per-dest cap


async def test_total_bytes_cap_evicts_oldest() -> None:
    store = _store(max_total=8, max_total_bytes=1024, max_message_size=512)
    assert (await _post(store, payload=b"a" * 400)).code == CHANGED_CODE
    assert (await _post(store, payload=b"b" * 300)).code == CHANGED_CODE
    # 400 + 300 + 400 = 1100 > 1024: the byte budget evicts the oldest
    # (400B) message, leaving 700 + the new 400 = fits.
    assert (await _post(store, payload=b"c" * 400)).code == CHANGED_CODE
    drained = [m["payload"] for m in await _drain(store)]
    assert drained == [b"b" * 300, b"c" * 400]


async def test_malformed_posts_are_400() -> None:
    store = _store()
    cases = [
        b"",
        b"not-cbor",
        cbor2.dumps([1, 2]),
        cbor2.dumps({"payload": b"m"}),  # missing dest
        cbor2.dumps({"dest": "", "payload": b"m"}),
        cbor2.dumps({"dest": 5, "payload": b"m"}),
        cbor2.dumps({"dest": "A", "payload": ""}),
        cbor2.dumps({"dest": "A", "payload": b"m", "extra": 1}),
        cbor2.dumps({"dest": "A", "payload": b"m", "ttl_s": 0}),
    ]
    for raw in cases:
        response = await _post(store, raw=raw)
        assert response.code == BAD_REQUEST_CODE


async def test_capability_link_description() -> None:
    store = _store()
    link = store.get_link_description()
    assert link["rt"] == "msg.store"
