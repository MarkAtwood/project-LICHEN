# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``/msg/store`` -- store-and-forward (spec/12-apps.md 18.1.4).

Nodes MAY implement store-and-forward for offline recipients: a sender
POSTs a message for a destination that is currently unreachable, the
store holds it under the destination identity, and the destination
drains it with GET when it reappears.

Capability advertisement: ``rt="msg.store"`` via the resource's link
description (spec 18.1.4: ``</msg/store>;rt="msg.store"``).

Storage limits, eviction order (expired first, then per-destination
fair-share oldest, then FIFO oldest) and back-pressure codes (5.03
storage full, 4.13 too large, 4.03 blacklisted destination, 4.00 TTL
too long) follow spec/12-apps.md 18.1.4 exactly.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import cbor2
from aiocoap import (
    BAD_REQUEST,
    CHANGED,
    FORBIDDEN,
    SERVICE_UNAVAILABLE,
    Message,
)
from aiocoap.resource import Resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor

_MAX_TTL_S_HARD_CAP = 24 * 3600  # 18.1.4 maximum TTL


@dataclass
class StoredMessage:
    """One stored store-and-forward message."""

    destination: str
    payload: bytes
    expires: float  # absolute clock seconds (from the injected clock)
    seq: int  # insertion order for FIFO tiebreaks


class MsgStoreResource(Resource):
    """``/msg/store`` -- store-and-forward for offline recipients (18.1.4).

    POST stores a CBOR body ``{dest, payload, ttl_s?}`` for the named
    destination; GET with query ``?dest=<id>`` drains and returns that
    destination's stored messages in FIFO order. Back-pressure codes per
    the 18.1.4 table; eviction per the 18.1.4 policy (expired first, then
    per-destination fair-share oldest, then FIFO oldest).
    """

    rt = "msg.store"

    def __init__(
        self,
        *,
        max_total: int = 16,
        max_per_dest: int = 4,
        max_message_size: int = 256,
        max_total_bytes: int = 4096,
        max_ttl_s: int = 4 * 3600,
        clock: Callable[[], float] | None = None,
        blacklisted_destinations: frozenset[str] = frozenset(),
    ) -> None:
        super().__init__()
        if not 8 <= max_total <= 64:
            raise ValueError("max_total must be within [8, 64] (spec 18.1.4)")
        if not 2 <= max_per_dest <= 16:
            raise ValueError("max_per_dest must be within [2, 16] (spec 18.1.4)")
        if not 128 <= max_message_size <= 512:
            raise ValueError("max_message_size must be within [128, 512]")
        if not 1024 <= max_total_bytes <= 16384:
            raise ValueError("max_total_bytes must be within [1024, 16384]")
        if not 3600 <= max_ttl_s <= _MAX_TTL_S_HARD_CAP:
            raise ValueError("max_ttl_s must be within [3600, 86400] (spec 18.1.4)")
        self._max_total = max_total
        self._max_per_dest = max_per_dest
        self._max_message_size = max_message_size
        self._max_total_bytes = max_total_bytes
        self._max_ttl_s = max_ttl_s
        self._clock = clock if clock is not None else time.monotonic
        self._blacklist = frozenset(blacklisted_destinations)
        self._messages: list[StoredMessage] = []
        self._seq = 0

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}

    def _now(self) -> float:
        return float(self._clock())

    def _count_per_dest(self, dest: str) -> int:
        return sum(1 for m in self._messages if m.destination == dest)

    def _total_bytes(self) -> int:
        return sum(len(m.payload) for m in self._messages)

    def _evict_one(self, incoming_dest: str) -> bool:
        """Free one slot per the 18.1.4 eviction order.

        Returns True when a slot was freed, False when nothing may be
        evicted (caller maps that to 5.03 when the store is still full).
        """
        # 1. Expired messages are always evicted first.
        now = self._now()
        expired = [m for m in self._messages if m.expires <= now]
        if expired:
            self._messages.remove(min(expired, key=lambda m: m.seq))
            return True
        if not self._messages:
            return False
        # 2. Per-destination fairness: spec 18.1.4 "fair share =
        # total_messages / active_destinations" (current message count).
        # A destination holding more than its fair share surrenders its
        # oldest message first. The incoming destination at its
        # per-destination cap also qualifies (its oldest message is what
        # the new message displaces).
        dests = {m.destination for m in self._messages}
        fair_share = len(self._messages) // max(len(dests), 1)
        over = [
            m
            for m in self._messages
            if self._count_per_dest(m.destination) > fair_share
            or (m.destination == incoming_dest
                and self._count_per_dest(incoming_dest) >= self._max_per_dest)
        ]
        if over:
            self._messages.remove(min(over, key=lambda m: m.seq))
            return True
        # 3. FIFO: oldest message across all destinations.
        self._messages.remove(min(self._messages, key=lambda m: m.seq))
        return True

    def _make_room(self, dest: str, size: int) -> bool:
        """Evict per policy until the incoming message fits; False when it
        cannot fit without violating the limits."""
        while (
            len(self._messages) >= self._max_total
            or self._total_bytes() + size > self._max_total_bytes
            or self._count_per_dest(dest) >= self._max_per_dest
        ):
            if not self._evict_one(dest):
                return False
        return True

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if type(body) is not dict:
            return Message(code=BAD_REQUEST)
        unknown = set(body) - {"dest", "payload", "ttl_s"}
        if unknown:
            return Message(code=BAD_REQUEST)
        dest = body.get("dest")
        payload = body.get("payload")
        ttl_s = body.get("ttl_s")
        if type(dest) is not str or dest == "":
            return Message(code=BAD_REQUEST)
        if type(payload) is not bytes or not payload:
            return Message(code=BAD_REQUEST)
        if len(payload) > self._max_message_size:
            # 4.13 Request Entity Too Large: reduce size (spec 18.1.4).
            return Message(code=4 * 32 + 13)
        if ttl_s is None:
            ttl_s = self._max_ttl_s  # default TTL (spec 18.1.4 table)
        if type(ttl_s) is not int or ttl_s <= 0:
            return Message(code=BAD_REQUEST)
        if ttl_s > self._max_ttl_s:
            return Message(code=BAD_REQUEST)  # TTL too long: reduce TTL
        if dest in self._blacklist:
            return Message(code=FORBIDDEN)  # won't store for this dest
        if not self._make_room(dest, len(payload)):
            return Message(code=SERVICE_UNAVAILABLE)  # 5.03 storage full
        self._seq += 1
        self._messages.append(
            StoredMessage(
                destination=dest,
                payload=payload,
                expires=self._now() + ttl_s,
                seq=self._seq,
            )
        )
        return Message(code=CHANGED)

    async def render_get(self, request: Message) -> Message:
        raw_query = request.opt.uri_query
        parts = (
            [raw_query] if isinstance(raw_query, str) else list(raw_query or ())
        )
        params = dict(
            part.split("=", 1) for part in parts if isinstance(part, str) and "=" in part
        )
        dest = params.get("dest")
        if type(dest) is not str or dest == "":
            return Message(code=BAD_REQUEST)
        now = self._now()
        self._messages = [m for m in self._messages if m.expires > now]
        drained = sorted(
            (m for m in self._messages if m.destination == dest),
            key=lambda m: m.seq,
        )
        body = [
            {"payload": m.payload, "expires": m.expires, "seq": m.seq}
            for m in drained
        ]
        self._messages = [m for m in self._messages if m.destination != dest]
        response = Message(code=CHANGED)
        response.payload = cbor2.dumps(body)
        response.opt.content_format = CBOR
        return response
