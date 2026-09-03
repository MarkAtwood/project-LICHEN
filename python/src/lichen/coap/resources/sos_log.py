# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""``/sos/log`` -- emergency log resource (spec 12-apps.md 18.4.5, bead l1qw.37).

Bounded in-RAM event log recording SOS lifecycle transitions:
initiated / update / cancelled. Process-lifetime state; oldest events
are dropped once :data:`SOS_LOG_MAX` is reached.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from typing import Any

import cbor2
from aiocoap import GET, Message
from aiocoap.resource import Resource

from lichen.coap.resources.base import CBOR

SOS_LOG_MAX = 64


class SosLogResource(Resource):
    """``GET /sos/log`` -- bounded SOS lifecycle event log (spec 18.4.5)."""

    rt = "sos.log"

    def __init__(
        self,
        *,
        sos: Any = None,
        clock: Callable[[], float] | None = None,
        max_events: int = SOS_LOG_MAX,
    ) -> None:
        super().__init__()
        self._sos = sos
        self._clock = clock if clock is not None else _default_clock
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}

    def record(self, node: str, sos_type: str, action: str) -> None:
        """Append one lifecycle event (spec 18.4.5 event shape)."""
        self._events.append(
            {
                "ts": int(self._clock()),
                "node": node,
                "type": sos_type,
                "action": action,
            }
        )

    def events(self) -> list[dict[str, Any]]:
        return [dict(e) for e in self._events]

    async def render_get(self, request: Message) -> Message:
        if request.code != GET:
            return Message(code=4 * 32 + 5)  # 4.05 Method Not Allowed
        body = {"events": self.events()}
        response = Message(code=2 * 32 + 5)
        response.payload = cbor2.dumps(body)
        response.opt.content_format = CBOR
        return response


def _default_clock() -> float:
    import time

    return time.time()
