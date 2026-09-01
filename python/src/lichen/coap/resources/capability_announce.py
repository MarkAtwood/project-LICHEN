# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /.well-known/capability-announce (spec 06-security.md 8.12, l1qw.32
sweep / b7z9.36).

Root-side capability table fed by node capability announcements. The
announcement is a COSE_Sign1 (Schnorr48 over SHA-256 Sig_structure) whose
kid is the announcer's link-local IID; the root verifies it against the
link-authenticated sender's pinned pubkey, tracks the per-announcer replay
floor, and bounds the table with LRU eviction. The table feeds tunnel-auth
and egress decisions (spec 8.12 -> 8.11 flow).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

import aiocoap
import cbor2
from aiocoap import Message, resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.deaddrop import _request_context_id
from lichen.crypto.capability_announcements import (
    decode_cose_sign1_announcement,
    verify_capability_announcement,
)

# Spec 06-security.md:977-981: the capability table is bounded at 256
# entries with LRU eviction; implementations MAY reserve 25% for egress.
CAPABILITY_TABLE_CAPACITY = 256
CAPABILITY_EGRESS_RESERVATION = CAPABILITY_TABLE_CAPACITY // 4

DEFAULT_RETRY_AFTER_S = 120


class CapabilityTable:
    """Bounded LRU cache of accepted capability announcements.

    Keyed by announcer IID (8 bytes). ``effective_capacity`` applies the
    25% egress reservation: non-egress inserts may not consume the
    reserved tail, so egress-sourced announcements always have room.
    """

    def __init__(
        self,
        capacity: int = CAPABILITY_TABLE_CAPACITY,
        egress_reservation: int = CAPABILITY_EGRESS_RESERVATION,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self.egress_reservation = min(egress_reservation, capacity)
        self._clock = clock or (lambda: 0)
        self._entries: OrderedDict[bytes, dict[str, Any]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def cached_seq(self, announcer_iid: bytes) -> int | None:
        entry = self._entries.get(announcer_iid)
        if entry is None:
            return None
        entry["last_used"] = self._clock()
        self._entries.move_to_end(announcer_iid)
        return int(entry["seq"])

    def record(
        self,
        announcer_iid: bytes,
        *,
        seq: int,
        expiry: int,
        capabilities: int,
        egress: bool = False,
    ) -> bool:
        """Accept one announcement into the table.

        Returns False when a non-egress insert would consume the reserved
        tail (the caller responds 5.03/4.03 per policy); returns True after
        an insert-or-refresh with LRU bookkeeping.
        """
        effective = (
            self.capacity
            if egress
            else self.capacity - self.egress_reservation
        )
        if announcer_iid in self._entries:
            entry = self._entries[announcer_iid]
            entry["seq"] = seq
            entry["expiry"] = expiry
            entry["capabilities"] = capabilities
            entry["last_used"] = self._clock()
            self._entries.move_to_end(announcer_iid)
            return True
        if len(self._entries) >= effective:
            # LRU eviction only for egress-sourced inserts that need the
            # reserved tail; non-egress inserts are refused instead.
            if not egress:
                return False
            self._entries.popitem(last=False)
        self._entries[announcer_iid] = {
            "seq": seq,
            "expiry": expiry,
            "capabilities": capabilities,
            "last_used": self._clock(),
        }
        return True

    def purge_expired(self, now: int) -> int:
        """Drop expired announcements; returns the number purged."""
        expired = [
            iid for iid, entry in self._entries.items() if entry["expiry"] <= now
        ]
        for iid in expired:
            del self._entries[iid]
        return len(expired)


class CapabilityAnnounceResource(resource.Resource):
    """POST /.well-known/capability-announce (spec 06-security.md 8.12).

    Requires OSCORE (the announcement is authenticated against the
    link-authenticated sender's pinned pubkey); 2.04 on success, 4.03 on
    any verification failure.
    """

    rt = "lichen.capability-announce"

    def __init__(
        self,
        table: CapabilityTable,
        pubkey_resolver: Callable[[str], bytes | None],
        clock: Callable[[], int] | None = None,
    ) -> None:
        super().__init__()
        self._table = table
        self._pubkey_resolver = pubkey_resolver
        self._clock: Callable[[], int] = (
            clock if clock is not None else (lambda: int(time.time()))
        )

    async def render_post(self, request: Message) -> Message:
        context_id = _request_context_id(request)
        if context_id is None:
            msg = Message(code=aiocoap.UNAUTHORIZED)
            msg.opt.content_format = CBOR
            msg.payload = cbor2.dumps({"error": "oscore_required"})
            return msg
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        pubkey = self._pubkey_resolver(context_id)
        if pubkey is None:
            return Message(code=aiocoap.FORBIDDEN)
        try:
            announcement = decode_cose_sign1_announcement(request.payload)
        except Exception:
            return Message(code=aiocoap.FORBIDDEN)
        announcer_iid = announcement.payload.announcer_iid
        valid, _error = verify_capability_announcement(
            announcement=announcement,
            pubkey=pubkey,
            current_time=self._clock(),
            cached_seq=self._table.cached_seq(announcer_iid),
        )
        if not valid:
            return Message(code=aiocoap.FORBIDDEN)
        if not self._table.record(
            announcer_iid,
            seq=announcement.payload.seq,
            expiry=announcement.payload.expiry,
            capabilities=announcement.payload.capabilities,
        ):
            return Message(code=aiocoap.SERVICE_UNAVAILABLE)
        msg = Message(code=aiocoap.CHANGED)
        msg.opt.content_format = CBOR
        return msg
