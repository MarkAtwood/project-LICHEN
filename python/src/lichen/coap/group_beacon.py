# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group-mode encrypted position beacons (spec 12-apps.md 18.2.4, l1qw.35.2).

In group privacy mode, position beacons are sealed with the group key and
PUT to the group's ff35 multicast address (RFC 3306, spec 18.8.3). Only
group members holding current key material can open them; non-members see
only that a transmission occurred.

Wire contract (PUT ``coap://[ff35:...group-mcast]/pos``):

    Content-Format: application/cbor
    payload: CBOR {nonce: bstr(13), ct: bstr, key_epoch: uint, gid: tstr}

This module provides:

- :func:`seal_position_beacon` — emitter side: seal a position dict for the
  group's ff35 address.
- :class:`GroupBeaconResource` — receiver side: an aiocoap resource handling
  PUTs of sealed beacons; opens with the group manager and forwards the
  plaintext position to the same ``on_position`` callback shape as
  ``PositionBeaconResource``. Non-members' beacons fail ``open`` and are
  silently dropped (spec 18.2.4: non-members see only presence).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import cbor2
from aiocoap import BAD_REQUEST, CHANGED, Message, resource

from lichen.coap.resources.base import CBOR
from lichen.crypto.group_oscore import (
    GroupKeyManager,
    open_group_payload,
    seal_group_payload,
)


def seal_position_beacon(
    manager: GroupKeyManager,
    position: dict[str, Any],
    group_id: str,
    mcast_addr: str,
) -> tuple[str, bytes]:
    """Seal a position beacon for group multicast (emitter side).

    Args:
        manager: Group key manager holding the current group key.
        position: Position dict (lat/lon required; optional alt, speed,
            heading, hacc, ts) — the SenML position record fields.
        group_id: Group identifier (drives the ff35 address and key epoch
            context).
        mcast_addr: The group's ff35 multicast address (spec 18.8.3), bound
            into the AEAD as AAD so beacons cannot be replayed to a
            different group address.

    Returns:
        ``(mcast_addr, sealed_wire_bytes)`` — PUT *sealed_wire_bytes* to
        ``coap://[mcast_addr]/pos``.
    """
    aad = mcast_addr.encode("utf-8")
    ct, nonce, epoch = seal_group_payload(manager, cbor2.dumps(position), aad)
    wire = cbor2.dumps(
        {"gid": group_id, "key_epoch": epoch, "nonce": nonce, "ct": ct}
    )
    return mcast_addr, wire


def open_position_beacon(
    manager: GroupKeyManager,
    wire: bytes,
    mcast_addr: str,
) -> tuple[str, dict[str, Any]]:
    """Open a sealed group beacon (receiver side).

    Args:
        manager: Group key manager holding current + grace-window material.
        wire: The sealed wire bytes from :func:`seal_position_beacon`.
        mcast_addr: The multicast address the beacon arrived on (AEAD AAD —
            a beacon relayed to a different group address fails to open).

    Returns:
        ``(group_id, position_dict)``.

    Raises:
        ValueError: On malformed wire, unknown group, or decryption failure
            (non-members and stale epochs fail closed here).
    """
    body = cbor2.loads(wire)
    if not isinstance(body, dict):
        raise ValueError("group beacon payload must be a CBOR map")
    group_id = body.get("gid")
    key_epoch = body.get("key_epoch")
    nonce = body.get("nonce")
    ct = body.get("ct")
    if (
        type(group_id) is not str
        or type(key_epoch) is not int
        or type(nonce) is not bytes
        or type(ct) is not bytes
    ):
        raise ValueError("group beacon payload fields malformed")
    aad = mcast_addr.encode("utf-8")
    if manager.group_id != group_id.encode("utf-8"):
        raise ValueError(f"group beacon for unknown group {group_id!r}")
    plaintext = open_group_payload(manager, ct, nonce, key_epoch, aad)
    position = cbor2.loads(plaintext)
    if not isinstance(position, dict):
        raise ValueError("group beacon payload must decode to a CBOR map")
    return group_id, position


class GroupBeaconResource(resource.Resource):
    """PUT receiver for sealed group-mode position beacons (spec 18.2.4).

    Accepts PUTs of ``seal_position_beacon`` wire payloads, opens them with
    the group key manager, and forwards the plaintext position to the
    configured callback (same ``(sender_id, position_dict)`` shape as
    ``PositionBeaconResource.on_position``). Non-members' beacons fail
    ``open()`` and are silently dropped — a non-member sees only that a
    transmission occurred (spec 18.2.4).
    """

    rt = "position.group-beacon"

    def __init__(
        self,
        manager: GroupKeyManager,
        *,
        mcast_addr: str,
        on_position: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        super().__init__()
        self._manager = manager
        self._mcast_addr = mcast_addr
        self._on_position = on_position

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            group_id, position = open_position_beacon(
                self._manager, request.payload, self._mcast_addr
            )
        except (ValueError, cbor2.CBORDecodeError):
            # Non-member or stale-epoch beacon: silently drop (spec 18.2.4
            # — non-members see only that a transmission occurred).
            return Message(code=BAD_REQUEST)
        if self._on_position is not None:
            self._on_position(group_id, position)
        return Message(code=CHANGED)
