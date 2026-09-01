# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Privacy configuration resources: /config/privacy (spec 18.2.4).

GET  /config/privacy          -> {mode, allowed_peer_count}
GET  /config/privacy/allowed  -> {peers: [...]}   (writes-enabled only)
PUT  /config/privacy/allowed  <- {peers: [...]}  (writes-enabled only)
"""

from __future__ import annotations

import aiocoap
import cbor2
from aiocoap import Message, resource

from lichen.coap.position_privacy import PositionPrivacyPolicy
from lichen.coap.resources.base import CBOR, _cbor_response
from lichen.coap.resources.cbor_validation import _decode_single_cbor


class PrivacyConfigResource(resource.Resource):
    """GET /config/privacy: current mode plus whitelist size.

    SECURITY: the individual whitelisted peer identities are the private
    mode's trust root — they are NOT disclosed here (count only). The
    full list is only readable via /config/privacy/allowed with writes
    enabled (i.e. by the authenticated local manager).
    """

    def __init__(self, policy: PositionPrivacyPolicy) -> None:
        super().__init__()
        self._policy = policy

    async def render_get(self, request: Message) -> Message:  # noqa: ARG002
        return _cbor_response(
            {
                "mode": self._policy.mode.value,
                "allowed_peer_count": len(self._policy.allowed_peers),
            }
        )


class PrivacyAllowedPeersResource(resource.Resource):
    """GET/PUT /config/privacy/allowed: the private-mode whitelist.

    SECURITY (spec 17.6.3): whitelist writes are Admin-tier config
    mutations. As with the other /config writers, PUT is rejected 4.01
    unless the caller enables ``allow_writes`` (i.e. the transport layer
    enforces OSCORE/local-admin for this endpoint). GET of the full list
    is likewise gated: it discloses trusted-relationship metadata.
    """

    def __init__(self, policy: PositionPrivacyPolicy, *, allow_writes: bool = False) -> None:
        super().__init__()
        self._policy = policy
        self._allow_writes = allow_writes

    async def render_get(self, request: Message) -> Message:  # noqa: ARG002
        if not self._allow_writes:
            return Message(code=aiocoap.UNAUTHORIZED)
        return _cbor_response({"peers": sorted(self._policy.allowed_peers)})

    async def render_put(self, request: Message) -> Message:
        if not self._allow_writes:
            return Message(code=aiocoap.UNAUTHORIZED)
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(body, dict):
            return Message(code=aiocoap.BAD_REQUEST)
        peers = body.get("peers")
        if not isinstance(peers, list) or not all(
            isinstance(peer, str) and peer for peer in peers
        ):
            return Message(code=aiocoap.BAD_REQUEST)
        self._policy.set_allowed_peers(peers)
        msg = Message(code=aiocoap.CHANGED)
        msg.opt.content_format = CBOR
        msg.payload = cbor2.dumps({"peers": sorted(self._policy.allowed_peers)})
        return msg
