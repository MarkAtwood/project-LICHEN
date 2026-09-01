# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP resource for root tunnel authorizations (spec/06-security.md 727-807).

POST ``/.well-known/tunnel-auth`` with a COSE_Sign1 tunnel authorization.
The egress caches it via :class:`lichen.gateway.tunnel_auth.TunnelAuthorizationTable`
(fail closed) and later consults the same table on the data path
(``authorize_decapsulation``). Denials are uniformly 4.03 Forbidden — the
internal :class:`lichen.gateway.tunnel_auth.TunnelDenial` category never
leaks onto the wire.
"""

from __future__ import annotations

import logging
import time
from ipaddress import IPv6Address

from aiocoap import CHANGED, FORBIDDEN, METHOD_NOT_ALLOWED, Message, resource

from lichen.gateway.tunnel_auth import (
    TUNNEL_AUTH_RESOURCE,
    TunnelAuthorizationTable,
)

logger = logging.getLogger(__name__)

__all__ = ["TUNNEL_AUTH_PATH", "TunnelAuthResource"]

#: Path segments for site mounting (mirrors TUNNEL_AUTH_RESOURCE).
TUNNEL_AUTH_PATH: tuple[str, ...] = tuple(TUNNEL_AUTH_RESOURCE.lstrip("/").split("/"))


class TunnelAuthResource(resource.Resource):
    """POST /.well-known/tunnel-auth — root-signed egress authorization.

    The POST must arrive over OSCORE from the configured root identity; the
    table's ``receive_post`` validates the COSE_Sign1, the root binding, the
    egress binding, the horizon, and replay state atomically.
    """

    def __init__(self, authorizations: TunnelAuthorizationTable) -> None:
        super().__init__()
        self._authorizations = authorizations

    def get_link_description(self) -> dict[str, str]:
        return {"rt": "tunnel-auth"}

    async def render_post(self, request: Message) -> Message:
        """Cache a root-signed tunnel authorization.

        Denials return 4.03 uniformly; only the log carries the category.
        """
        if not request.payload:
            return Message(code=FORBIDDEN)

        authenticated, sender_iid = _oscore_sender(request)
        if not authenticated:
            return Message(code=FORBIDDEN)

        result = self._authorizations.receive_post(
            request.payload,
            oscore_authenticated=True,
            oscore_sender_iid=sender_iid,
            now=_now_seconds(),
        )
        if result.allowed:
            return Message(code=CHANGED)
        logger.info(
            "tunnel-auth POST denied (%s) from %s",
            result.denial,
            request.remote,
        )
        return Message(code=FORBIDDEN)

    async def render_get(self, request: Message) -> Message:
        return Message(code=METHOD_NOT_ALLOWED)

    async def render_put(self, request: Message) -> Message:
        return Message(code=METHOD_NOT_ALLOWED)

    async def render_delete(self, request: Message) -> Message:
        return Message(code=METHOD_NOT_ALLOWED)


def _oscore_sender(request: Message) -> tuple[bool, bytes]:
    """Return ``(is_oscore_authenticated, sender_iid)`` for the request.

    Only OSCORE bindings attached after successful unprotect count (the same
    post-unprotect rule as the messaging resource); the sender IID comes from
    the transport-bound remote address when present.
    """
    from lichen.coap.resources.messaging import _request_is_oscore_protected

    if not _request_is_oscore_protected(request):
        return False, b""
    remote = getattr(request, "remote", None)
    hostinfo = getattr(remote, "hostinfo", "") if remote is not None else ""
    if not isinstance(hostinfo, str) or not hostinfo:
        return False, b""
    # hostinfo is "[v6]:port" for UDP remotes; extract the address.
    host = hostinfo.rsplit("]", 1)[0].lstrip("[") if "]" in hostinfo else hostinfo
    try:
        address = IPv6Address(host)
    except ValueError:
        return False, b""
    return True, address.packed[8:]


def _now_seconds() -> int:
    return int(time.time())
