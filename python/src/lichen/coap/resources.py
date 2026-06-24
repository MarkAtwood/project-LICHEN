# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP resources for a LICHEN node (spec section 7, RFC 6690).

Exposes ``/.well-known/core`` (resource discovery), ``/status``, ``/neighbors``,
and ``/config``. Payloads use CBOR (content-format 60), the compact encoding
appropriate for constrained LoRa links.

Also provides :class:`ProxyResource` — a forward proxy (RFC 7252 §5.7) that
lets a local client reach any mesh node by passing a ``Proxy-Uri`` option.

Because the integrated Node class does not exist yet, the local resources read
from an injected :class:`NodeInfo` provider rather than a live node; swap in
a node-backed provider once it lands.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol

import aiocoap
import cbor2
from aiocoap import BAD_GATEWAY, BAD_REQUEST, CHANGED, CONTENT, Message, resource
from aiocoap.numbers import ContentFormat

CBOR = ContentFormat.CBOR


class NodeInfo(Protocol):
    """Data source backing the CoAP resources."""

    def get_status(self) -> dict[str, Any]: ...
    def get_neighbors(self) -> list[dict[str, Any]]: ...
    def get_config(self) -> dict[str, Any]: ...
    def set_config(self, updates: dict[str, Any]) -> None: ...


@dataclass
class StaticNodeInfo:
    """A simple in-memory :class:`NodeInfo` for tests and single-node sims."""

    status: dict[str, Any] = field(default_factory=dict)
    neighbors: list[dict[str, Any]] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    def get_status(self) -> dict[str, Any]:
        return dict(self.status)

    def get_neighbors(self) -> list[dict[str, Any]]:
        return [dict(n) for n in self.neighbors]

    def get_config(self) -> dict[str, Any]:
        return dict(self.config)

    def set_config(self, updates: dict[str, Any]) -> None:
        self.config.update(updates)


def _cbor_response(value: Any) -> Message:
    msg = Message(code=CONTENT, payload=cbor2.dumps(value))
    msg.opt.content_format = CBOR
    return msg


class _ReadResource(resource.Resource):
    """A read-only CBOR resource advertising a resource type."""

    rt = "lichen"

    def __init__(self, node_info: NodeInfo) -> None:
        super().__init__()
        self.node_info = node_info

    def get_link_description(self) -> dict[str, Any]:
        # Link-format attribute values are strings (RFC 6690).
        return {"rt": self.rt, "ct": str(int(CBOR))}


class StatusResource(_ReadResource):
    """``/status`` — node status (uptime, rank, parent, battery, ...)."""

    rt = "lichen.status"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_status())


class NeighborsResource(_ReadResource):
    """``/neighbors`` — the neighbour table."""

    rt = "lichen.neighbors"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_neighbors())


class ConfigResource(_ReadResource):
    """``/config`` — node configuration (GET to read, PUT to update)."""

    rt = "lichen.config"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_config())

    async def render_put(self, request: Message) -> Message:
        updates = cbor2.loads(request.payload) if request.payload else {}
        if not isinstance(updates, dict):
            return Message(code=CHANGED)  # ignore non-object bodies
        self.node_info.set_config(updates)
        return Message(code=CHANGED)


class ProxyResource(resource.Resource):
    """CoAP forward proxy — relays requests with Proxy-Uri into the mesh.

    A local client (phone, desktop) sends a request to ``/proxy`` on the
    gateway with a ``Proxy-Uri`` option naming the target mesh node::

        GET coap://[gateway]/proxy
        Proxy-Uri: coap://[fd00::2]/status

    The gateway forwards the request via its mesh-side aiocoap context and
    relays the response — including any CoAP error codes from the target.
    The ``mesh_ctx`` must be a context whose transport can route to mesh nodes
    (e.g. a :class:`~lichen.coap.transport.LichenTransport` backed by a
    :class:`~lichen.coap.node_channel.NodeChannel`).

    Per RFC 7252 §5.7, the Proxy-Uri option is stripped before forwarding.
    """

    def __init__(self, mesh_ctx: aiocoap.Context, *, timeout: float = 30.0) -> None:
        super().__init__()
        self._mesh_ctx = mesh_ctx
        self._timeout = timeout

    async def render(self, request: Message) -> Message:
        target = request.opt.proxy_uri
        if not target:
            return Message(code=BAD_REQUEST)

        fwd = Message(code=request.code, uri=target, payload=request.payload)
        if request.opt.content_format is not None:
            fwd.opt.content_format = request.opt.content_format

        try:
            response = await asyncio.wait_for(
                self._mesh_ctx.request(fwd).response,
                timeout=self._timeout,
            )
        except Exception:
            return Message(code=BAD_GATEWAY)

        relay = Message(code=response.code, payload=response.payload)
        if response.opt.content_format is not None:
            relay.opt.content_format = response.opt.content_format
        return relay


def build_site(
    node_info: NodeInfo,
    *,
    mesh_client: aiocoap.Context | None = None,
) -> resource.Site:
    """Build an aiocoap Site exposing the LICHEN node resources.

    Pass ``mesh_client`` to also expose a forward proxy at ``/proxy``
    that routes requests with ``Proxy-Uri`` into the mesh.
    """
    site = resource.Site()
    site.add_resource(
        [".well-known", "core"],
        resource.WKCResource(site.get_resources_as_linkheader),
    )
    site.add_resource(["status"], StatusResource(node_info))
    site.add_resource(["neighbors"], NeighborsResource(node_info))
    site.add_resource(["config"], ConfigResource(node_info))
    if mesh_client is not None:
        site.add_resource(["proxy"], ProxyResource(mesh_client))
    return site
