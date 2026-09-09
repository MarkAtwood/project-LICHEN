# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""UDP CoAP server binding for LICHEN nodes.

Exposes a Node's CoAP resources (/status, /neighbors, /config) on a real
UDP port so external tools (like the Rust TUI) can query simulated nodes
the same way they query real hardware.

Usage:
    node = Node(identity, radio)
    await node.start()
    ctx = await bind_coap_udp(node, port=5683)
    # ... node is now queryable via coap://[::1]:5683/status
    await ctx.shutdown()
"""
# ponytail: thin wrapper, aiocoap does the heavy lifting

from __future__ import annotations

from typing import Any

import aiocoap

from lichen.coap.resources import SosResource, build_site


async def bind_coap_udp(
    node: Any,
    port: int = 5683,
    bind: str = "::1",
    *,
    config_allow_writes: bool = False,
    sos_resource: SosResource | None = None,
    multicast_interface: str | None = None,
) -> aiocoap.Context:
    """Bind a Node's CoAP resources to a real UDP port.

    Args:
        node: A Node instance implementing get_status/get_neighbors/get_config.
        port: UDP port to bind (default 5683).
        bind: Address to bind (default "::1" for localhost).
        config_allow_writes: Explicitly permit PUT requests to /config.
        sos_resource: Optional :class:`SosResource` held by caller for
            programmatic control (activate, cancel, retrigger).
        multicast_interface: Optional OS interface name (e.g. "eth0") on which
            to join the all-nodes multicast group ff02::1 (R-12-036). aiocoap
            joins the 'all CoAP nodes' + 'all nodes' groups for the interface,
            and routes requests by Uri-Path (not dst address), so /sos becomes
            reachable at coap://[ff02::1%<iface>]/sos exactly as at unicast —
            an unpaired node in distress can POST SOS without a unicast address.
            Joining ff02::1 on a wildcard ("::") bind is the only arrangement
            aiocoap supports; pass bind="::" alongside.

    Returns:
        An aiocoap.Context that must be shutdown() when done.
    """
    site = build_site(node, config_allow_writes=config_allow_writes, sos_resource=sos_resource)
    # ponytail: aiocoap wants explicit address, not "::"
    context = await aiocoap.Context.create_server_context(
        site,
        bind=(bind, port),
        # Interface-name shortcut: aiocoap joins that interface's all-nodes
        # (ff02::1/ff05::1) and all-CoAP-nodes (ff02::fd/ff05::fd) groups.
        multicast=[multicast_interface] if multicast_interface is not None else [],
    )
    return context
