"""LICHEN hybrid routing (spec section 7).

Three-tier routing architecture:
1. RPL: Border router traffic (upward/downward tree)
2. Announce: Peer-to-peer with active nodes (proactive gradient)
3. LOADng: Peer-to-peer fallback (reactive discovery)

The Router class decides which tier to use based on address classification.
"""

from lichen.routing.router import (
    AddressClass,
    PendingPacket,
    RouteDecision,
    Router,
    RoutingError,
)

__all__ = [
    "AddressClass",
    "PendingPacket",
    "RouteDecision",
    "Router",
    "RoutingError",
]
