"""Hybrid routing decision logic (spec section 7.2).

The Router decides how to forward each packet based on destination address:
1. Link-local (fe80::/10): Direct neighbor delivery
2. Mesh-local (ULA or mesh GUA): Gradient lookup → LOADng discovery
3. External: Forward to RPL parent toward border router

Why separate Router from LOADng/RPL: Each protocol has its own state machine.
The Router orchestrates them based on address classification and route availability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv6Address, IPv6Network
from typing import Callable

from lichen.gradient import GradientEntry, GradientTable
from lichen.ipv6.packet import IPv6Packet
from lichen.loadng.discovery import LoadngRouter
from lichen.rpl.dodag import DodagState

logger = logging.getLogger(__name__)


class RoutingError(Exception):
    """Raised on routing failures that shouldn't happen."""


class AddressClass(Enum):
    """Classification of IPv6 destination address (spec 7.2).

    Why classify: Different address types require different routing strategies.
    Link-local goes directly to neighbor. Mesh-local uses gradient/LOADng.
    External routes through the border router via RPL.
    """

    LINK_LOCAL = auto()  # fe80::/10 - direct neighbor
    MESH_LOCAL = auto()  # ULA or mesh GUA - peer in mesh
    EXTERNAL = auto()    # Other GUA or unknown - route via border router


class RouteDecision(Enum):
    """What to do with a packet after routing decision.

    Why explicit enum: Callers need to know what action to take, and the
    decision may require additional state (queued packet, discovery request).
    """

    FORWARD = auto()      # Forward to next_hop now
    QUEUE = auto()        # Queue pending LOADng discovery
    DROP = auto()         # No route, cannot discover (unjoined, etc.)
    DELIVER_LOCAL = auto()  # Packet is for this node


@dataclass
class PendingPacket:
    """A packet queued pending route discovery.

    Why track: When LOADng discovery completes, we need to forward the
    original packet. Also for timeouts and queue management.

    Attributes:
        packet: The queued IPv6 packet.
        destination: The address we're discovering a route to.
        queued_at_ms: Timestamp when queued (for timeout).
    """

    packet: IPv6Packet
    destination: IPv6Address
    queued_at_ms: int


@dataclass
class Router:
    """Hybrid routing decision engine (spec 7.2).

    Why a class: Needs state across invocations:
    - gradient_table: Where to look up routes
    - dodag: RPL state for parent selection
    - loadng: LOADng router for discovery
    - pending_queue: Packets waiting for discovery
    - mesh_prefixes: Which prefixes are "in the mesh"

    Attributes:
        node_address: This node's IPv6 address.
        gradient_table: Unified routing table (spec section 11).
        dodag: RPL DODAG state for upward routing.
        loadng: LOADng router for reactive discovery.
        mesh_prefixes: Set of IPv6 prefixes that are "mesh-local".
            Why a set: Nodes may be part of multiple prefixes (ULA + GUA).
        pending_queue: Packets waiting for route discovery.
            Why dict by destination: Multiple packets may be queued for same dest.
        max_pending_per_dest: Max packets to queue per destination.
            Why limit: Prevent memory exhaustion during discovery.
    """

    node_address: IPv6Address
    gradient_table: GradientTable
    dodag: DodagState | None = None
    loadng: LoadngRouter | None = None
    mesh_prefixes: set[IPv6Network] = field(default_factory=set)
    pending_queue: dict[IPv6Address, list[PendingPacket]] = field(
        default_factory=dict, repr=False
    )
    max_pending_per_dest: int = 3

    # Why fe80::/10: RFC 4291 link-local prefix. All link-local addresses
    # start with fe80:: through febf::, which is fe80::/10.
    _LINK_LOCAL_PREFIX = IPv6Network("fe80::/10")

    # Why fd00::/8: RFC 4193 ULA prefix. LICHEN meshes typically use ULA.
    _ULA_PREFIX = IPv6Network("fd00::/8")

    def classify_address(self, addr: IPv6Address) -> AddressClass:
        """Classify an IPv6 destination address (spec 7.2 table).

        Why this order:
        1. Link-local check first: Most specific, cheap to check
        2. Mesh-local next: ULA or configured GUA prefixes
        3. External fallback: Everything else

        Args:
            addr: Destination IPv6 address.

        Returns:
            AddressClass indicating how to route.
        """
        # Why check link-local first: It's the most specific and common case
        # for neighbor discovery, etc.
        if addr in self._LINK_LOCAL_PREFIX:
            return AddressClass.LINK_LOCAL

        # Why check ULA: LICHEN meshes typically use fd00::/8 ULA prefixes
        # for mesh-internal addressing.
        if addr in self._ULA_PREFIX:
            return AddressClass.MESH_LOCAL

        # Why check mesh_prefixes: GUA prefixes from DIO/border router
        # should be routed as mesh-local.
        for prefix in self.mesh_prefixes:
            if addr in prefix:
                return AddressClass.MESH_LOCAL

        # Why external: Everything else goes to the border router.
        return AddressClass.EXTERNAL

    def route(
        self,
        packet: IPv6Packet,
        now_ms: int,
    ) -> tuple[RouteDecision, IPv6Address | None]:
        """Make a routing decision for a packet (spec 7.2 pseudocode).

        Why return tuple: Callers need both the decision (what to do) and
        the next hop (where to send it).

        Args:
            packet: IPv6 packet to route.
            now_ms: Current time in milliseconds.

        Returns:
            (decision, next_hop) tuple. next_hop is None for QUEUE/DROP/DELIVER_LOCAL.
        """
        dst = packet.header.dst_addr

        # Why check for local first: Don't route packets addressed to us.
        if dst == self.node_address:
            return RouteDecision.DELIVER_LOCAL, None

        addr_class = self.classify_address(dst)
        logger.debug("routing %s: class=%s", dst, addr_class.name)

        if addr_class == AddressClass.LINK_LOCAL:
            return self._route_link_local(dst)

        if addr_class == AddressClass.MESH_LOCAL:
            return self._route_mesh_local(packet, dst, now_ms)

        # External: route via RPL parent
        return self._route_external()

    def _route_link_local(
        self, dst: IPv6Address
    ) -> tuple[RouteDecision, IPv6Address | None]:
        """Route to a link-local address (direct neighbor).

        Why no lookup: Link-local addresses are by definition one hop away.
        The destination IS the next hop.
        """
        return RouteDecision.FORWARD, dst

    def _route_mesh_local(
        self,
        packet: IPv6Packet,
        dst: IPv6Address,
        now_ms: int,
    ) -> tuple[RouteDecision, IPv6Address | None]:
        """Route to a mesh-local address (ULA or mesh GUA).

        Strategy (spec 7.2):
        1. Check gradient table for existing route
        2. If found and not expired, forward
        3. If not found, initiate LOADng discovery and queue packet
        """
        # Why lookup with now: Expired entries should not be used.
        entry = self.gradient_table.lookup(dst, now=now_ms)

        if entry is not None:
            logger.debug("gradient found for %s: via %s, %d hops",
                        dst, entry.next_hop, entry.hop_count)
            return RouteDecision.FORWARD, entry.next_hop

        # Why check loadng: If LOADng isn't configured, we can't discover.
        if self.loadng is None:
            logger.warning("no gradient for %s and LOADng not configured", dst)
            return RouteDecision.DROP, None

        # Initiate discovery and queue packet
        logger.debug("no gradient for %s, initiating LOADng discovery", dst)
        self._queue_pending(packet, dst, now_ms)

        return RouteDecision.QUEUE, None

    def _route_external(self) -> tuple[RouteDecision, IPv6Address | None]:
        """Route to an external address (via RPL border router).

        Why RPL parent: External traffic goes "up" the DODAG tree to the
        border router, which has connectivity to the wider network.
        """
        if self.dodag is None:
            logger.warning("no DODAG state, cannot route external")
            return RouteDecision.DROP, None

        if not self.dodag.is_joined():
            logger.warning("not joined to DODAG, cannot route external")
            return RouteDecision.DROP, None

        parent = self.dodag.preferred_parent
        if parent is None:
            logger.warning("no preferred parent, cannot route external")
            return RouteDecision.DROP, None

        # Why parse as IPv6Address: preferred_parent is stored as string
        # in DodagState for flexibility, but we need an address here.
        try:
            next_hop = IPv6Address(parent)
        except ValueError:
            logger.error("invalid preferred_parent address: %s", parent)
            return RouteDecision.DROP, None

        return RouteDecision.FORWARD, next_hop

    def _queue_pending(
        self,
        packet: IPv6Packet,
        dst: IPv6Address,
        now_ms: int,
    ) -> None:
        """Queue a packet pending route discovery.

        Why queue: During LOADng discovery, packets should be held rather
        than dropped. When discovery succeeds, queued packets are forwarded.
        """
        pending = PendingPacket(
            packet=packet,
            destination=dst,
            queued_at_ms=now_ms,
        )

        queue = self.pending_queue.setdefault(dst, [])

        # Why limit: Prevent memory exhaustion during slow discovery.
        if len(queue) >= self.max_pending_per_dest:
            # Drop oldest packet
            dropped = queue.pop(0)
            logger.debug("pending queue full for %s, dropped oldest", dst)

        queue.append(pending)
        logger.debug("queued packet for %s, queue depth=%d", dst, len(queue))

    def get_pending(self, dst: IPv6Address) -> list[PendingPacket]:
        """Get all pending packets for a destination.

        Why separate method: Called when discovery succeeds to retrieve
        packets that can now be forwarded.

        Returns:
            List of pending packets (may be empty).
        """
        return list(self.pending_queue.get(dst, []))

    def clear_pending(self, dst: IPv6Address) -> int:
        """Clear pending packets for a destination.

        Why: Called after forwarding or after timeout to clean up.

        Returns:
            Number of packets cleared.
        """
        queue = self.pending_queue.pop(dst, [])
        return len(queue)

    def expire_pending(self, now_ms: int, timeout_ms: int) -> int:
        """Remove pending packets older than timeout.

        Why: Packets shouldn't be queued forever. If discovery fails or
        takes too long, drop the packets.

        Returns:
            Number of packets expired.
        """
        expired_count = 0
        cutoff = now_ms - timeout_ms

        # Why iterate copy: We're modifying the dict during iteration.
        for dst in list(self.pending_queue.keys()):
            queue = self.pending_queue[dst]
            original_len = len(queue)
            queue[:] = [p for p in queue if p.queued_at_ms > cutoff]
            expired_count += original_len - len(queue)

            if not queue:
                del self.pending_queue[dst]

        if expired_count > 0:
            logger.debug("expired %d pending packets", expired_count)

        return expired_count

    def add_mesh_prefix(self, prefix: IPv6Network | str) -> None:
        """Add a prefix to the set of mesh-local prefixes.

        Why: Prefixes learned from DIO or configuration should be added
        so addresses within them are classified as mesh-local.
        """
        if isinstance(prefix, str):
            prefix = IPv6Network(prefix)
        self.mesh_prefixes.add(prefix)

    def remove_mesh_prefix(self, prefix: IPv6Network | str) -> None:
        """Remove a prefix from mesh-local prefixes."""
        if isinstance(prefix, str):
            prefix = IPv6Network(prefix)
        self.mesh_prefixes.discard(prefix)

    def on_route_discovered(
        self, dst: IPv6Address, next_hop: IPv6Address, now_ms: int
    ) -> list[PendingPacket]:
        """Called when LOADng discovers a route.

        Why a callback: The Router owns the pending queue. When discovery
        succeeds, it needs to return the queued packets for forwarding.

        Returns:
            List of pending packets that can now be forwarded.
        """
        pending = self.get_pending(dst)
        self.clear_pending(dst)
        logger.debug("route discovered for %s, releasing %d pending packets",
                    dst, len(pending))
        return pending
