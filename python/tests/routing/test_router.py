"""Tests for hybrid router.

Why these tests: The router is the core decision point for packet forwarding.
Bugs here mean:
- Packets sent to wrong destinations (routing failure)
- External traffic not reaching border router (connectivity failure)
- Mesh traffic not discovered (peer-to-peer failure)
- Link-local traffic mishandled (neighbor communication failure)

Test categories:
1. Address classification
2. Route decisions by address class
3. Gradient table integration
4. Pending packet queue management
5. RPL parent routing
6. LOADng discovery integration
"""

import pytest
from ipaddress import IPv6Address, IPv6Network

from lichen.gradient import GradientEntry, GradientSource, GradientTable
from lichen.routing.router import (
    AddressClass,
    PendingPacket,
    RouteDecision,
    Router,
)
from lichen.ipv6.packet import IPv6Header, IPv6Packet
from lichen.rpl.dodag import DodagRole, DodagState


def make_packet(dst: str, src: str = "fe80::1") -> IPv6Packet:
    """Create a minimal IPv6 packet for testing."""
    return IPv6Packet(
        header=IPv6Header(
            src_addr=IPv6Address(src),
            dst_addr=IPv6Address(dst),
            next_header=17,  # UDP
            payload_length=0,
        ),
        payload=b"",
    )


@pytest.fixture
def gradient_table() -> GradientTable:
    """An empty gradient table."""
    return GradientTable()


@pytest.fixture
def router(gradient_table: GradientTable) -> Router:
    """A router with minimal configuration."""
    return Router(
        node_address=IPv6Address("fd00::1"),
        gradient_table=gradient_table,
    )


class TestAddressClassification:
    """Tests for classify_address()."""

    def test_link_local_fe80(self, router: Router):
        """fe80::x is link-local."""
        # Why test: Link-local is the most common case for neighbor traffic.
        addr = IPv6Address("fe80::1234")
        assert router.classify_address(addr) == AddressClass.LINK_LOCAL

    def test_link_local_fea0(self, router: Router):
        """fea0::x is also link-local (within fe80::/10)."""
        # Why test: fe80::/10 includes fe80:: through febf::.
        addr = IPv6Address("fea0::1")
        assert router.classify_address(addr) == AddressClass.LINK_LOCAL

    def test_ula_is_mesh_local(self, router: Router):
        """fd00::x (ULA) is mesh-local."""
        # Why test: LICHEN meshes typically use ULA for internal addressing.
        addr = IPv6Address("fd00::1234")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

    def test_ula_different_prefix_is_mesh_local(self, router: Router):
        """fdxx::x (any ULA) is mesh-local."""
        # Why test: ULA is fd00::/8, not just fd00::.
        addr = IPv6Address("fdab:cdef::1")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

    def test_gua_without_prefix_is_external(self, router: Router):
        """GUA not in mesh_prefixes is external."""
        # Why test: Unknown GUA should route via border router.
        addr = IPv6Address("2001:db8::1")
        assert router.classify_address(addr) == AddressClass.EXTERNAL

    def test_gua_with_prefix_is_mesh_local(self, router: Router):
        """GUA in mesh_prefixes is mesh-local."""
        # Why test: Border router may assign GUA prefixes to the mesh.
        router.add_mesh_prefix("2001:db8::/32")
        addr = IPv6Address("2001:db8::1")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

    def test_localhost_is_external(self, router: Router):
        """::1 (localhost) is external."""
        # Why test: Localhost shouldn't be routed at all, classified as external.
        addr = IPv6Address("::1")
        assert router.classify_address(addr) == AddressClass.EXTERNAL


class TestLinkLocalRouting:
    """Tests for link-local address routing."""

    def test_link_local_forwards_directly(self, router: Router):
        """Link-local destinations forward directly to the address."""
        # Why test: Link-local = one hop, destination is next hop.
        packet = make_packet("fe80::1234")
        decision, next_hop = router.route(packet, now_ms=0)

        assert decision == RouteDecision.FORWARD
        assert next_hop == IPv6Address("fe80::1234")


class TestMeshLocalRouting:
    """Tests for mesh-local address routing."""

    def test_gradient_found_forwards(self, router: Router, gradient_table: GradientTable):
        """Mesh-local with gradient entry forwards to next_hop."""
        # Why test: The happy path - gradient exists, forward immediately.
        dst = IPv6Address("fd00::beef")
        next_hop = IPv6Address("fe80::1")

        gradient_table.update(GradientEntry(
            destination=dst,
            next_hop=next_hop,
            hop_count=3,
            seq_num=1,
            source=GradientSource.ANNOUNCE,
            expires=10000,
        ))

        packet = make_packet("fd00::beef")
        decision, result_hop = router.route(packet, now_ms=0)

        assert decision == RouteDecision.FORWARD
        assert result_hop == next_hop

    def test_expired_gradient_queues(self, router: Router, gradient_table: GradientTable):
        """Expired gradient entry triggers queue (if LOADng available)."""
        # Why test: Stale routes should not be used; need rediscovery.
        dst = IPv6Address("fd00::beef")

        gradient_table.update(GradientEntry(
            destination=dst,
            next_hop=IPv6Address("fe80::1"),
            hop_count=3,
            seq_num=1,
            source=GradientSource.ANNOUNCE,
            expires=100,  # Already expired at now=1000
        ))

        # Without LOADng, should drop
        packet = make_packet("fd00::beef")
        decision, _ = router.route(packet, now_ms=1000)
        assert decision == RouteDecision.DROP

    def test_no_gradient_without_loadng_drops(self, router: Router):
        """No gradient and no LOADng = drop."""
        # Why test: Can't discover without LOADng.
        packet = make_packet("fd00::beef")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DROP

    def test_no_gradient_with_loadng_queues(self, router: Router, gradient_table: GradientTable):
        """No gradient but LOADng available = queue for discovery."""
        # Why test: LOADng can discover routes on demand.
        from lichen.loadng.discovery import LoadngRouter
        from lichen.loadng.cache import RouteCache

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        packet = make_packet("fd00::beef")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.QUEUE


class TestExternalRouting:
    """Tests for external address routing."""

    def test_external_without_dodag_drops(self, router: Router):
        """External destination without DODAG = drop."""
        # Why test: Can't route external without RPL.
        packet = make_packet("2001:db8::1")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DROP

    def test_external_unjoined_drops(self, router: Router):
        """External destination when not joined to DODAG = drop."""
        # Why test: Must be joined to use RPL parent.
        router.dodag = DodagState(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
            role=DodagRole.UNJOINED,
        )

        packet = make_packet("2001:db8::1")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DROP

    def test_external_no_parent_drops(self, router: Router):
        """External destination when joined but no parent = drop."""
        # Why test: Edge case - joined but lost parent.
        router.dodag = DodagState(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
            role=DodagRole.JOINED,
            preferred_parent=None,  # No parent!
        )

        packet = make_packet("2001:db8::1")
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DROP

    def test_external_with_parent_forwards(self, router: Router):
        """External destination with RPL parent = forward to parent."""
        # Why test: Happy path for external routing.
        router.dodag = DodagState(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
            role=DodagRole.JOINED,
            preferred_parent="fe80::abcd",
        )

        packet = make_packet("2001:db8::1")
        decision, next_hop = router.route(packet, now_ms=0)

        assert decision == RouteDecision.FORWARD
        assert next_hop == IPv6Address("fe80::abcd")


class TestLocalDelivery:
    """Tests for packets addressed to this node."""

    def test_packet_for_self_delivers_local(self, router: Router):
        """Packet to node's own address = deliver local."""
        # Why test: Don't route packets addressed to us.
        packet = make_packet("fd00::1")  # router.node_address
        decision, _ = router.route(packet, now_ms=0)

        assert decision == RouteDecision.DELIVER_LOCAL


class TestPendingQueue:
    """Tests for pending packet queue management."""

    def test_queue_stores_packet(self, router: Router, gradient_table: GradientTable):
        """Queued packets are stored for later forwarding."""
        # Setup LOADng so we queue instead of drop
        from lichen.loadng.discovery import LoadngRouter
        from lichen.loadng.cache import RouteCache

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        dst = IPv6Address("fd00::beef")
        packet = make_packet("fd00::beef")
        router.route(packet, now_ms=0)

        pending = router.get_pending(dst)
        assert len(pending) == 1
        assert pending[0].packet == packet

    def test_queue_limit_drops_oldest(self, router: Router, gradient_table: GradientTable):
        """Queue limit drops oldest packets when exceeded."""
        from lichen.loadng.discovery import LoadngRouter
        from lichen.loadng.cache import RouteCache

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )
        router.max_pending_per_dest = 2

        dst = "fd00::beef"
        p1 = make_packet(dst)
        p2 = make_packet(dst)
        p3 = make_packet(dst)

        router.route(p1, now_ms=0)
        router.route(p2, now_ms=1)
        router.route(p3, now_ms=2)  # Should drop p1

        pending = router.get_pending(IPv6Address(dst))
        assert len(pending) == 2
        # p1 should be gone, p2 and p3 remain
        assert pending[0].packet == p2
        assert pending[1].packet == p3

    def test_clear_pending_removes_all(self, router: Router, gradient_table: GradientTable):
        """clear_pending removes all packets for a destination."""
        from lichen.loadng.discovery import LoadngRouter
        from lichen.loadng.cache import RouteCache

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        dst = IPv6Address("fd00::beef")
        router.route(make_packet("fd00::beef"), now_ms=0)
        router.route(make_packet("fd00::beef"), now_ms=1)

        count = router.clear_pending(dst)
        assert count == 2
        assert router.get_pending(dst) == []

    def test_expire_pending_removes_old(self, router: Router, gradient_table: GradientTable):
        """expire_pending removes packets older than timeout."""
        from lichen.loadng.discovery import LoadngRouter
        from lichen.loadng.cache import RouteCache

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        dst = IPv6Address("fd00::beef")
        router.route(make_packet("fd00::beef"), now_ms=0)
        router.route(make_packet("fd00::beef"), now_ms=100)
        router.route(make_packet("fd00::beef"), now_ms=200)

        # Expire packets older than 150ms
        expired = router.expire_pending(now_ms=300, timeout_ms=150)

        assert expired == 2  # Packets at 0 and 100 expired
        pending = router.get_pending(dst)
        assert len(pending) == 1
        assert pending[0].queued_at_ms == 200

    def test_on_route_discovered_returns_pending(self, router: Router, gradient_table: GradientTable):
        """on_route_discovered returns and clears pending packets."""
        from lichen.loadng.discovery import LoadngRouter
        from lichen.loadng.cache import RouteCache

        router.loadng = LoadngRouter(
            node_address=router.node_address,
            gradient=gradient_table,
            cache=RouteCache(),
        )

        dst = IPv6Address("fd00::beef")
        p1 = make_packet("fd00::beef")
        p2 = make_packet("fd00::beef")
        router.route(p1, now_ms=0)
        router.route(p2, now_ms=1)

        # Discovery completes
        pending = router.on_route_discovered(
            dst, IPv6Address("fe80::1234"), now_ms=100
        )

        assert len(pending) == 2
        assert router.get_pending(dst) == []  # Cleared


class TestMeshPrefixManagement:
    """Tests for mesh prefix add/remove."""

    def test_add_prefix_makes_gua_mesh_local(self, router: Router):
        """Adding a prefix makes addresses in it mesh-local."""
        addr = IPv6Address("2001:db8:1234::5678")
        assert router.classify_address(addr) == AddressClass.EXTERNAL

        router.add_mesh_prefix("2001:db8::/32")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

    def test_remove_prefix_makes_gua_external(self, router: Router):
        """Removing a prefix makes addresses external again."""
        router.add_mesh_prefix("2001:db8::/32")
        addr = IPv6Address("2001:db8:1234::5678")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL

        router.remove_mesh_prefix("2001:db8::/32")
        assert router.classify_address(addr) == AddressClass.EXTERNAL

    def test_add_prefix_string_form(self, router: Router):
        """add_mesh_prefix accepts string form."""
        router.add_mesh_prefix("2001:db8::/48")
        addr = IPv6Address("2001:db8::1")
        assert router.classify_address(addr) == AddressClass.MESH_LOCAL


class TestRootNode:
    """Tests for border router (root) behavior."""

    def test_root_can_route_external(self, router: Router):
        """Root node routes external via preferred_parent (self)."""
        # Why test: Root may have different routing behavior.
        # For now, root still uses parent (which might be upstream gateway).
        router.dodag = DodagState.as_root(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
        )
        # Root needs a parent (upstream gateway) to route external
        router.dodag = DodagState(
            rpl_instance_id=1,
            dodag_id="fd00::1",
            version=1,
            role=DodagRole.ROOT,
            preferred_parent="fe80::aaaa",  # Upstream gateway
        )

        packet = make_packet("2001:db8::1")
        decision, next_hop = router.route(packet, now_ms=0)

        assert decision == RouteDecision.FORWARD
        assert next_hop == IPv6Address("fe80::aaaa")
