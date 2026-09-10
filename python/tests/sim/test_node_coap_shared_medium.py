# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""oa51.3 infrastructure baseline: real Nodes over the shared radio medium.

Routes are seeded diagnostically; this does not establish autonomous route
formation or completion of the messaging milestone. Peer admission uses signed
DIOs sent over SimRadio, and the application exchange uses real L2 and SCHC.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack, suppress
from ipaddress import IPv6Address

import aiocoap
import pytest
from aiocoap import GET, Message, resource
from lora_medium import ChaosEngine, PartitionRule, PropagationModel

from lichen.coap.node_channel import NodeChannel
from lichen.coap.transport import create_lichen_context
from lichen.crypto.identity import Identity, PeerIdentity, yggdrasil_address
from lichen.ipv6.packet import IPv6Packet
from lichen.ipv6.udp import UdpDatagram
from lichen.l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body
from lichen.link.frame import LichenFrame
from lichen.link.link_layer import RxFrame
from lichen.node import Node, NodeConfig
from lichen.radio.sim_client import SimRadio
from lichen.schc.headers import decompress_packet
from lichen.sim.node import NodeState
from lichen.sim.node_server import NodeServer
from lichen.sim.simulation import Simulation
from tests.sim.test_observer import RecordingObserver
from tests.test_node_coap_integration import _dio_schc_payload, _seed_gradient, _Status


@pytest.mark.asyncio
async def test_coap_get_via_shared_medium_relay() -> None:
    """Capture GET /status at A and correlate A-B-C / C-B-A radio deliveries."""
    chaos = ChaosEngine()
    chaos.add_rule(PartitionRule(groups=[{"A"}, {"C"}]))
    sim = Simulation("node-coap-baseline", chaos_engine=chaos, seed=0)
    sim.medium.propagation = PropagationModel(shadow_std_db=0, fading_std_db=0)

    class WireObserver(RecordingObserver):
        def on_tx_start(self, **event) -> None:
            transmission = next(
                tx
                for tx in sim.medium.get_active_transmissions(event["time_us"])
                if tx.id == event["tx_id"]
            )
            super().on_tx_start(**event, wire=transmission.payload)

    ledger = WireObserver()
    sim.add_observer(ledger)
    server = NodeServer(sim)
    handlers: list[asyncio.Task[None]] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        handlers.append(task)
        await server.handle_connection(reader, writer)

    async def bounded_close(close) -> None:
        await asyncio.wait_for(close(), timeout=2)

    listener = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    try:
        async with AsyncExitStack() as stack:
            identities = [Identity.from_seed(bytes([i]) + bytes(31)) for i in range(3)]
            nodes: list[Node] = []
            for name, x, identity in zip("ABC", (0, 24_000, 48_000), identities, strict=True):
                radio = SimRadio("127.0.0.1", port, sim.id, name, (x, 0, 0))
                stack.push_async_callback(bounded_close, radio.close)
                await asyncio.wait_for(radio.connect(), timeout=2)
                radio.configure(915_000_000, 22)
                sim_node = sim.get_node(name)
                assert sim_node is not None
                sim_node.hop_schedule = (0,)
                nodes.append(
                    Node(
                        identity,
                        radio,
                        config=NodeConfig(
                            receive_timeout_ms=1000,
                            announce_interval_ms=300_000,
                            announce_jitter_ms=0,
                            rpl_instance_id=0,
                            rpl_dodag_id=IPv6Address("fe80::1"),
                            rpl_dio_expected_role="peer",
                        ),
                    )
                )

            for local, remote in ((0, 1), (1, 0), (1, 2), (2, 1)):
                nodes[local].add_peer(PeerIdentity.from_pubkey(identities[remote].pubkey))

            # Receive through the real link verifier before Node dispatch admits
            # SCHC policy. Barrier timeouts can precede TCP TX arrival, so re-arm.
            async def receive_dio(node: Node) -> None:
                while (frame := await node.link.receive(1000)) is None:
                    pass
                assert isinstance(frame, RxFrame)
                await node._process_received(frame)

            for sender in range(3):
                receivers = [i for i in range(3) if abs(i - sender) == 1]
                tasks = [asyncio.create_task(receive_dio(nodes[i])) for i in receivers]
                try:
                    async with asyncio.timeout(5):
                        while not all(
                            sim.get_node("ABC"[i]).state == NodeState.RX_WAIT for i in receivers
                        ):
                            await asyncio.sleep(0)
                        assert await nodes[sender].link.send(_dio_schc_payload(identities[sender]))
                        await asyncio.gather(*tasks)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True), timeout=2
                    )

            # Diagnostic routes only; authenticated admission above is not seeded.
            native_a, _, native_c = [yggdrasil_address(i.pubkey) for i in identities]
            now_ms = int(asyncio.get_running_loop().time() * 1000)
            for local, destination, via, hops in (
                (0, native_c, 1, 2),
                (1, native_c, 2, 1),
                (2, native_a, 1, 2),
                (1, native_a, 0, 1),
            ):
                _seed_gradient(
                    nodes[local].gradient_table, destination, identities[via].iid, hops, now_ms
                )

            site = resource.Site()
            site.add_resource(["status"], _Status())
            # Register node cleanup before contexts so contexts shut down first.
            for node in nodes:
                stack.push_async_callback(bounded_close, node.stop)
            ctx_c = await asyncio.wait_for(
                create_lichen_context(
                    NodeChannel(nodes[2], str(native_c)), str(native_c), site=site
                ),
                timeout=2,
            )
            stack.push_async_callback(bounded_close, ctx_c.shutdown)
            ctx_a = await asyncio.wait_for(
                create_lichen_context(NodeChannel(nodes[0], str(native_a)), str(native_a)),
                timeout=2,
            )
            stack.push_async_callback(bounded_close, ctx_a.shutdown)
            for node in nodes:
                await asyncio.wait_for(node.start(), timeout=2)

            exchange_start = len(ledger.events)
            response = await asyncio.wait_for(
                ctx_a.request(Message(code=GET, uri=f"coap://[{native_c}]/status")).response,
                timeout=15,
            )
            assert response.code == aiocoap.CONTENT
            assert response.payload == b"ok"

            tx = {e["tx_id"]: e["node_id"] for kind, e in ledger.events if kind == "tx_start"}
            deliveries = [e for kind, e in ledger.events if kind == "rx_success"]
            assert deliveries
            assert all(tx[e["tx_id"]] == e["from_node_id"] for e in deliveries)
            assert not any({e["from_node_id"], e["node_id"]} == {"A", "C"} for e in deliveries)
            codes = {}
            for kind, event in ledger.events[exchange_start:]:
                if kind != "tx_start":
                    continue
                frame = LichenFrame.from_bytes(event["wire"])
                assert frame.signature_present
                assert classify_l2_payload(frame.payload) == L2PayloadKind.SCHC
                packet = IPv6Packet.from_bytes(decompress_packet(l2_payload_body(frame.payload)))
                message = Message.decode(UdpDatagram.from_bytes(packet.payload).payload)
                assert message.token == response.token
                codes[event["tx_id"]] = message.code
            for code, expected in (
                (GET, {("A", "B"), ("B", "C")}),
                (aiocoap.CONTENT, {("C", "B"), ("B", "A")}),
            ):
                edges = {
                    (e["from_node_id"], e["node_id"])
                    for kind, e in ledger.events[exchange_start:]
                    if kind == "rx_success" and codes.get(e["tx_id"]) == code
                }
                assert expected <= edges
    finally:
        listener.close()
        await asyncio.wait_for(listener.wait_closed(), timeout=2)
        try:
            await asyncio.wait_for(asyncio.gather(*handlers), timeout=2)
        finally:
            if server._sim_driver_task is not None:
                server._sim_driver_task.cancel()
                with suppress(asyncio.CancelledError):
                    await asyncio.wait_for(server._sim_driver_task, timeout=2)
