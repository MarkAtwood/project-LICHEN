# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for packet correlation IDs (pkt_id) through the RX/TX pipeline.

Covers bead gy32.1.2: (1) pkt_id increments on each receive, (2) pkt_id is
present in the receive return, (3) forwarded packets log both in_pkt_id
(inbound correlation id) and pkt_id (new outbound correlation id).
"""

import logging
import re
from ipaddress import IPv6Address

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.crypto.schnorr48 import sign
from lichen.ipv6.addr import iid_to_eui64
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader
from lichen.l2_payload import wrap_schc_payload
from lichen.link.frame import LINK_SIGNATURE_DOMAIN, LichenFrame
from lichen.link.frames import RxFrame
from lichen.link.link_layer import LinkLayer
from lichen.node import Node, NodeConfig
from lichen.routing.router import RouteDecision

_MAX_U32 = 0xFFFFFFFF


class MockRadio:
    """Minimal mock radio: queued RX frames, always-clear CAD."""

    def __init__(self):
        self.rx_queue: list[tuple[bytes, int, int]] = []
        self.tx_history: list[bytes] = []

    async def transmit(self, payload: bytes, channel: int = 0) -> bool:
        self.tx_history.append(payload)
        return True

    async def receive(self, timeout_ms: int, channel: int = 0) -> tuple[bytes, int, int] | None:
        if self.rx_queue:
            return self.rx_queue.pop(0)
        return None

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        pass

    async def cad(self, timeout_ms: int, channel: int = 0) -> bool:
        return False

    def queue_rx(self, data: bytes, rssi: int = -50, snr: int = 10) -> None:
        self.rx_queue.append((data, rssi, snr))


def _signed_broadcast_wire(identity: Identity, seqnum: int) -> bytes:
    """Build one valid signed broadcast frame with an explicit sequence number."""
    signer_eui64 = iid_to_eui64(identity.iid)
    payload = b"correlation-test"
    length = 4 + len(signer_eui64) + len(payload) + 48
    transcript = (
        LINK_SIGNATURE_DOMAIN
        + bytes((length, 0xA0, seqnum >> 16))
        + (seqnum & 0xFFFF).to_bytes(2, "big")
        + b"\x00"
        + signer_eui64
        + payload
    )
    signature = sign(identity.privkey, identity.pubkey, transcript)
    return LichenFrame(
        epoch=seqnum >> 16,
        seqnum=seqnum & 0xFFFF,
        dst_addr=b"",
        payload=payload,
        mic=signature,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()


def _verified_rx(payload: bytes, peer: PeerIdentity, pkt_id: int) -> RxFrame:
    """Hand-build an RxFrame fixture with an explicit inbound correlation id."""
    value = object.__new__(RxFrame)
    object.__setattr__(value, "sender", peer)
    object.__setattr__(value, "rssi_dbm", -90)
    object.__setattr__(value, "snr_db", 4)
    object.__setattr__(value, "_authenticated_payload", payload)
    object.__setattr__(value, "_authenticated_sender_pubkey", peer.pubkey)
    object.__setattr__(value, "_authenticated_pkt_id", pkt_id)
    return value


@pytest.fixture
def link_identity() -> Identity:
    return Identity.from_seed(bytes(32))


@pytest.fixture
def peer_identity() -> Identity:
    return Identity.from_seed(bytes([1] + [0] * 31))


@pytest.fixture
def mock_radio() -> MockRadio:
    return MockRadio()


@pytest.fixture
def link_layer(
    mock_radio: MockRadio,
    link_identity: Identity,
    peer_identity: Identity,
) -> LinkLayer:
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)

    def peer_lookup(_hint: bytes) -> PeerIdentity | None:
        return peer

    def peer_lookup_all() -> list[PeerIdentity]:
        return [peer]

    return LinkLayer(
        radio=mock_radio,
        identity=link_identity,
        peer_lookup=peer_lookup,
        peer_lookup_all=peer_lookup_all,
    )


@pytest.fixture
def node(link_identity: Identity, mock_radio: MockRadio) -> Node:
    return Node(
        identity=link_identity,
        radio=mock_radio,
        config=NodeConfig(
            receive_timeout_ms=100,
            announce_interval_ms=10000,
            announce_jitter_ms=0,
        ),
    )


class TestReceivePktId:
    """RX-side correlation id: present in the receive return, monotonic."""

    @pytest.mark.asyncio
    async def test_receive_return_carries_pkt_id(
        self,
        link_layer: LinkLayer,
        mock_radio: MockRadio,
        peer_identity: Identity,
    ):
        mock_radio.queue_rx(_signed_broadcast_wire(peer_identity, 0))
        result = await link_layer.receive(timeout_ms=100)
        assert isinstance(result, RxFrame)
        assert type(result.pkt_id) is int
        assert 0 <= result.pkt_id <= _MAX_U32

    @pytest.mark.asyncio
    async def test_pkt_id_increments_on_each_receive(
        self,
        link_layer: LinkLayer,
        mock_radio: MockRadio,
        peer_identity: Identity,
    ):
        mock_radio.queue_rx(_signed_broadcast_wire(peer_identity, 0))
        first = await link_layer.receive(timeout_ms=100)
        assert isinstance(first, RxFrame)

        mock_radio.queue_rx(_signed_broadcast_wire(peer_identity, 1))
        second = await link_layer.receive(timeout_ms=100)
        assert isinstance(second, RxFrame)

        assert second.pkt_id == first.pkt_id + 1


class TestForwardedPacketCorrelation:
    """Forwarded packets log the inbound id and a fresh outbound id."""

    @pytest.mark.asyncio
    async def test_forward_logs_in_pkt_id_and_outbound_pkt_id(
        self,
        node: Node,
        peer_identity: Identity,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ):
        ingress_peer = PeerIdentity.from_pubkey(Identity.from_seed(bytes([7]) * 32).pubkey)
        next_peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node.add_peer(next_peer)
        next_hop = IPv6Address(IPv6Address("fe80::").packed[:8] + next_peer.iid)
        raw = IPv6Packet(
            IPv6Header(
                src_addr=IPv6Address("fe80::1234"),
                dst_addr=IPv6Address("fe80::abcd"),
                next_header=NextHeader.NO_NEXT_HEADER,
                hop_limit=64,
            ),
        ).to_bytes()
        inbound_pkt_id = 77

        monkeypatch.setattr(node.link, "accept_authenticated_schc_packet", lambda _rx: raw)
        monkeypatch.setattr(
            node.router,
            "route",
            lambda _packet, _now: (RouteDecision.FORWARD, next_hop),
        )
        monkeypatch.setattr(
            node.link,
            "compress_schc_for_peer",
            lambda _ipv6, _remote, *, allow_fragmentation: b"forwarded-schc",
        )

        with caplog.at_level(logging.DEBUG):
            await node._process_received(
                _verified_rx(wrap_schc_payload(b"\x02test"), ingress_peer, inbound_pkt_id)
            )

        assert f"in_pkt_id={inbound_pkt_id}" in caplog.text

        # The outbound hop is a distinct packet in the shared per-node id
        # space: the TX queue push log must carry its own pkt_id, different
        # from the inbound one.
        push_ids = re.findall(r"TX queue push: pkt_id=(\d+)", caplog.text)
        assert push_ids, "forwarded packet was not pushed to the TX queue"
        outbound_pkt_id = int(push_ids[-1])
        assert 0 <= outbound_pkt_id <= _MAX_U32
        assert outbound_pkt_id != inbound_pkt_id
