# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Node capability re-announcement on RPL root change (spec 8.12, bead 99sg.2).

After DIO processing records a DODAGID membership transition, the node POSTs
a COSE_Sign1 capability announcement to the new root's
/.well-known/capability-announce over the SCHC/UDP/CoAP mesh transport.
"""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest
from aiocoap import POST, Message

from lichen.crypto.capability_announcements import (
    Capability,
    decode_cose_sign1_announcement,
    verify_capability_announcement,
)
from lichen.crypto.identity import Identity, PeerIdentity
from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.l2_payload import wrap_schc_payload
from lichen.link.frames import RxFrame
from lichen.node import (
    MAX_CAPABILITY_BITMASK,
    Node,
    NodeConfig,
)
from lichen.rpl.dodag import INFINITE_RANK
from lichen.rpl.messages import DIO, RPL_ICMPV6_TYPE, RplCode
from lichen.schc.headers import compress_packet

IDENTITY = Identity.from_seed(bytes(range(32)))
PEER = Identity.from_seed(bytes(range(32, 64)))
DODAG_A = "0200::1"
DODAG_B = "0200::99"
P1 = IPv6Address("fe80::1")


class _CaptureRadio:
    """Minimal radio: never receives, accepts every transmit."""

    async def receive(self, timeout_ms: int) -> None:
        return None

    async def transmit(self, payload: bytes) -> bool:
        return True


def _node(*, capabilities: int = 1) -> Node:
    return Node(
        identity=IDENTITY,
        radio=_CaptureRadio(),
        config=NodeConfig(
            rpl_instance_id=0,
            rpl_dodag_id=IPv6Address(DODAG_A),
            rpl_dodag_version=1,
            rpl_dio_expected_role="root",
            node_capabilities=capabilities,
        ),
    )


def _dio(dodag_id: str, rank: int = 256, version: int = 1) -> DIO:
    return DIO(rpl_instance_id=0, version=version, rank=rank, dtsn=0, dodag_id=dodag_id)


def _verified_rx(payload: bytes, peer: PeerIdentity) -> RxFrame:
    """Hand-issue a test RxFrame (mirrors test_node._verified_rx)."""
    value = object.__new__(RxFrame)
    object.__setattr__(value, "sender", peer)
    object.__setattr__(value, "rssi_dbm", -90)
    object.__setattr__(value, "snr_db", 4)
    object.__setattr__(value, "_authenticated_payload", payload)
    object.__setattr__(value, "_authenticated_sender_pubkey", peer.pubkey)
    return value


def _dio_schc_payload(dodag_id: str) -> bytes:
    dio = _dio(dodag_id, rank=512)
    source = IPv6Address(IPv6Address("fe80::").packed[:8] + PEER.iid)
    destination = IPv6Address("ff02::1a")
    icmp = Icmpv6Message(RPL_ICMPV6_TYPE, int(RplCode.DIO), dio.to_bytes()).to_bytes(
        source, destination
    )
    raw = (
        IPv6Header(
            src_addr=source,
            dst_addr=destination,
            next_header=NextHeader.ICMPV6,
            payload_length=len(icmp),
            hop_limit=255,
        ).to_bytes()
        + icmp
    )
    return wrap_schc_payload(compress_packet(raw))


def _capture_send(node: Node, monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    sent: list[bytes] = []

    async def fake_send(ipv6_bytes: bytes) -> bool:
        sent.append(ipv6_bytes)
        return True

    monkeypatch.setattr(node, "send", fake_send)
    return sent


def _decode_post(datagram: bytes, expected_dst: IPv6Address) -> Message:
    packet = IPv6Packet.from_bytes(datagram, strict=True)
    assert packet.header.dst_addr == expected_dst
    udp = UdpDatagram.from_bytes(packet.payload)
    assert udp.dst_port == 5683
    message = Message.decode(udp.payload)
    assert message.code == POST
    assert tuple(message.opt.uri_path) == (".well-known", "capability-announce")
    return message


def _assert_valid_announcement(message: Message, *, capabilities: int, seq: int, now: int) -> None:
    announcement = decode_cose_sign1_announcement(message.payload)
    # COSE structural checks (alg -65537, kid == announcer_iid) run in decode.
    assert announcement.payload.announcer_iid == IDENTITY.iid
    assert announcement.payload.capabilities == capabilities
    assert announcement.payload.seq == seq
    valid, error = verify_capability_announcement(announcement, IDENTITY.pubkey, current_time=now)
    assert valid, error


@pytest.mark.asyncio
async def test_root_change_posts_valid_cose_announcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = _node()
    sent = _capture_send(node, monkeypatch)
    now = 1_800_000_000
    monkeypatch.setattr("time.time", lambda: now)

    assert node.dodag is not None
    node.dodag.process_dio(_dio(DODAG_A), P1, link_etx=1.0)
    await node._reannounce_capabilities_to_new_root()
    assert len(sent) == 1
    message = _decode_post(sent[0], IPv6Address(DODAG_A))
    _assert_valid_announcement(message, capabilities=1, seq=1, now=now)

    # Root re-election: poison evicts the parent, then a foreign DODAGID joins.
    node.dodag.process_dio(_dio(DODAG_A, rank=INFINITE_RANK), P1, link_etx=1.0)
    node.dodag.process_dio(_dio(DODAG_B), P1, link_etx=1.0)
    await node._reannounce_capabilities_to_new_root()
    assert len(sent) == 2
    message = _decode_post(sent[1], IPv6Address(DODAG_B))
    # The in-memory seq keeps climbing: a fresh root accepts any seq, and a
    # still-cached older root never sees a rollback.
    _assert_valid_announcement(message, capabilities=1, seq=2, now=now)


@pytest.mark.asyncio
async def test_no_root_change_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    node = _node()
    sent = _capture_send(node, monkeypatch)
    await node._reannounce_capabilities_to_new_root()
    assert sent == []


@pytest.mark.asyncio
async def test_zero_capabilities_drains_but_stays_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = _node(capabilities=0)
    sent = _capture_send(node, monkeypatch)
    assert node.dodag is not None
    node.dodag.process_dio(_dio(DODAG_A), P1, link_etx=1.0)
    await node._reannounce_capabilities_to_new_root()
    assert sent == []
    assert node.dodag.take_root_changes() == []  # drained, not leaked


@pytest.mark.asyncio
async def test_dio_ingress_wiring_triggers_reannounce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_process_received drains root changes after an admitted DIO."""
    node = _node()
    sent = _capture_send(node, monkeypatch)
    assert node.dodag is not None

    def admit_via_real_dodag(
        _link: object, _rx: RxFrame, *, expected_role: str, link_etx: float = 1.0
    ) -> None:
        # Test seam: the link-layer authenticated-DIO receipt is covered by
        # tests/rpl/test_authenticated_dio_security.py; here the real
        # DodagState admission produces the JOINED transition.
        assert expected_role == "root"
        node.dodag.process_dio(_dio(DODAG_A), P1, link_etx=link_etx)

    monkeypatch.setattr(node.dodag, "process_authenticated_dio", admit_via_real_dodag)
    peer = PeerIdentity.from_pubkey(PEER.pubkey)
    await node._process_received(_verified_rx(_dio_schc_payload(DODAG_A), peer))

    assert len(sent) == 1
    message = _decode_post(sent[0], IPv6Address(DODAG_A))
    assert message.code == POST


def test_node_capabilities_bitmask_validation() -> None:
    for valid in range(MAX_CAPABILITY_BITMASK + 1):
        _node(capabilities=valid)  # must not raise
    for invalid in (-1, MAX_CAPABILITY_BITMASK + 1, 0x80, True, 1.5, "1"):
        with pytest.raises((ValueError, TypeError)):
            _node(capabilities=invalid)  # type: ignore[arg-type]


def test_capability_enum_matches_config_mask() -> None:
    assert int(Capability.EGRESS | Capability.PREFIX_DELEGATION) == MAX_CAPABILITY_BITMASK
