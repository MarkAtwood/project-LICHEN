#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Run the C L2 probe against a real NodeServer/SimRadio/LinkLayer peer."""

from __future__ import annotations

import argparse
import asyncio
import struct
from pathlib import Path

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.ipv6.addr import iid_to_eui64
from lichen.l2_payload import (
    L2PayloadKind,
    classify_l2_payload,
    l2_payload_body,
    wrap_schc_payload,
)
from lichen.link.frame import AddrMode
from lichen.link.link_layer import LinkLayer, ReceiveError
from lichen.radio.sim_client import SimRadio
from lichen.schc.headers import decode_rule255, encode_rule255
from lichen.sim.node_server import start_node_server
from lichen.sim.simulation import Simulation, TimeMode

REQUEST = bytes.fromhex("50025103ff637478")
RESPONSE = bytes.fromhex("60455103ff707921")


def udp_packet(src: bytes, dst: bytes, payload: bytes) -> bytes:
    """Independent RFC 8200 pseudo-header checksum, not the C packet builder."""
    udp = struct.pack("!HHHH", 56830, 56830, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack("!I3xB", len(udp), 17)
    data = pseudo + udp
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    checksum = (~total & 0xFFFF) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", checksum) + udp[8:]
    return struct.pack("!IHBB", 0x60000000, len(udp), 17, 64) + src + dst + udp


async def exchange(link: LinkLayer, c_peer: PeerIdentity, local: Identity) -> None:
    prefix = bytes.fromhex("fe80000000000000")
    c_addr = prefix + c_peer.iid
    py_addr = prefix + local.iid
    while True:
        received = await link.receive(1000)
        if received is None:
            continue
        if isinstance(received, ReceiveError):
            raise AssertionError(f"Python LinkLayer rejected frame: {received.name}")
        if classify_l2_payload(received.payload) is not L2PayloadKind.SCHC:
            continue
        assert received.sender_pubkey == c_peer.pubkey
        assert received.frame.signature_present and len(received.frame.mic) == 48
        # This is a LinkLayer + codec interoperability test, not a Node/RPL
        # policy test. Do not manufacture authenticated DIO/context tokens.
        compressed = l2_payload_body(received.payload)
        assert compressed[0] == 255, "expected full-IPv6 fallback without negotiated rules"
        assert decode_rule255(compressed) == udp_packet(c_addr, py_addr, REQUEST)
        print("Python authenticated C Schnorr48 frame and matched IPv6/UDP bytes", flush=True)
        reply = encode_rule255(udp_packet(py_addr, c_addr, RESPONSE))
        assert await link.send(
            wrap_schc_payload(reply),
            dst_addr=iid_to_eui64(c_peer.iid),
            addr_mode=AddrMode.EXTENDED,
        )
        return


async def run(binary: Path, port: int) -> None:
    local = Identity.from_seed(bytes([0x51, 4]) + bytes(30))
    c_identity = Identity.from_seed(bytes([0x51, 3]) + bytes(30))
    c_peer = PeerIdentity.from_pubkey(c_identity.pubkey)
    simulation = Simulation("lichen", time_mode=TimeMode.REALTIME)
    server = await start_node_server(simulation, port=port)
    process = None
    async with (
        server,
        asyncio.timeout(30),
        SimRadio("127.0.0.1", port, "lichen", "python-peer", (1, 0, 0)) as radio,
    ):
        link = LinkLayer(
            radio=radio,
            identity=local,
            peer_lookup=lambda iid: c_peer if iid == c_peer.iid else None,
        )
        try:
            async with asyncio.timeout(30):
                process = await asyncio.create_subprocess_exec(str(binary.resolve()), "-rt")
                peer_task = asyncio.create_task(exchange(link, c_peer, local))
                exit_task = asyncio.create_task(process.wait())
                try:
                    done, _ = await asyncio.wait(
                        (peer_task, exit_task), return_when=asyncio.FIRST_COMPLETED
                    )
                    if exit_task in done:
                        assert exit_task.result() == 0, f"C probe exited {exit_task.result()}"
                    await peer_task
                    code = await exit_task
                    assert code == 0, f"C probe exited {code}"
                finally:
                    for task in (peer_task, exit_task):
                        task.cancel()
                    await asyncio.gather(peer_task, exit_task, return_exceptions=True)
                print("PASS: signed C/Python TCP-backed L2 roundtrip", flush=True)
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--port", type=int, default=4444, help="match CONFIG_LORA_LICHEN_SIM_PORT")
    args = parser.parse_args()
    asyncio.run(run(args.binary, args.port))
