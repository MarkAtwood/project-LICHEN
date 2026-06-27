# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Renode bridge server."""

import asyncio
import struct

import pytest

from lichen.sim.renode_server import start_renode_server
from lichen.sim.simulation import Simulation


async def _send_message(writer: asyncio.StreamWriter, data: bytes) -> None:
    """Send length-prefixed message."""
    writer.write(struct.pack("<I", len(data)) + data)
    await writer.drain()


async def _read_message(reader: asyncio.StreamReader) -> bytes:
    """Read length-prefixed message."""
    length_bytes = await reader.readexactly(4)
    (length,) = struct.unpack("<I", length_bytes)
    if length == 0:
        return b""
    return await reader.readexactly(length)


@pytest.mark.asyncio
async def test_renode_tx_basic() -> None:
    """Test TX from mock Renode client."""
    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Send TX: type(0x10) + len(2) + payload
        payload = b"hello from renode"
        tx_msg = bytes([0x10]) + struct.pack("<H", len(payload)) + payload
        await _send_message(writer, tx_msg)

        # Read TX_DONE response
        resp = await _read_message(reader)
        assert resp[0] == 0x11  # TX_DONE
        airtime = struct.unpack("<I", resp[1:5])[0]
        assert airtime > 0

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_renode_rx_poll_empty() -> None:
    """Test RX poll returns empty when no packets."""
    sim = Simulation("test")
    server, port = await start_renode_server(sim, "renode-node", port=0)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Send RX_POLL: type(0x20)
        await _send_message(writer, bytes([0x20]))

        # Read RX_EMPTY response
        resp = await _read_message(reader)
        assert resp[0] == 0x23  # RX_EMPTY

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


# ponytail: complex RX test deferred - requires full simulation event loop
# integration test with actual Renode will cover this path
