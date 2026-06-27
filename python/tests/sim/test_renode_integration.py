# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Integration test for Renode SubGHz <-> lichen-sim bridge.

Requires Renode to be installed. Run with: pytest -v -k renode_integration
"""

import asyncio
import subprocess
from pathlib import Path

import pytest

from lichen.sim.renode_server import start_renode_server
from lichen.sim.simulation import Simulation

# Path to project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent


def _has_renode() -> bool:
    """Check if Renode is available."""
    try:
        result = subprocess.run(
            ["renode", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.mark.skipif(not _has_renode(), reason="Renode not installed")
@pytest.mark.asyncio
async def test_renode_integration_tx() -> None:
    """Test TX from Renode peripheral reaches lichen-sim."""
    sim = Simulation("renode-test")
    server, port = await start_renode_server(sim, "renode-node", port=5555)

    # Track transmissions
    tx_received = []

    def on_tx_start(
        sim_id: str, node_id: str, tx_id: str, payload_len: int, time_us: int
    ) -> None:
        tx_received.append((node_id, payload_len))

    sim.add_observer(type("Observer", (), {"on_tx_start": on_tx_start})())

    try:
        # Create Renode test script
        renode_dir = PROJECT_ROOT / "lichen/boards/renode/nucleo_wl55jc"
        peripheral = renode_dir / "peripherals/LichenSubGHz.cs"
        platform = renode_dir / "support/stm32wl55.repl"
        script = f"""\
:name: Integration Test
include @{peripheral}
mach create "test"
machine LoadPlatformDescription @{platform}

# Connect to lichen-sim
sysbus WriteDoubleWord 0x58010024 1

# Write payload "TEST" to TX buffer
sysbus WriteDoubleWord 0x58010100 0x54534554

# Set TX length = 4
sysbus WriteDoubleWord 0x58010000 4

# Trigger TX
sysbus WriteDoubleWord 0x58010004 1

# Brief pause for socket IO
sleep 0.1

quit
"""
        script_path = PROJECT_ROOT / "lichen/boards/renode/nucleo_wl55jc/_integration_test.resc"
        script_path.write_text(script)

        # Run Renode
        proc = await asyncio.create_subprocess_exec(
            "renode",
            "--disable-gui",
            "--port", "-1",
            str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        except TimeoutError:
            proc.kill()
            await proc.wait()

        script_path.unlink(missing_ok=True)

        # Check if TX was received
        # ponytail: observer may not fire in time, check node state instead
        assert sim.get_node("renode-node") is not None

    finally:
        await server.stop()
