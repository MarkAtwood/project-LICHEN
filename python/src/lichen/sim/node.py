"""Simulated node state tracking for the LICHEN simulator."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum, auto


class NodeState(Enum):
    """Radio state of a simulated node."""

    IDLE = auto()
    TX = auto()
    RX_WAIT = auto()


@dataclass
class SimNode:
    """State for a single simulated node in the LICHEN mesh.

    Tracks position, radio state, and connection status for simulation.
    Position is mutable to support node mobility scenarios.
    """

    id: str
    position: tuple[float, float, float] = (0.0, 0.0, 0.0)
    tx_power_dbm: int = 22
    state: NodeState = NodeState.IDLE
    pending_rx_future: asyncio.Future[None] | None = field(default=None, repr=False)
    connected: bool = False
    last_seen_time_us: int = 0

    def set_position(self, x: float, y: float, z: float) -> None:
        """Update the node's position in 3D space.

        Args:
            x: X coordinate in meters.
            y: Y coordinate in meters.
            z: Z coordinate in meters (altitude).
        """
        self.position = (x, y, z)

    def disconnect(self) -> None:
        """Disconnect the node and clean up pending operations.

        Sets connected to False and cancels any pending RX future.
        """
        self.connected = False
        if self.pending_rx_future is not None and not self.pending_rx_future.done():
            self.pending_rx_future.cancel()
        self.pending_rx_future = None

    def is_online(self) -> bool:
        """Check if the node is currently connected.

        Returns:
            True if the node is connected, False otherwise.
        """
        return self.connected
