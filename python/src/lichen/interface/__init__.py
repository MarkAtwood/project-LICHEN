"""LICHEN Native protocol interface."""

from lichen.interface.framing import FrameReader, FrameWriter, frame, unframe
from lichen.interface.messages import (
    Message,
    Hello,
    ConfigGet,
    ConfigSet,
    ConfigResult,
    SendMessage,
    MessageReceived,
    MeshState,
    NodeInfo,
    LogEntry,
    LogSubscribe,
    encode_message,
    decode_message,
)
from lichen.interface.tcp import TcpConnection, TcpServer, connect, serve
from lichen.interface.handler import NodeHandler, bind_native
from lichen.interface.serial import SerialConnection, open_serial, list_serial_ports

__all__ = [
    # Framing
    "FrameReader",
    "FrameWriter",
    "frame",
    "unframe",
    # Messages
    "Message",
    "Hello",
    "ConfigGet",
    "ConfigSet",
    "ConfigResult",
    "SendMessage",
    "MessageReceived",
    "MeshState",
    "NodeInfo",
    "LogEntry",
    "LogSubscribe",
    "encode_message",
    "decode_message",
    # TCP transport
    "TcpConnection",
    "TcpServer",
    "connect",
    "serve",
    # Node handler
    "NodeHandler",
    "bind_native",
    # Serial transport
    "SerialConnection",
    "open_serial",
    "list_serial_ports",
]
