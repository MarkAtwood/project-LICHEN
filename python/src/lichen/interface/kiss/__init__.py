"""KISS protocol interface for TNC app compatibility."""

from lichen.interface.kiss.framing import (
    FEND,
    FESC,
    TFEND,
    TFESC,
    KissCommand,
    KissError,
    KissFrame,
    KissReader,
    kiss_encode,
    kiss_decode,
    kiss_escape,
    kiss_unescape,
)
from lichen.interface.kiss.handler import (
    DefaultKissConfig,
    KissConfig,
    KissHandler,
)
from lichen.interface.kiss.serial import (
    KissSerialConnection,
    open_kiss_serial,
)

__all__ = [
    "FEND",
    "FESC",
    "TFEND",
    "TFESC",
    "KissCommand",
    "KissConfig",
    "KissError",
    "KissFrame",
    "KissHandler",
    "KissReader",
    "KissSerialConnection",
    "DefaultKissConfig",
    "kiss_encode",
    "kiss_decode",
    "kiss_escape",
    "kiss_unescape",
    "open_kiss_serial",
]
