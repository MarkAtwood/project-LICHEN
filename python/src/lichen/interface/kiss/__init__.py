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

__all__ = [
    "FEND",
    "FESC",
    "TFEND",
    "TFESC",
    "KissCommand",
    "KissError",
    "KissFrame",
    "KissReader",
    "kiss_encode",
    "kiss_decode",
    "kiss_escape",
    "kiss_unescape",
]
