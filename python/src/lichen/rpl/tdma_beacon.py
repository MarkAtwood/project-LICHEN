# SPDX-FileCopyrightText: The contributors to the LICHEN project
# SPDX-License-Identifier: GPL-3.0-or-later

"""TDMA beacon wire format (spec/02a-coordinated-capacity.md 2a.2).

Port of rust lichen-core tdma_beacon.rs: fixed-format
uncompressed beacon header (24 bytes) plus trailing Schnorr48 signature.

Header layout (all unsigned big-endian):
  [0..4)   epoch
  [4]      num_slots
  [5..9)   sfn
  [9..13)  timestamp
  [13]     flags (bit0 scheduled, bit1 csma, bit2 ch0_rx, bit3 gnss_pps,
           bits 4-7 reserved MUST be zero on send)
  [14]     rx_chains
  [15..17) setup_window
  [17..19) occupied_time
  [19]     guard (normative 50 ms)
  [20..24) channel_mask (bit0 = CH0)

CBOR options (per CDDL, e.g. slot_map / pow_challenge) sit between the
header and the trailing 48-byte Schnorr48 beacon signature.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

HEADER_SIZE = 24
SIG_SIZE = 48
MIN_BEACON_SIZE = HEADER_SIZE + SIG_SIZE
FLAG_SCHEDULED = 0x01
FLAG_CSMA = 0x02
FLAG_CH0_RX = 0x04
FLAG_GNSS_PPS = 0x08
FLAG_RESERVED_MASK = 0xF0


class BeaconFormatError(Exception):
    """Malformed beacon header or flags."""


@dataclass
class TdmaBeaconHeader:
    """Parsed TDMA beacon header fields."""

    epoch: int
    num_slots: int
    sfn: int
    timestamp: int
    flags: int
    rx_chains: int
    setup_window: int
    occupied_time: int
    guard: int
    channel_mask: int

    @property
    def is_scheduled(self) -> bool:
        return bool(self.flags & FLAG_SCHEDULED)

    @property
    def is_csma(self) -> bool:
        return bool(self.flags & FLAG_CSMA)

    @property
    def has_gnss_pps(self) -> bool:
        return bool(self.flags & FLAG_GNSS_PPS)

    @property
    def is_ch0_rx(self) -> bool:
        return bool(self.flags & FLAG_CH0_RX)


def _require_u8(value: int, name: str) -> int:
    if not 0 <= value <= 0xFF:
        raise BeaconFormatError(f"{name} out of u8 range: {value}")
    return value


def _require_u16(value: int, name: str) -> int:
    if not 0 <= value <= 0xFFFF:
        raise BeaconFormatError(f"{name} out of u16 range: {value}")
    return value


def _require_u32(value: int, name: str) -> int:
    if not 0 <= value <= 0xFFFFFFFF:
        raise BeaconFormatError(f"{name} out of u32 range: {value}")
    return value


def parse_header(data: bytes) -> TdmaBeaconHeader:
    """Parse the 24-byte beacon header.

    Raises BeaconFormatError when the buffer is too short or a reserved
    flag bit (4-7) is set.
    """
    if len(data) < HEADER_SIZE:
        raise BeaconFormatError("beacon header too short")
    flags = data[13]
    if flags & FLAG_RESERVED_MASK:
        raise BeaconFormatError("reserved flag bits set")
    return TdmaBeaconHeader(
        epoch=int.from_bytes(data[0:4], "big"),
        num_slots=data[4],
        sfn=int.from_bytes(data[5:9], "big"),
        timestamp=int.from_bytes(data[9:13], "big"),
        flags=flags,
        rx_chains=data[14],
        setup_window=int.from_bytes(data[15:17], "big"),
        occupied_time=int.from_bytes(data[17:19], "big"),
        guard=data[19],
        channel_mask=int.from_bytes(data[20:24], "big"),
    )


def serialize_header(header: TdmaBeaconHeader) -> bytes:
    """Serialize the 24-byte beacon header."""
    flags = _require_u8(header.flags, "flags")
    if flags & FLAG_RESERVED_MASK:
        raise BeaconFormatError("reserved flag bits set")
    out = bytearray(HEADER_SIZE)
    out[0:4] = _require_u32(header.epoch, "epoch").to_bytes(4, "big")
    out[4] = _require_u8(header.num_slots, "num_slots")
    out[5:9] = _require_u32(header.sfn, "sfn").to_bytes(4, "big")
    out[9:13] = _require_u32(header.timestamp, "timestamp").to_bytes(4, "big")
    out[13] = flags
    out[14] = _require_u8(header.rx_chains, "rx_chains")
    out[15:17] = _require_u16(header.setup_window, "setup_window").to_bytes(2, "big")
    out[17:19] = _require_u16(header.occupied_time, "occupied_time").to_bytes(2, "big")
    out[19] = _require_u8(header.guard, "guard")
    out[20:24] = _require_u32(header.channel_mask, "channel_mask").to_bytes(4, "big")
    return bytes(out)


def signature_bytes(beacon: bytes) -> bytes | None:
    """Trailing 48-byte Schnorr48 signature, or None if too short."""
    if len(beacon) < MIN_BEACON_SIZE:
        return None
    return beacon[-SIG_SIZE:]


def signed_data(beacon: bytes) -> bytes | None:
    """Everything except the trailing signature, or None if too short."""
    if len(beacon) < MIN_BEACON_SIZE:
        return None
    return beacon[:-SIG_SIZE]


def cbor_options(beacon: bytes) -> bytes | None:
    """CBOR options between the header and the signature."""
    if len(beacon) <= MIN_BEACON_SIZE:
        return None
    return beacon[HEADER_SIZE:-SIG_SIZE]


def verify_gate(beacon: bytes, verify_fn: Callable[[bytes, bytes], bool]) -> bool:
    """Beacon signature verify-gate (spec 8 / ccp_beacon_sig_gate.json).

    Extracts signed_data and signature_bytes, then delegates to the
    caller-provided verify function (which performs the Schnorr48
    verification against the sender's registered pubkey).

    Returns False if the beacon is too short or the verify function
    rejects. Per ccp_beacon_sig_gate.json: an invalid signature MUST
    reject the frame before DIO processing.
    """
    signed = signed_data(beacon)
    if signed is None:
        return False
    sig = signature_bytes(beacon)
    if sig is None:
        return False
    return verify_fn(signed, sig)
