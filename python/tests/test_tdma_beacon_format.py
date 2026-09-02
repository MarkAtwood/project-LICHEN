# SPDX-FileCopyrightText: The contributors to the LICHEN project
# SPDX-License-Identifier: GPL-3.0-or-later

"""TDMA beacon wire-format tests consuming test/vectors/ccp_beacon_format.json
(beacon_format cases; spec/02a 2a.2; bead b7z9.60 slice: Python pack/parse)."""

import json
from pathlib import Path

import pytest

from lichen.rpl.tdma_beacon import (
    BeaconFormatError,
    TdmaBeaconHeader,
    cbor_options,
    parse_header,
    serialize_header,
    signature_bytes,
    signed_data,
)

_VECTOR_FILE = Path(__file__).resolve().parents[2] / "test" / "vectors" / "ccp_beacon_format.json"
VECTORS = json.loads(_VECTOR_FILE.read_text())


def _beacon_format_cases() -> list[dict]:
    """Wire-oracle cases only (beacon_header_layout is prose documentation)."""
    return [
        v
        for v in VECTORS["vectors"]
        if v.get("type") == "beacon_format" and "input" in v and "output" in v
    ]


def test_beacon_wire_cases_present() -> None:
    """A missing wire oracle must fail loudly, not skip."""
    assert _beacon_format_cases(), "ccp_beacon_format.json lost its wire cases"


@pytest.mark.parametrize("case", _beacon_format_cases(), ids=lambda c: c["name"])
def test_beacon_wire_example(case: dict) -> None:
    """Drive the production codec from the independent wire oracle."""
    inp = case["input"]
    expected_hex = case["output"]["header_hex"]

    header = TdmaBeaconHeader(
        epoch=inp["epoch"],
        num_slots=inp["num_slots"],
        sfn=inp["sfn"],
        timestamp=inp["timestamp"],
        flags=inp["flags"],
        rx_chains=inp["rx_chains"],
        setup_window=inp["setup_window"],
        occupied_time=inp["occupied_time"],
        guard=inp["guard"],
        channel_mask=inp["channel_mask"],
    )
    packed = serialize_header(header)
    assert packed.hex() == expected_hex

    parsed = parse_header(packed)
    assert parsed == header
    assert parse_header(bytes.fromhex(expected_hex)) == header


def test_parse_rejects_short_buffer() -> None:
    with pytest.raises(BeaconFormatError):
        parse_header(bytes(23))


def test_parse_rejects_reserved_flag_bits() -> None:
    data = bytearray(24)
    data[13] = 0x10  # reserved bit 4
    with pytest.raises(BeaconFormatError):
        parse_header(bytes(data))


def test_serialize_rejects_reserved_flag_bits() -> None:
    header = TdmaBeaconHeader(
        epoch=1, num_slots=16, sfn=0, timestamp=0, flags=0x80,
        rx_chains=1, setup_window=0, occupied_time=0, guard=50,
        channel_mask=1,
    )
    with pytest.raises(BeaconFormatError):
        serialize_header(header)


def test_serialize_rejects_out_of_range_fields() -> None:
    base = {
        "epoch": 1,
        "num_slots": 16,
        "sfn": 0,
        "timestamp": 0,
        "flags": 0,
        "rx_chains": 1,
        "setup_window": 0,
        "occupied_time": 0,
        "guard": 50,
        "channel_mask": 1,
    }
    with pytest.raises(BeaconFormatError):
        serialize_header(TdmaBeaconHeader(**{**base, "num_slots": 256}))
    with pytest.raises(BeaconFormatError):
        serialize_header(TdmaBeaconHeader(**{**base, "num_slots": -1}))
    with pytest.raises(BeaconFormatError):
        serialize_header(TdmaBeaconHeader(**{**base, "guard": -50}))
    with pytest.raises(BeaconFormatError):
        serialize_header(TdmaBeaconHeader(**{**base, "epoch": 1 << 32}))
    with pytest.raises(BeaconFormatError):
        serialize_header(TdmaBeaconHeader(**{**base, "setup_window": 0x10000}))


def test_flag_predicates() -> None:
    header = TdmaBeaconHeader(
        epoch=0, num_slots=16, sfn=0, timestamp=0, flags=0x0F,
        rx_chains=1, setup_window=20, occupied_time=2300, guard=50,
        channel_mask=1,
    )
    assert header.is_scheduled
    assert header.is_csma
    assert header.is_ch0_rx
    assert header.has_gnss_pps


def test_signature_and_options_extraction() -> None:
    header_bytes = bytes.fromhex(
        "000000011000003039659200800001001408fc3200000001"
    )
    options = b"\xa1\x01\x02"  # tiny CBOR map stand-in
    signature = bytes(range(48))
    beacon = header_bytes + options + signature

    assert signature_bytes(beacon) == signature
    assert signed_data(beacon) == header_bytes + options
    assert cbor_options(beacon) == options
    # Minimal beacon (no options) -> no CBOR section.
    minimal = header_bytes + signature
    assert signature_bytes(minimal) == signature
    assert cbor_options(minimal) is None
    # Too short for a signature at all.
    assert signature_bytes(header_bytes) is None
    assert signed_data(header_bytes) is None
