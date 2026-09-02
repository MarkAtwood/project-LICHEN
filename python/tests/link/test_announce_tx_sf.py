# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""TX_SF announce TLV (spec 02 3.4 R-02-026, bead b7z9.74.2)."""

from __future__ import annotations

import pytest

from lichen.announce.coords import (
    TX_SF_ABSENT_DEFAULT,
    decode_tx_sf,
    encode_tx_sf,
)


def test_encode_roundtrip() -> None:
    for sf in range(7, 13):
        assert decode_tx_sf(encode_tx_sf(sf)) == sf


def test_absence_means_sf10() -> None:
    assert decode_tx_sf(b"") == TX_SF_ABSENT_DEFAULT
    assert decode_tx_sf(b"\xAA") == TX_SF_ABSENT_DEFAULT
    assert decode_tx_sf(b"\x01\x02\x03") == TX_SF_ABSENT_DEFAULT


def test_tlv_after_other_app_data() -> None:
    app_data = bytes([0x01]) + b"\x00" * 8 + encode_tx_sf(12)
    assert decode_tx_sf(app_data) == 12


def test_out_of_range_clamps_to_sf10() -> None:
    assert decode_tx_sf(bytes([0x06, 13])) == TX_SF_ABSENT_DEFAULT
    assert decode_tx_sf(bytes([0x06, 6])) == TX_SF_ABSENT_DEFAULT


def test_encode_out_of_range_raises() -> None:
    with pytest.raises(ValueError):
        encode_tx_sf(6)
    with pytest.raises(ValueError):
        encode_tx_sf(13)
