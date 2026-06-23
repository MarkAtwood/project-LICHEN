# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for RPL control message codecs (RFC 6550).

Byte oracles are hand-constructed from the RFC 6550 base-object layouts.
"""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.rpl.messages import (
    DAO,
    DIO,
    DIS,
    DAOAck,
    ModeOfOperation,
    RplCode,
    RplError,
    RplOption,
    RplOptionType,
    from_icmpv6,
    to_icmpv6,
)

DODAG = IPv6Address("fd00::1")
DODAG_PACKED = DODAG.packed  # fd00 then 13 zero bytes then 01


def test_dis_known_vector() -> None:
    assert DIS().to_bytes() == bytes([0x00, 0x00])


def test_dis_round_trip_with_options() -> None:
    dis = DIS(flags=0x01, reserved=0x00, options=[RplOption(RplOptionType.PADN, b"\x00")])
    assert DIS.from_bytes(dis.to_bytes()) == dis


def test_dio_known_vector() -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=256,
        dtsn=0,
        dodag_id=DODAG,
        grounded=True,
        mode_of_operation=ModeOfOperation.NON_STORING,
        preference=0,
    )
    expected = (
        bytes([0x00, 0x01])  # instance, version
        + bytes([0x01, 0x00])  # rank = 256
        + bytes([0x88])  # G=1 (0x80) | MOP=1 (<<3 = 0x08) | Prf=0
        + bytes([0x00, 0x00, 0x00])  # dtsn, flags, reserved
        + DODAG_PACKED
    )
    assert dio.to_bytes() == expected
    assert len(dio.to_bytes()) == 24


def test_dio_flag_field_decoding() -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=512,
        dtsn=3,
        dodag_id=DODAG,
        grounded=False,
        mode_of_operation=ModeOfOperation.STORING_NO_MULTICAST,
        preference=5,
    )
    parsed = DIO.from_bytes(dio.to_bytes())
    assert parsed.grounded is False
    assert parsed.mode_of_operation == ModeOfOperation.STORING_NO_MULTICAST
    assert parsed.preference == 5
    assert parsed == dio


def test_dio_round_trip_with_options() -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=256,
        dtsn=0,
        dodag_id=DODAG,
        options=[
            RplOption(RplOptionType.PAD1),
            RplOption(RplOptionType.DODAG_CONFIGURATION, b"\x01\x02\x03\x04"),
        ],
    )
    assert DIO.from_bytes(dio.to_bytes()) == dio


def test_dao_with_dodagid_known_vector() -> None:
    dao = DAO(rpl_instance_id=0, dao_sequence=5, dodag_id=DODAG)
    expected = bytes([0x00, 0x40, 0x00, 0x05]) + DODAG_PACKED  # D flag = 0x40
    assert dao.to_bytes() == expected


def test_dao_without_dodagid_ack_requested() -> None:
    dao = DAO(rpl_instance_id=0, dao_sequence=5, ack_requested=True)
    expected = bytes([0x00, 0x80, 0x00, 0x05])  # K flag = 0x80, no DODAGID
    assert dao.to_bytes() == expected
    parsed = DAO.from_bytes(expected)
    assert parsed.ack_requested is True
    assert parsed.dodag_id is None
    assert parsed == dao


def test_dao_round_trip_with_dodagid() -> None:
    dao = DAO(
        rpl_instance_id=0,
        dao_sequence=9,
        dodag_id=DODAG,
        options=[RplOption(RplOptionType.RPL_TARGET, b"\xaa\xbb")],
    )
    assert DAO.from_bytes(dao.to_bytes()) == dao


def test_dao_ack_known_vector() -> None:
    ack = DAOAck(rpl_instance_id=0, dao_sequence=5, status=0)
    assert ack.to_bytes() == bytes([0x00, 0x00, 0x05, 0x00])


def test_dao_ack_round_trip_with_dodagid() -> None:
    ack = DAOAck(rpl_instance_id=0, dao_sequence=5, status=0, dodag_id=DODAG)
    expected = bytes([0x00, 0x80, 0x05, 0x00]) + DODAG_PACKED  # D flag = 0x80
    assert ack.to_bytes() == expected
    assert DAOAck.from_bytes(expected) == ack


def test_option_pad1_and_padn_parsing() -> None:
    # Pad1 (single 0x00) followed by PadN(type=1,len=2,data=00 00).
    raw = bytes([0x00, 0x01, 0x02, 0x00, 0x00])
    dis = DIS.from_bytes(bytes([0x00, 0x00]) + raw)
    assert dis.options[0].type == RplOptionType.PAD1
    assert dis.options[1] == RplOption(RplOptionType.PADN, b"\x00\x00")


def test_option_truncated_rejected() -> None:
    # Option type 5 claims length 4 but only 1 data byte present.
    with pytest.raises(RplError):
        DIS.from_bytes(bytes([0x00, 0x00, 0x05, 0x04, 0x01]))


def test_icmpv6_wrap_and_dispatch() -> None:
    for message, code in [
        (DIS(), RplCode.DIS),
        (DIO(0, 1, 256, 0, DODAG), RplCode.DIO),
        (DAO(0, 5, dodag_id=DODAG), RplCode.DAO),
        (DAOAck(0, 5), RplCode.DAO_ACK),
    ]:
        icmp = to_icmpv6(message)
        assert icmp.type == 155
        assert icmp.code == code
        assert from_icmpv6(icmp) == message


def test_from_icmpv6_rejects_non_rpl() -> None:
    with pytest.raises(RplError):
        from_icmpv6(Icmpv6Message(type=128, code=0, body=b""))


def test_from_icmpv6_rejects_unknown_code() -> None:
    with pytest.raises(RplError):
        from_icmpv6(Icmpv6Message(type=155, code=99, body=b""))


def test_dao_coerces_str_dodag_id() -> None:
    # DAO/DAO-ACK accept a string dodag_id like DIO (coerced to IPv6Address).
    dao = DAO(rpl_instance_id=0, dao_sequence=5, dodag_id="fd00::1")
    assert dao.dodag_id == IPv6Address("fd00::1")
    assert DAO.from_bytes(dao.to_bytes()) == dao

    ack = DAOAck(rpl_instance_id=0, dao_sequence=5, dodag_id="fd00::1")
    assert ack.dodag_id == IPv6Address("fd00::1")
    assert DAOAck.from_bytes(ack.to_bytes()) == ack
