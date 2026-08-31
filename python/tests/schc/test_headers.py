# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for whole-packet SCHC compression (packet <-> field dicts)."""

from __future__ import annotations

from ipaddress import IPv6Address
from typing import cast

import aiocoap
import pytest
from aiocoap import GET, Message

from lichen.constants import PORT_MQTT_SN
from lichen.ipv6.icmpv6 import EchoRequest
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.link.link_layer import MAX_SINGLE_FRAME_SCHC_PACKET
from lichen.schc.codec import SchcError
from lichen.schc.fragment import MAX_PACKET_SIZE
from lichen.schc.headers import (
    compress_packet,
    decode_rule255,
    decompress_packet,
    encode_rule255,
    validate_full_ipv6,
)

SRC = IPv6Address("fe80::1")
DST = IPv6Address("fe80::2")
COAP_PORT = 5683


def _build_packet(
    coap_bytes: bytes,
    src: IPv6Address = SRC,
    dst: IPv6Address = DST,
    hop_limit: int = 64,
) -> bytes:
    udp = UdpDatagram(COAP_PORT, COAP_PORT, coap_bytes).to_bytes(src, dst)
    header = IPv6Header(
        src_addr=src,
        dst_addr=dst,
        next_header=NextHeader.UDP,
        payload_length=len(udp),
        hop_limit=hop_limit,
    )
    return header.to_bytes() + udp


def _coap_request() -> bytes:
    msg = Message(code=GET, uri="coap://dest/status")
    msg.mtype = aiocoap.CON
    msg.mid = 0x1234
    msg.token = b"\xaa\xbb"
    return cast(bytes, msg.encode())


def _build_mqtt_packet(
    payload: bytes,
    *,
    src: IPv6Address = SRC,
    dst: IPv6Address = DST,
    src_port: int = PORT_MQTT_SN,
    dst_port: int = 5000,
) -> bytes:
    udp = UdpDatagram(src_port, dst_port, payload).to_bytes(src, dst)
    return (
        IPv6Header(
            src_addr=src,
            dst_addr=dst,
            next_header=NextHeader.UDP,
            payload_length=len(udp),
            hop_limit=64,
        ).to_bytes()
        + udp
    )


def test_round_trip_compresses_real_coap_packet() -> None:
    raw = _build_packet(_coap_request())
    compressed = compress_packet(raw)
    assert compressed[0] == 0  # rule 0 (link-local CoAP)
    assert len(compressed) < len(raw)  # headers were compressed
    assert decompress_packet(compressed) == raw


def test_compressed_smaller_than_headers() -> None:
    raw = _build_packet(_coap_request())
    compressed = compress_packet(raw)
    # 40 (IPv6) + 8 (UDP) + 4 (CoAP fixed) = 52 header bytes collapse into the
    # 1-byte rule id + 25-byte residue; the variable CoAP tail is unchanged.
    header_bytes = HEADER_LENGTH + 8 + 4
    assert len(compressed) - len(_coap_request()[4:]) <= header_bytes


def test_coap_token_and_payload_survive() -> None:
    msg = Message(code=aiocoap.POST, uri="coap://dest/x", payload=b"sensor-reading")
    msg.mtype = aiocoap.CON
    msg.mid = 7
    msg.token = b"\x01\x02\x03"
    raw = _build_packet(msg.encode())
    restored = decompress_packet(compress_packet(raw))
    assert restored == raw
    # The reconstructed CoAP payload is intact.
    assert b"sensor-reading" in restored


def test_hop_limit_preserved() -> None:
    raw = _build_packet(_coap_request(), hop_limit=7)
    restored = decompress_packet(compress_packet(raw))
    assert IPv6Header.from_bytes(restored).hop_limit == 7


@pytest.mark.parametrize(
    ("src_port", "dst_port"),
    [(PORT_MQTT_SN, 5000), (5000, PORT_MQTT_SN), (PORT_MQTT_SN, PORT_MQTT_SN)],
)
def test_mqtt_sn_rule7_link_local_port_modes(src_port: int, dst_port: int) -> None:
    raw = _build_mqtt_packet(b"mqtt", src_port=src_port, dst_port=dst_port)
    compressed = compress_packet(raw)
    assert compressed[0] == 7
    assert len(compressed) == 21 + 4
    assert decompress_packet(compressed) == raw


@pytest.mark.parametrize(
    ("src", "dst"),
    [
        (IPv6Address("2001:db8::1"), IPv6Address("2001:db8::2")),
        (IPv6Address("fe80:0:0:1::1"), IPv6Address("fe80:0:0:2::2")),
    ],
)
def test_mqtt_sn_rule7_full_address_mode_round_trips(src: IPv6Address, dst: IPv6Address) -> None:
    raw = _build_mqtt_packet(b"mqtt", src=src, dst=dst)
    compressed = compress_packet(raw)
    assert compressed[0] == 7
    assert len(compressed) == 37 + 4
    assert decompress_packet(compressed) == raw


def test_mqtt_sn_rule7_rejects_invalid_elided_fields() -> None:
    valid = _build_mqtt_packet(b"mqtt")
    for offset, replacement in ((0, valid[0] | 1), (2, 1)):
        nonmatch = bytearray(valid)
        nonmatch[offset] = replacement
        assert compress_packet(bytes(nonmatch))[0] == 255

    for offset, replacement in (
        (5, (valid[5] + 1) & 0xFF),
        (45, (valid[45] + 1) & 0xFF),
        (46, 0),
        (47, valid[47] ^ 1),
    ):
        malformed = bytearray(valid)
        if offset == 46:
            malformed[46:48] = b"\x00\x00"
        else:
            malformed[offset] = replacement
        with pytest.raises(SchcError):
            compress_packet(bytes(malformed))


def test_mqtt_sn_rule7_rejects_noncanonical_residue_forms() -> None:
    canonical = bytearray(
        compress_packet(
            _build_mqtt_packet(
                b"x",
                src_port=PORT_MQTT_SN,
                dst_port=PORT_MQTT_SN,
            )
        )
    )
    canonical[20] |= 1
    with pytest.raises(SchcError, match="padding"):
        decompress_packet(bytes(canonical))

    canonical = bytearray(
        compress_packet(
            _build_mqtt_packet(
                b"x",
                src_port=PORT_MQTT_SN,
                dst_port=PORT_MQTT_SN,
            )
        )
    )
    canonical[18] |= 0x40
    with pytest.raises(SchcError, match="direction"):
        decompress_packet(bytes(canonical))


def test_mqtt_sn_rule7_checksum_zero_serializes_as_ffff() -> None:
    payload = next(
        value.to_bytes(2, "big")
        for value in range(1 << 16)
        if _build_mqtt_packet(value.to_bytes(2, "big"))[46:48] == b"\xff\xff"
    )
    raw = _build_mqtt_packet(payload)
    assert raw[46:48] == b"\xff\xff"
    assert decompress_packet(compress_packet(raw)) == raw


def test_mqtt_sn_rule7_rejects_invalid_full_mode_addresses() -> None:
    # Structure checks precede address checks (mirroring Rust/C order), so a
    # multicast source that the UDP datagram constructor also rejects surfaces
    # the UDP-layer message first.
    for source, destination, message in (
        (IPv6Address("ff02::1"), IPv6Address("2001:db8::2"), "malformed source"),
        (IPv6Address("2001:db8::1"), IPv6Address("::"), "address"),
    ):
        raw = _build_mqtt_packet(b"x", src=source, dst=destination)
        with pytest.raises(SchcError, match=message):
            compress_packet(raw)

    for wire in (
        "0740ff810000000000000000000000000000900086dc00000000000000000000000104e20078",
        "0740900086dc0000000000000000000000008000000000000000000000000000000004e20078",
    ):
        with pytest.raises(SchcError, match="address"):
            decompress_packet(bytes.fromhex(wire))


def test_mqtt_sn_rule7_profile_size_boundary() -> None:
    # The profile ceiling bounds the RAW packet (the fragmenter's reassembly
    # buffer), not the encoded form: raw == MAX_PACKET_SIZE compresses
    # (encoded = raw - 27); raw == MAX_PACKET_SIZE + 1 is rejected before
    # rule dispatch.
    payload = bytes(MAX_PACKET_SIZE - 48)
    raw = _build_mqtt_packet(payload)
    compressed = compress_packet(raw)
    assert len(compressed) == MAX_PACKET_SIZE - 27
    assert decompress_packet(compressed) == raw

    raw_over = _build_mqtt_packet(bytes(MAX_PACKET_SIZE - 47))
    with pytest.raises(SchcError, match="profile limit"):
        compress_packet(raw_over)


def test_mqtt_sn_rule7_full_address_profile_size_boundary() -> None:
    # Raw-bound contract as above; the full-address residue shifts the
    # encoded size by +16 relative to the canonical-address variant.
    payload = bytes(MAX_PACKET_SIZE - 48)
    raw = _build_mqtt_packet(
        payload,
        src=IPv6Address("2001:db8::1"),
        dst=IPv6Address("2001:db8::2"),
    )
    compressed = compress_packet(raw)
    assert len(compressed) == MAX_PACKET_SIZE - 11
    assert decompress_packet(compressed) == raw

    raw_over = _build_mqtt_packet(
        bytes(MAX_PACKET_SIZE - 47),
        src=IPv6Address("2001:db8::1"),
        dst=IPv6Address("2001:db8::2"),
    )
    with pytest.raises(SchcError, match="profile limit"):
        compress_packet(raw_over)


def test_custom_profiles_do_not_replace_reserved_rule7() -> None:
    mqtt = _build_mqtt_packet(b"x")
    assert compress_packet(mqtt, profiles=())[0] == 7
    assert decompress_packet(compress_packet(mqtt), profiles=()) == mqtt


def test_rule255_rejects_zero_udp_checksum() -> None:
    raw = bytearray(_build_mqtt_packet(b"x"))
    raw[46:48] = b"\x00\x00"
    with pytest.raises(SchcError, match="checksum"):
        decode_rule255(b"\xff" + bytes(raw))


def test_validate_full_ipv6_structure_precedes_address_checks() -> None:
    # Dual-defect packets report a STRUCTURAL error first, mirroring Rust
    # validate_full_ipv6 (codec.rs:363-366) and the C compress gate order:
    # the address message must never surface for a packet whose structure
    # is also invalid.
    for src, dst, zero_message, corrupt_message in (
        # mcast src: UdpDatagram.from_bytes rejects zero checksums before its
        # source check, and rejects the source itself when checksum != 0.
        (IPv6Address("ff02::1"), IPv6Address("2001:db8::1"),
         "checksum is zero", "malformed source"),
        # loopback src: from_bytes passes (loopback is not checked there),
        # so both defects surface through the checksum machinery.
        (IPv6Address("::1"), IPv6Address("2001:db8::1"),
         "checksum is zero", "checksum"),
    ):
        raw = bytearray(_build_packet(_coap_request(), src=src, dst=dst))
        raw[46:48] = b"\x00\x00"  # zero UDP checksum
        with pytest.raises(SchcError, match=zero_message):
            decode_rule255(b"\xff" + bytes(raw))
        raw[46] ^= 0xFF  # corrupt it instead
        with pytest.raises(SchcError, match=corrupt_message):
            decode_rule255(b"\xff" + bytes(raw))
        with pytest.raises(SchcError, match=corrupt_message):
            validate_full_ipv6(bytes(raw))


def test_rule255_emission_rejects_policy_invalid_endpoints() -> None:
    # Canonical TX/RX split (spec/03-adaptation.md): encode must not originate
    # loopback, IPv4-mapped, or bad-scope-multicast endpoints.
    cases = [
        ("::1", "2001:db8::1", "invalid IPv6 source address"),
        ("::ffff:192.0.2.1", "2001:db8::1", "invalid IPv6 source address"),
        ("2001:db8::1", "::1", "invalid IPv6 destination address"),
        ("2001:db8::1", "::ffff:192.0.2.1", "invalid IPv6 destination address"),
        ("2001:db8::1", "ff01::1", "invalid IPv6 destination multicast scope"),
        ("2001:db8::1", "ff0f::1", "invalid IPv6 destination multicast scope"),
    ]
    for src, dst, message in cases:
        raw = _build_packet(_coap_request(), src=IPv6Address(src), dst=IPv6Address(dst))
        with pytest.raises(SchcError, match=message):
            encode_rule255(raw)
        with pytest.raises(SchcError, match=message):
            compress_packet(raw)


def test_rule255_accepts_policy_valid_endpoints() -> None:
    raw = _build_packet(
        _coap_request(),
        src=IPv6Address("2001:db8::1"),
        dst=IPv6Address("ff15::1"),
    )
    encoded = encode_rule255(raw)
    assert encoded == b"\xff" + raw
    assert decode_rule255(encoded) == raw


def test_rule255_decode_is_byte_preserving_despite_emission_policy() -> None:
    # A structurally valid packet that violates only the emission policy
    # still decodes byte-preserving (interop with pre-canonicalization senders).
    raw = _build_packet(_coap_request(), src=IPv6Address("::1"), dst=IPv6Address("2001:db8::1"))
    assert decode_rule255(b"\xff" + raw) == raw


def _rule255_schc_bytes(encoded_length: int) -> bytes:
    data_length = encoded_length - 1 - 40 - 8
    icmp = (
        EchoRequest(identifier=1, sequence=1, data=bytes(data_length))
        .to_message()
        .to_bytes(SRC, DST)
    )
    raw = IPv6Header(SRC, DST, NextHeader.ICMPV6, payload_length=len(icmp)).to_bytes() + icmp
    encoded = encode_rule255(raw)
    assert len(encoded) == encoded_length
    return encoded


def test_decode_rule255_enforces_single_frame_limit_only_when_given() -> None:
    limit = MAX_SINGLE_FRAME_SCHC_PACKET
    at_ceiling = _rule255_schc_bytes(limit)
    above_ceiling = _rule255_schc_bytes(limit + 1)

    assert decode_rule255(at_ceiling, single_frame_limit=limit) == at_ceiling[1:]
    with pytest.raises(SchcError, match="single frame limit"):
        decode_rule255(above_ceiling, single_frame_limit=limit)
    assert decode_rule255(above_ceiling) == above_ceiling[1:]


def test_non_linklocal_falls_back_to_uncompressed() -> None:
    # Addresses outside fe80::/10 and 02xx::/8 don't match any rule -> fallback 255.
    doc = IPv6Address("2001:db8::1")
    raw = _build_packet(_coap_request(), src=doc, dst=doc)
    compressed = compress_packet(raw)
    assert compressed[0] == 255
    assert decompress_packet(compressed) == raw


def test_03xx_is_not_a_native_profile_address() -> None:
    raw = _build_packet(
        _coap_request(),
        src=IPv6Address("0300::1"),
        dst=IPv6Address("0300::2"),
    )
    compressed = compress_packet(raw)
    assert compressed[0] == 255
    assert decompress_packet(compressed) == raw


def test_non_udp_packet_falls_back() -> None:
    header = IPv6Header(SRC, DST, NextHeader.ICMPV6, payload_length=4)
    raw = header.to_bytes() + bytes(4)
    compressed = compress_packet(raw)
    assert compressed[0] == 255
    assert decompress_packet(compressed) == raw


def test_truncated_input_is_rejected_before_rule255() -> None:
    """Rule 255 carries a full validated IPv6 packet, never arbitrary bytes."""
    with pytest.raises(SchcError):
        compress_packet(b"")
    short = b"\x60" + b"\x00" * 10  # partial IPv6 header
    with pytest.raises(SchcError):
        compress_packet(short)


def test_truncated_udp_packet_is_rejected() -> None:
    # IPv6 header with UDP next header but no payload
    header = IPv6Header(
        src_addr=SRC,
        dst_addr=DST,
        next_header=NextHeader.UDP,
        payload_length=0,
    )
    raw = header.to_bytes()
    with pytest.raises(SchcError):
        compress_packet(raw)


def test_packet_with_trailing_bytes_falls_back() -> None:
    raw = _build_packet(_coap_request()) + b"junk"
    with pytest.raises(SchcError):
        compress_packet(raw)


def test_packet_with_invalid_udp_length_is_rejected() -> None:
    raw = bytearray(_build_packet(_coap_request()))
    raw[HEADER_LENGTH + 4 : HEADER_LENGTH + 6] = (8).to_bytes(2, "big")
    with pytest.raises(SchcError):
        compress_packet(bytes(raw))


def test_packet_with_invalid_udp_checksum_is_rejected() -> None:
    raw = bytearray(_build_packet(_coap_request()))
    raw[HEADER_LENGTH + 6] ^= 0x01
    with pytest.raises(SchcError):
        compress_packet(bytes(raw))


def test_truncated_icmpv6_falls_back() -> None:
    """A valid IPv6 header with ICMPv6 but truncated payload falls back."""
    header = IPv6Header(
        src_addr=SRC,
        dst_addr=DST,
        next_header=NextHeader.ICMPV6,
        payload_length=2,  # Too short for echo base (needs 8)
    )
    raw = header.to_bytes() + bytes(2)
    compressed = compress_packet(raw)
    assert compressed[0] == 255  # Falls back


def test_decompress_rejects_truncated_packet_residue() -> None:
    # Rule 0 requires 1 rule-ID byte + 22 residue bytes (174 bits) = 23 minimum.
    # 22 total bytes is 1 short.
    with pytest.raises(SchcError, match="need 23|too short"):
        decompress_packet(bytes(22))


def test_decompress_missing_tail_bytes_is_rejected() -> None:
    coap = bytes([0x48, 0x01, 0x12, 0x34]) + bytes(8)
    raw = _build_packet(coap)
    compressed = compress_packet(raw)
    with pytest.raises(SchcError):
        decompress_packet(compressed[:-8])


def test_decompress_rejects_plain_content_under_oscore_rule() -> None:
    compressed = bytearray(compress_packet(_build_packet(_coap_request())))
    compressed[0] = 5
    with pytest.raises(SchcError, match="does not reconstruct its packet profile"):
        decompress_packet(bytes(compressed))


def test_oscore_without_payload_compresses_to_oscore_rule() -> None:
    """OSCORE-protected CoAP GET without payload must use OSCORE rule (5), not plain CoAP.

    Per RFC 7252, the payload marker (0xFF) is ONLY present if there is a payload.
    A valid OSCORE-protected CoAP message without payload body is legal and should
    still be detected as OSCORE-protected.
    """
    # Build a minimal OSCORE-protected CoAP GET with no payload:
    # Ver=1, T=0 (CON), TKL=0 -> 0x40
    # Code=GET (0.01) -> 0x01
    # MID -> 0x00 0x01
    # OSCORE option (option 9): delta=9, length=2 -> (9 << 4) | 2 = 0x92
    # OSCORE value: flags=0x09 (partial IV len=1, kid present), PIV=0x01
    # No payload marker (0xFF) - this is valid per RFC 7252 when there's no payload
    coap_oscore_no_payload = bytes(
        [
            0x40,  # Ver=1, T=CON, TKL=0
            0x01,  # Code: GET
            0x00,
            0x01,  # Message ID
            0x92,  # Option: delta=9 (OSCORE), length=2
            0x09,
            0x01,  # OSCORE value: flags + partial IV
            # No 0xFF payload marker - valid for empty payload
        ]
    )
    raw = _build_packet(coap_oscore_no_payload)
    compressed = compress_packet(raw)
    # Must match OSCORE rule 5 (link-local), not plain CoAP rule 0
    assert compressed[0] == 5, "OSCORE without payload should use OSCORE rule 5, not CoAP rule 0"
    # Round-trip must work
    assert decompress_packet(compressed) == raw


# ─── routing-header policy (RFC 6554 RH3-only, RFC 2460 section 8.1) ──────────


def _build_srh_packet(
    routing_type: int,
    segments_left: int,
    hop: IPv6Address,
    *,
    checksum_dst: IPv6Address | None = None,
    use_fragment: bool = False,
) -> bytes:
    """Build an IPv6 datagram with a Routing (or Fragment) header.

    The UDP checksum is computed over ``checksum_dst`` so tests can pin the
    RFC 2460 section 8.1 pseudo-header destination independently of the outer
    header destination.
    """
    udp = UdpDatagram(5000, 5001, b"ping").to_bytes(SRC, checksum_dst or DST)
    if use_fragment:
        body = bytes([NextHeader.UDP, 0, 0, 0, 0, 0, 0, 1]) + udp
        next_header = NextHeader.FRAGMENT
    else:
        # RFC 6554 RH3: next_header, hdr_ext_len, type, segments_left,
        # CmprI/CmprE, Pad/Reserved, Reserved
        rh3 = bytes([NextHeader.UDP, 2, routing_type, segments_left, 0, 0, 0, 0]) + hop.packed
        body = rh3 + udp
        next_header = NextHeader.ROUTING
    header = IPv6Header(
        src_addr=SRC,
        dst_addr=DST,
        next_header=next_header,
        payload_length=len(body),
        hop_limit=64,
    )
    return header.to_bytes() + body


def test_valid_rh3_in_transit_falls_back_byte_preserving() -> None:
    """In-transit RH3 with checksum over the final destination round-trips via 255."""
    final = IPv6Address("fe80::a")
    raw = _build_srh_packet(3, 1, final, checksum_dst=final)
    compressed = compress_packet(raw)
    assert compressed == b"\xff" + raw
    assert decompress_packet(compressed) == raw


def test_routing_type_zero_is_rejected() -> None:
    """RFC 5095 deprecated Routing type 0 must not be forwarded under Rule 255."""
    with pytest.raises(SchcError, match="routing"):
        compress_packet(_build_srh_packet(0, 1, IPv6Address("fe80::b")))


def test_rh3_segments_left_overflow_is_rejected() -> None:
    with pytest.raises(SchcError, match="segments-left"):
        compress_packet(_build_srh_packet(3, 2, IPv6Address("fe80::c")))


def test_fragment_header_is_rejected() -> None:
    with pytest.raises(SchcError):
        compress_packet(_build_srh_packet(0, 0, DST, use_fragment=True))


def test_rh3_checksum_over_outer_destination_is_rejected() -> None:
    """In-transit RH3 whose checksum covers the outer destination is malformed."""
    raw = _build_srh_packet(3, 1, IPv6Address("fe80::a"), checksum_dst=DST)
    with pytest.raises(SchcError, match="checksum"):
        compress_packet(raw)


def _prepend_hbh(raw: bytes) -> bytes:
    """Insert an 8-byte Hop-by-Hop header (six Pad1 options) after the IPv6 header."""
    header = bytearray(raw[:HEADER_LENGTH])
    header[6] = NextHeader.HOP_BY_HOP
    header[4:6] = (len(raw) - HEADER_LENGTH + 8).to_bytes(2, "big")
    hbh = bytes([NextHeader.UDP, 0, 0, 0, 0, 0, 0, 0])
    return bytes(header) + hbh + raw[HEADER_LENGTH:]


def test_hbh_led_udp_bad_checksum_is_rejected() -> None:
    """A Hop-by-Hop chain does not bypass UDP checksum validation."""
    raw = bytearray(_build_mqtt_packet(b"ping", src_port=5000, dst_port=5001))
    raw[HEADER_LENGTH + 6 : HEADER_LENGTH + 8] = b"\xde\xad"
    with pytest.raises(SchcError, match="checksum"):
        compress_packet(_prepend_hbh(bytes(raw)))


def test_ext_header_led_udp_length_mismatch_is_rejected() -> None:
    """The UDP length field must match the bytes present even after ext headers."""
    raw = bytearray(_build_srh_packet(3, 1, IPv6Address("fe80::a")))
    raw[HEADER_LENGTH + 24 + 4 : HEADER_LENGTH + 24 + 6] = (8).to_bytes(2, "big")
    with pytest.raises(SchcError, match="UDP datagram|length"):
        compress_packet(bytes(raw))


def test_plain_udp_zero_checksum_is_rejected() -> None:
    """Wire checksum zero is malformed on non-SCHC ports too (0xFFFF encodes computed-zero)."""
    raw = bytearray(_build_mqtt_packet(b"ping", src_port=5000, dst_port=5001))
    raw[HEADER_LENGTH + 6 : HEADER_LENGTH + 8] = b"\x00\x00"
    with pytest.raises(SchcError, match="checksum"):
        compress_packet(bytes(raw))
