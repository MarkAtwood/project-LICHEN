#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate independent /deaddrop SCHC compressed-packet vectors.

spec/12-apps.md:1737 mandates that implementations match test-vector outputs
for compressed /deaddrop packets. appendix-schc.md A.4.1 provisions the rules:
POSTs MUST use Rule 5 (link-local) or Rule 6 (Yggdrasil) with OSCORE; GETs use
Rule 5/6 when OSCORE-protected and Rule 0/1 for unprotected reads of public
drops. No dedicated rule IDs are allocated.

This generator is an independent oracle: it imports neither the Python nor the
Rust SCHC implementation. IPv6/UDP/CoAP and the Rule 0/1/5/6 residues are
encoded directly from the wire specification (appendix-schc.md A.3/A.4). The
OSCORE ciphertext is pinned from ``deaddrop.json`` (an independent oracle
shared by both stacks), not derived here.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEADDROP_SOURCE = ROOT / "test" / "vectors" / "deaddrop.json"
OUTPUT = ROOT / "test" / "vectors" / "deaddrop_schc.json"

COAP_PORT = 5683
LINK_LOCAL_SOURCE = bytes.fromhex("fe800000000000000000000000000001")
LINK_LOCAL_DESTINATION = bytes.fromhex("fe800000000000000000000000000002")
GLOBAL_SOURCE = bytes.fromhex("027dd5cfc679ab637dd5cfc679ab6342")
GLOBAL_DESTINATION = bytes.fromhex("02f77a7baa1226b5f57a7baa1226b50c")

COAP_CODE_GET = 1
COAP_CODE_POST = 2
OSCORE_OPTION_NUMBER = 9
URI_PATH_OPTION_NUMBER = 11

# The OSCORE Object-Security option and ciphertext for a /deaddrop POST, pinned
# from the independent deaddrop.json oracle (oscore_wrapped_dead_drop). The
# Uri-Path "deaddrop" and Content-Format 112 are Inner options encrypted inside
# the ciphertext, so they do not appear as outer CoAP options on the wire.
DEADDROP_OSCORE_VECTOR = "oscore_wrapped_dead_drop"


def _sum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(
        int.from_bytes(data[offset : offset + 2], "big") for offset in range(0, len(data), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _udp_checksum(source: bytes, destination: bytes, udp: bytes) -> int:
    pseudo = source + destination + len(udp).to_bytes(4, "big") + bytes((0, 0, 0, 17))
    checksum = (~_sum16(pseudo + udp)) & 0xFFFF
    return checksum or 0xFFFF


def _coap_option(number: int, value: bytes) -> bytes:
    if not 0 <= number <= 12 or not 0 <= len(value) <= 12:
        raise ValueError("fixture uses only directly encoded CoAP option nibbles")
    return bytes(((number << 4) | len(value),)) + value


def _pack_bits(fields: list[tuple[int, int]]) -> bytes:
    value = 0
    width = 0
    for field, bits in fields:
        if field < 0 or field >= 1 << bits:
            raise ValueError(f"field {field} does not fit {bits} bits")
        value = (value << bits) | field
        width += bits
    padding = (-width) % 8
    return (value << padding).to_bytes((width + padding) // 8, "big")


def _build_ipv6_udp(source: bytes, destination: bytes, coap: bytes) -> bytes:
    udp_length = 8 + len(coap)
    udp_zero = (
        COAP_PORT.to_bytes(2, "big")
        + COAP_PORT.to_bytes(2, "big")
        + udp_length.to_bytes(2, "big")
        + b"\x00\x00"
        + coap
    )
    checksum = _udp_checksum(source, destination, udp_zero)
    udp = udp_zero[:6] + checksum.to_bytes(2, "big") + udp_zero[8:]
    ipv6 = (
        b"\x60\x00\x00\x00" + udp_length.to_bytes(2, "big") + bytes((17, 64)) + source + destination
    )
    return ipv6 + udp


def _residue(
    source: bytes,
    destination: bytes,
    code: int,
    message_id: int,
    token_length: int,
    address_lsb_bits: int,
) -> bytes:
    lsb_bytes = address_lsb_bits // 8
    return _pack_bits(
        [
            (64, 8),  # Hop Limit (value-sent)
            (int.from_bytes(source[16 - lsb_bytes :], "big"), address_lsb_bits),
            (int.from_bytes(destination[16 - lsb_bytes :], "big"), address_lsb_bits),
            (COAP_PORT & 0x0F, 4),  # UDP source port LSB(4)
            (COAP_PORT & 0x0F, 4),  # UDP destination port LSB(4)
            # CoAP.version is Mo::Equal/Cda::NotSent (target 1): zero residue
            # bits. CoAP.type (CON=0) is value-sent in 2 bits.
            (0, 2),  # CoAP type (CON)
            (token_length, 4),  # CoAP TKL
            (code, 8),  # CoAP code
            (message_id, 16),  # CoAP message ID
        ]
    )


def _build(
    rule_id: int,
    source: bytes,
    destination: bytes,
    code: int,
    message_id: int,
    tail: bytes,
    address_lsb_bits: int,
    residue_octets: int,
) -> tuple[bytes, bytes]:
    coap = bytes((0x40, code)) + message_id.to_bytes(2, "big") + tail
    packet = _build_ipv6_udp(source, destination, coap)
    residue = _residue(source, destination, code, message_id, 0, address_lsb_bits)
    if len(residue) != residue_octets:
        raise AssertionError(f"Rule {rule_id} residue must be {residue_octets} octets")
    compressed = bytes((rule_id,)) + residue + coap[4:]
    return packet, compressed


def _deaddrop_oscore() -> tuple[str, str]:
    source = json.loads(DEADDROP_SOURCE.read_text())
    for vector in source["vectors"]:
        if vector["name"] == DEADDROP_OSCORE_VECTOR:
            return vector["expected"]["oscore_option"], vector["ciphertext"]
    raise ValueError(f"{DEADDROP_OSCORE_VECTOR} not present in {DEADDROP_SOURCE.name}")


def main() -> int:
    oscore_option, ciphertext = _deaddrop_oscore()
    oscore_tail = _coap_option(OSCORE_OPTION_NUMBER, bytes.fromhex(oscore_option))
    oscore_tail += b"\xff" + bytes.fromhex(ciphertext)
    uri_path_tail = _coap_option(URI_PATH_OPTION_NUMBER, b"deaddrop")

    message_id = 0x1234

    def next_mid() -> int:
        nonlocal message_id
        current = message_id
        message_id += 1
        return current

    vectors = []

    def add(
        name: str,
        direction: str,
        rule_id: int,
        source: bytes,
        destination: bytes,
        code: int,
        tail: bytes,
        address_lsb_bits: int,
        residue_octets: int,
        scope: str,
        protection: str,
    ) -> None:
        packet, compressed = _build(
            rule_id, source, destination, code, next_mid(), tail, address_lsb_bits, residue_octets
        )
        vectors.append(
            {
                "name": name,
                "direction": direction,
                "rule_id": rule_id,
                "scope": scope,
                "protection": protection,
                "coap_code": code,
                "message_id": int.from_bytes(packet[50:52], "big"),
                "ipv6_packet": packet.hex(),
                "compressed": compressed.hex(),
            }
        )

    add(
        "deaddrop_post_linklocal",
        "POST",
        5,
        LINK_LOCAL_SOURCE,
        LINK_LOCAL_DESTINATION,
        COAP_CODE_POST,
        oscore_tail,
        64,
        22,
        "link-local",
        "oscore",
    )
    add(
        "deaddrop_post_global",
        "POST",
        6,
        GLOBAL_SOURCE,
        GLOBAL_DESTINATION,
        COAP_CODE_POST,
        oscore_tail,
        120,
        36,
        "yggdrasil",
        "oscore",
    )
    add(
        "deaddrop_get_protected_linklocal",
        "GET",
        5,
        LINK_LOCAL_SOURCE,
        LINK_LOCAL_DESTINATION,
        COAP_CODE_GET,
        oscore_tail,
        64,
        22,
        "link-local",
        "oscore",
    )
    add(
        "deaddrop_get_public_linklocal",
        "GET",
        0,
        LINK_LOCAL_SOURCE,
        LINK_LOCAL_DESTINATION,
        COAP_CODE_GET,
        uri_path_tail,
        64,
        22,
        "link-local",
        "plaintext",
    )
    add(
        "deaddrop_get_public_global",
        "GET",
        1,
        GLOBAL_SOURCE,
        GLOBAL_DESTINATION,
        COAP_CODE_GET,
        uri_path_tail,
        120,
        36,
        "yggdrasil",
        "plaintext",
    )

    document = {
        "name": "deaddrop_schc",
        "format_version": 2,
        "description": (
            "Independent /deaddrop SCHC compressed-packet vectors (appendix-schc.md "
            "A.4.1). POSTs use Rule 5/6 with OSCORE (Uri-Path and Content-Format 112 "
            "are Inner options encrypted in the ciphertext); public GETs use Rule 0/1 "
            "with Uri-Path carried verbatim in the tail. IPv6/UDP/CoAP and residues "
            "are encoded directly from the wire specification by this generator; the "
            "OSCORE ciphertext is pinned from deaddrop.json."
        ),
        "spec": "spec/appendix-schc.md A.4.1; spec/12-apps.md 18.9",
        "source_vectors": ["test/vectors/deaddrop.json"],
        "generator": "test/vectors/generate_deaddrop_schc.py",
        "vectors": vectors,
    }
    OUTPUT.write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(vectors)} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
