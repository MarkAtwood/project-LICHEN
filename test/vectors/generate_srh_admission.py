#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate RFC 6554 source-route admission vectors without importing LICHEN.

Oracle: hand-constructed packets from RFC 8200 IPv6/extension-header layouts,
RFC 6554 RH3 fields, and RFC 768 UDP framing using Python stdlib only. Every
``verdict`` is a fixed spec-derived literal matching the C router's
``parse_ipv6_dispatch`` policy (lichen/subsys/lichen/routing/router.c):

- ``admit_in_transit``: admitted, RH3 with ``segments_left != 0`` present, so
  the datagram has forwarding precedence and must never be delivered locally.
- ``admit_consumed``: admitted with no in-transit RH3 (no Routing header, a
  consumed RH3, or No-Next-Header termination with no trailing bytes).
- ``reject``: dropped outright (any admission stage).

The expected verdicts are committed literals, never production return values;
the Rust and Python admission tests compare their implementations against this
file. Per RFC 6554 4.2 the CmprI/CmprE octet and the Pad bits must be zero
while the remaining reserved bits are ignored.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json_batch,
    json_bytes,
    read_bounded_exact,
)

OUTPUT = VECTORS_DIR / "srh_admission.json"
SCHEMA = VECTORS_DIR / "srh_admission.schema.json"

NEXT_HEADER_HOP_BY_HOP = 0
NEXT_HEADER_TCP = 6
NEXT_HEADER_UDP = 17
NEXT_HEADER_ICMPV6 = 58
NEXT_HEADER_ROUTING = 43
NEXT_HEADER_FRAGMENT = 44
NEXT_HEADER_DEST_OPTIONS = 60
NEXT_HEADER_NONE = 59
HOP_LIMIT = 64

# Deterministic primary 0200::/8 test identities (never real keys).
SOURCE = "02000000000000000000000000000001"
RELAY_A = "02000000000000000000000000000002"
RELAY_B = "02000000000000000000000000000003"
FINAL = "02000000000000000000000000000004"
UDP_HEADER = "0000000000080000"

Header = tuple[int, str]  # (own next-header type, body after the 2-byte prefix)


def rh3(
    segments_left: int,
    addresses: list[str],
    *,
    routing_type: int = 3,
    cmpr_octet: int = 0,
    pad_octet: int = 0,
    reserved_octets: str = "0000",
) -> Header:
    """RFC 6554 Routing header for the RPL source-route profile (type 3)."""
    body = (
        f"{routing_type:02x}"
        + f"{segments_left:02x}"
        + f"{cmpr_octet:02x}"
        + f"{pad_octet:02x}"
        + reserved_octets
        + "".join(addresses)
    )
    return (NEXT_HEADER_ROUTING, body)


def rh3_raw(body: str) -> Header:
    """Routing header with an explicit body (for length/type violations)."""
    return (NEXT_HEADER_ROUTING, body)


def hbh() -> Header:
    return (NEXT_HEADER_HOP_BY_HOP, "000000000000")


def dest_options() -> Header:
    return (NEXT_HEADER_DEST_OPTIONS, "000000000000")


def fragment() -> Header:
    # Offset 0, M flag clear, identification 0.
    return (NEXT_HEADER_FRAGMENT, "000000000000")


def extension_wire(own_type: int, body_hex: str, following_type: int) -> str:
    """One 8-octet-multiple extension header of the common TLV shape."""
    body = bytes.fromhex(body_hex)
    total = 2 + len(body)
    if total % 8 or total < 8:
        raise ValueError("extension header must be a positive multiple of 8 octets")
    return f"{following_type:02x}{total // 8 - 1:02x}" + body_hex


def packet(
    *,
    dst: str,
    src: str = SOURCE,
    hop_limit: int = HOP_LIMIT,
    upper: int = NEXT_HEADER_UDP,
    extensions: list[Header] | None = None,
    payload: str = UDP_HEADER,
) -> str:
    """Assemble a complete datagram: header, extension chain, payload."""
    chain = ""
    exts = list(extensions or [])
    for index, (own_type, body) in enumerate(exts):
        following = exts[index + 1][0] if index + 1 < len(exts) else upper
        chain += extension_wire(own_type, body, following)
    first = exts[0][0] if exts else upper
    payload_len = (len(chain) + len(payload)) // 2
    header = (
        "60000000"
        + f"{payload_len:04x}"
        + f"{first:02x}"
        + f"{hop_limit:02x}"
        + src
        + dst
    )
    return header + chain + payload


CASES: list[dict[str, object]] = [
    {
        "name": "udp_no_routing_header",
        "description": "Plain UDP datagram without any Routing header is deliverable at its destination.",
        "packet": packet(dst=FINAL),
        "verdict": "admit_consumed",
    },
    {
        "name": "in_transit_two_segments",
        "description": "RH3 with segments_left 2 at relay A has forwarding precedence and must be relayed, never delivered locally.",
        "packet": packet(dst=RELAY_A, extensions=[rh3(2, [RELAY_B, FINAL])]),
        "verdict": "admit_in_transit",
    },
    {
        "name": "consumed_at_final",
        "description": "RH3 with segments_left 0 at the final destination is deliverable; the RFC 6554 swap-back keeps grid addresses distinct from the outer destination.",
        "packet": packet(dst=FINAL, extensions=[rh3(0, [RELAY_A, RELAY_B])]),
        "verdict": "admit_consumed",
    },
    {
        "name": "degenerate_zero_address_consumed",
        "description": "A minimal 8-octet RH3 with segments_left 0 and an empty grid is admitted (the C router admits Routing header lengths down to 8 octets).",
        "packet": packet(dst=FINAL, extensions=[rh3(0, [])]),
        "verdict": "admit_consumed",
    },
    {
        "name": "reserved_ignored_octets_admitted",
        "description": "RFC 6554 4.2: the low nibble of the Pad/Reserved octet and Reserved octets 6-7 are ignored when CmprI/CmprE and Pad are zero.",
        "packet": packet(
            dst=FINAL,
            extensions=[
                rh3(0, [RELAY_A, RELAY_B], pad_octet=0x01, reserved_octets="7f2a")
            ],
        ),
        "verdict": "admit_consumed",
    },
    {
        "name": "hop_by_hop_then_routing_in_transit",
        "description": "A leading Hop-by-Hop header followed by an in-transit RH3 is admitted.",
        "packet": packet(
            dst=RELAY_B,
            extensions=[hbh(), rh3(1, [FINAL])],
        ),
        "verdict": "admit_in_transit",
    },
    {
        "name": "dest_options_pair_admitted",
        "description": "Repeated Destination Options headers are tolerated (only Hop-by-Hop is unique).",
        "packet": packet(dst=FINAL, extensions=[dest_options(), dest_options()]),
        "verdict": "admit_consumed",
    },
    {
        "name": "next_header_none_empty",
        "description": "No-Next-Header termination with no trailing bytes is admitted.",
        "packet": packet(dst=FINAL, upper=NEXT_HEADER_NONE, payload=""),
        "verdict": "admit_consumed",
    },
    {
        "name": "reject_grid_equals_outer_destination",
        "description": "RH3 grid containing the outer destination is rejected (router-level final-address check).",
        "packet": packet(dst=RELAY_A, extensions=[rh3(2, [RELAY_B, RELAY_A])]),
        "verdict": "reject",
    },
    {
        "name": "reject_grid_equals_source",
        "description": "RH3 grid containing the packet source is rejected (forwarding loop).",
        "packet": packet(dst=RELAY_A, extensions=[rh3(1, [SOURCE])]),
        "verdict": "reject",
    },
    {
        "name": "reject_grid_unspecified",
        "description": "RH3 grid containing the unspecified address is rejected.",
        "packet": packet(dst=RELAY_A, extensions=[rh3(1, ["0" * 32])]),
        "verdict": "reject",
    },
    {
        "name": "reject_grid_multicast",
        "description": "RH3 grid containing a multicast address is rejected.",
        "packet": packet(
            dst=RELAY_A,
            extensions=[rh3(1, ["ff020000000000000000000000000001"])],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_duplicate_grid",
        "description": "RH3 grid repeating an address is rejected.",
        "packet": packet(dst=RELAY_A, extensions=[rh3(2, [RELAY_B, RELAY_B])]),
        "verdict": "reject",
    },
    {
        "name": "reject_segments_left_exceeds_addresses",
        "description": "segments_left greater than the RH3 address count is rejected.",
        "packet": packet(dst=RELAY_A, extensions=[rh3(3, [RELAY_B, FINAL])]),
        "verdict": "reject",
    },
    {
        "name": "reject_segments_left_gte_hop_limit",
        "description": "In-transit RH3 with segments_left >= hop_limit cannot complete the route and is rejected (spec 05-routing 8.4).",
        "packet": packet(
            dst=RELAY_A,
            hop_limit=2,
            extensions=[rh3(2, [RELAY_B, FINAL])],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_hop_limit_zero",
        "description": "A datagram with an exhausted Hop Limit is rejected before any routing decision.",
        "packet": packet(dst=FINAL, hop_limit=0),
        "verdict": "reject",
    },
    {
        "name": "reject_source_unspecified",
        "description": "A datagram whose source address is unspecified is rejected.",
        "packet": packet(src="0" * 32, dst=FINAL),
        "verdict": "reject",
    },
    {
        "name": "reject_source_multicast",
        "description": "A datagram whose source address is multicast is rejected.",
        "packet": packet(src="ff020000000000000000000000000001", dst=FINAL),
        "verdict": "reject",
    },
    {
        "name": "reject_routing_type_two",
        "description": "A Routing header whose type is not 3 is rejected (LICHEN admits only RH3).",
        "packet": packet(
            dst=RELAY_A,
            extensions=[rh3(1, [FINAL], routing_type=2)],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_second_routing_header",
        "description": "A second Routing header is rejected: RFC 8200 4.4 processes only the first and layered RH3s create ambiguous checksum scope.",
        "packet": packet(
            dst=FINAL,
            extensions=[rh3(0, [RELAY_A, RELAY_B]), rh3(0, [RELAY_A, RELAY_B])],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_misaligned_address_grid",
        "description": "A Routing header whose address grid is not a multiple of 16 octets is rejected: this 32-octet header carries a 24-byte grid.",
        "packet": packet(
            dst=FINAL,
            extensions=[rh3_raw("030000000000" + RELAY_A + "00" * 8)],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_four_extension_chain",
        "description": "Four extension headers before the upper protocol exceed the bounded embedded profile and are rejected (C router -E2BIG).",
        "packet": packet(
            dst=FINAL,
            extensions=[
                dest_options(),
                dest_options(),
                dest_options(),
                dest_options(),
            ],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_routing_header_beyond_chain_bound",
        "description": "An in-transit RH3 placed beyond the three-header chain bound is rejected, never admitted past unexamined headers.",
        "packet": packet(
            dst=RELAY_A,
            extensions=[
                dest_options(),
                dest_options(),
                dest_options(),
                rh3(1, [FINAL]),
            ],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_truncated_udp",
        "description": "A datagram whose UDP terminal header is shorter than eight octets is rejected (C router -EMSGSIZE).",
        "packet": packet(dst=FINAL, payload="00000000"),
        "verdict": "reject",
    },
    {
        "name": "reject_truncated_icmpv6",
        "description": "A datagram whose ICMPv6 terminal header is shorter than four octets is rejected (C router -EMSGSIZE).",
        "packet": packet(dst=FINAL, upper=NEXT_HEADER_ICMPV6, payload="0000"),
        "verdict": "reject",
    },
    {
        "name": "icmpv6_upper_admitted",
        "description": "An ICMPv6 datagram (RPL control and diagnostics ride ICMPv6) without a Routing header is deliverable at its destination.",
        "packet": packet(dst=FINAL, upper=NEXT_HEADER_ICMPV6, payload="8000" + "00" * 4),
        "verdict": "admit_consumed",
    },
    {
        "name": "reject_cmpr_octet_nonzero",
        "description": "A nonzero CmprI/CmprE octet is rejected (LICHEN's profile is uncompressed).",
        "packet": packet(
            dst=FINAL,
            extensions=[rh3(0, [RELAY_A, RELAY_B], cmpr_octet=0x01)],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_pad_nibble_nonzero",
        "description": "Nonzero Pad bits are rejected whenever CmprI/CmprE are zero (RFC 6554 4.2).",
        "packet": packet(
            dst=FINAL,
            extensions=[rh3(0, [RELAY_A, RELAY_B], pad_octet=0x10)],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_max_addresses_exceeded",
        "description": "A nine-address RH3 grid exceeds the eight-hop LICHEN route bound and is rejected.",
        "packet": packet(
            dst=FINAL,
            extensions=[
                rh3(
                    0,
                    [f"020000000000000000000000000000{index:02x}" for index in range(0x11, 0x1A)],
                )
            ],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_hop_by_hop_not_first",
        "description": "A Hop-by-Hop header that does not immediately follow the IPv6 header is rejected (RFC 8200 4.3).",
        "packet": packet(
            dst=FINAL,
            extensions=[dest_options(), hbh(), rh3(0, [RELAY_A, RELAY_B])],
        ),
        "verdict": "reject",
    },
    {
        "name": "reject_second_hop_by_hop",
        "description": "A repeated Hop-by-Hop header is rejected (RFC 8200 4.3).",
        "packet": packet(dst=FINAL, extensions=[hbh(), hbh()]),
        "verdict": "reject",
    },
    {
        "name": "reject_fragment_header",
        "description": "A Fragment header is rejected: SCHC fragmentation belongs below IPv6 and dual reassembly is ambiguous.",
        "packet": packet(dst=FINAL, extensions=[fragment()]),
        "verdict": "reject",
    },
    {
        "name": "reject_next_header_none_with_payload",
        "description": "No-Next-Header followed by trailing bytes is rejected: the bytes belong to no protocol and cannot be delivered.",
        "packet": packet(dst=FINAL, upper=NEXT_HEADER_NONE),
        "verdict": "reject",
    },
    {
        "name": "reject_unsupported_upper_protocol",
        "description": "A TCP payload is rejected: the LICHEN constrained profile admits only UDP and ICMPv6 upper protocols.",
        "packet": packet(dst=FINAL, upper=NEXT_HEADER_TCP, payload="aabbccdd"),
        "verdict": "reject",
    },
]


def document() -> dict[str, object]:
    return {
        "$schema": "./srh_admission.schema.json",
        "format_version": 2,
        "name": "srh_admission",
        "description": (
            "Cross-implementation RFC 6554 source-route admission vectors: "
            "forwarding precedence for in-transit RH3 datagrams and router-level "
            "rejection of malformed or non-canonical source routes."
        ),
        "spec": (
            "RFC 6554 Sections 4.1 and 4.2; RFC 8200 Sections 4.3 and 4.4; "
            "LICHEN spec/05-routing.md Section 8.4; C reference "
            "parse_ipv6_dispatch in lichen/subsys/lichen/routing/router.c"
        ),
        "verdicts": {
            "admit_in_transit": (
                "admitted with segments_left != 0: RFC 6554 forwarding precedence, "
                "relay to the next segment, never deliver locally"
            ),
            "admit_consumed": (
                "admitted with no in-transit RH3: deliverable at the outer destination"
            ),
            "reject": "dropped outright at admission",
        },
        "cases": CASES,
    }


SCHEMA_DOCUMENT: dict[str, object] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "LICHEN RFC 6554 source-route admission vectors",
    "type": "object",
    "required": ["$schema", "format_version", "name", "description", "spec", "verdicts", "cases"],
    "additionalProperties": False,
    "properties": {
        "$schema": {"const": "./srh_admission.schema.json"},
        "format_version": {"const": 2},
        "name": {"const": "srh_admission"},
        "description": {"type": "string", "minLength": 1},
        "spec": {"type": "string", "minLength": 1},
        "verdicts": {
            "type": "object",
            "required": ["admit_in_transit", "admit_consumed", "reject"],
            "additionalProperties": False,
            "properties": {
                "admit_in_transit": {"type": "string", "minLength": 1},
                "admit_consumed": {"type": "string", "minLength": 1},
                "reject": {"type": "string", "minLength": 1},
            },
        },
        "cases": {
            "type": "array",
            "minItems": 1,
            "items": {"$ref": "#/definitions/case"},
        },
    },
    "definitions": {
        "packet": {"type": "string", "pattern": "^(?:[0-9a-f]{2})+$"},
        "verdict": {
            "type": "string",
            "enum": ["admit_in_transit", "admit_consumed", "reject"],
        },
        "case": {
            "type": "object",
            "required": ["name", "description", "packet", "verdict"],
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string", "pattern": "^[a-z0-9_]+$"},
                "description": {"type": "string", "minLength": 1},
                "packet": {"$ref": "#/definitions/packet"},
                "verdict": {"$ref": "#/definitions/verdict"},
            },
        },
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed artifacts are byte-exact without writing",
    )
    args = parser.parse_args()

    outputs = [(OUTPUT, document()), (SCHEMA, SCHEMA_DOCUMENT)]
    if args.check:
        for path, expected in outputs:
            committed = read_bounded_exact(path)
            if committed != json_bytes(expected):
                print(f"out-of-date vector file: {path.name}", file=sys.stderr)
                return 1
        return 0
    atomic_write_json_batch(outputs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
