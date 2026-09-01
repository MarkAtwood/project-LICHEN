#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate IPv6-in-IPv6 tunnel encapsulation/decapsulation test vectors.

Independent oracle for spec/05-routing.md 8.9 (R-05-063/R-05-066):
reimplements the root encapsulation and E-side decapsulation arithmetic
from the spec text only — no lichen package imports.

Wire rules encoded here:
  Outer: 40-byte IPv6 header, next_header=43 (Routing), hop_limit=64,
         src = root address, dst = first route hop; SRH (type 3) with
         segments_left = num_addrs, addresses = route[1..].
  Inner: Hop Limit decremented by the normal forwarding decrement (1)
         plus the initial Segments Left (num_addrs).  The initial Segments
         Left MUST be strictly less than the Hop Limit available after the
         forwarding decrement, else no route is emitted.
  Decap: outer must be a consistent IPv6 packet with next_header=41,
         inner must be a consistent IPv6 packet whose destination equals
         the expected (authorized primary) address; anything else fails
         closed.

Usage: python3 test/vectors/generate_tunnel_encapsulation.py \
           test/vectors/tunnel_encapsulation.json
"""

import json
import struct
import sys

IPV6_HEADER_LEN = 40
NH_IPV6_IN_IPV6 = 41
NH_ROUTING = 43
ROUTING_TYPE_SRH = 3
OUTER_HOP_LIMIT = 64


def checksum(src: bytes, dst: bytes, nh: int, payload: bytes) -> int:
    """Upper-layer checksum over the IPv6 pseudo-header (RFC 8200 8.1)."""
    pseudo = src + dst + struct.pack(">I", len(payload)) + bytes([0, 0, 0, nh])
    data = pseudo + payload
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv6_packet(src: bytes, dst: bytes, nh: int, hop_limit: int, payload: bytes) -> bytes:
    packet = bytearray(IPV6_HEADER_LEN + len(payload))
    packet[0] = 0x60
    packet[4:6] = struct.pack(">H", len(payload))
    packet[6] = nh
    packet[7] = hop_limit
    packet[8:24] = src
    packet[24:40] = dst
    packet[40:] = payload
    return bytes(packet)


def udp_inner(src: bytes, dst: bytes, hop_limit: int) -> bytes:
    """Minimal valid inner packet: IPv6 + 8-byte UDP header, valid checksum."""
    udp = bytearray(8)
    udp[0:2] = struct.pack(">H", 0x1633)  # source port (CoAP 5683)
    udp[1:2] = udp[0:2]
    udp[2:4] = struct.pack(">H", 8)  # length
    udp_payload = bytes(udp)
    csum = checksum(src, dst, 17, udp_payload)
    udp = bytearray(udp_payload)
    udp[6:8] = struct.pack(">H", csum)
    return ipv6_packet(src, dst, 17, hop_limit, bytes(udp))


def encapsulate(inner: bytes, root_addr: bytes, route: list) -> bytes:
    """Root-side tunnel encapsulation per spec 05-routing 8.9 (R-05-066)."""
    num_addrs = len(route) - 1
    hl_after_fwd = inner[7] - 1
    if num_addrs >= hl_after_fwd:
        return None  # no route: hop budget below initial Segments Left
    routing_len = 8 + 16 * num_addrs
    outer_payload = routing_len + len(inner)
    outer = bytearray(40 + routing_len)
    outer[0] = 0x60
    outer[4:6] = struct.pack(">H", outer_payload)
    outer[6] = NH_ROUTING
    outer[7] = OUTER_HOP_LIMIT
    outer[8:24] = root_addr
    outer[24:40] = route[0]
    outer[40] = NH_IPV6_IN_IPV6  # SRH next_header = inner IPv6
    outer[41] = routing_len // 8 - 1
    outer[42] = ROUTING_TYPE_SRH
    outer[43] = num_addrs  # initial Segments Left
    outer[44:48] = b"\x00" * 4
    for i, addr in enumerate(route[1:]):
        start = 48 + i * 16
        outer[start:start + 16] = addr
    decremented = bytearray(inner)
    decremented[7] = hl_after_fwd - num_addrs
    return bytes(outer) + bytes(decremented)


def hx(b: bytes) -> str:
    return b.hex()


def main() -> None:
    out_path = sys.argv[1] if len(sys.argv) > 1 else \
        "test/vectors/tunnel_encapsulation.json"

    root_addr = bytes.fromhex("0200" + "00" * 13 + "01")
    hop_a = bytes.fromhex("0200" + "00" * 13 + "02")
    hop_b = bytes.fromhex("0200" + "00" * 13 + "03")
    final = bytes.fromhex("0200" + "00" * 13 + "04")
    src = bytes.fromhex("fe80" + "00" * 13 + "0a")
    other = bytes.fromhex("0200" + "00" * 13 + "ff")

    vectors = {"encapsulation": [], "decapsulation": []}

    # --- Encapsulation: inner HL decrement + hop-budget rejection ----------
    for name, orig_hl, route in [
        ("encap_two_hops", 64, [hop_a, hop_b, final]),
        ("encap_one_hop", 64, [hop_a, final]),
        ("encap_min_hl_ok", 5, [hop_a, hop_b, final]),  # 5-1-2=2 > 0
    ]:
        num_addrs = len(route) - 1
        inner = udp_inner(src, final, orig_hl)
        outer = encapsulate(inner, root_addr, route)
        vectors["encapsulation"].append({
            "name": name,
            "description": (
                f"orig HL={orig_hl}, num_addrs={num_addrs} -> "
                f"inner HL={orig_hl - 1 - num_addrs}"
            ),
            "original_hop_limit": orig_hl,
            "num_addrs": num_addrs,
            "root_addr_hex": hx(root_addr),
            "route_hops_hex": [hx(h) for h in route],
            "inner_packet_hex": hx(inner),
            "expected_encapsulated_hex": hx(outer),
            "expected_inner_hop_limit": orig_hl - 1 - num_addrs,
            "expect": "encapsulate",
        })

    for name, orig_hl, route in [
        ("encap_reject_sl_equals_hl", 3, [hop_a, hop_b, final]),  # 2 >= 2
        ("encap_reject_sl_above_hl", 2, [hop_a, hop_b, hop_b, final]),
    ]:
        num_addrs = len(route) - 1
        inner = udp_inner(src, final, orig_hl)
        vectors["encapsulation"].append({
            "name": name,
            "description": (
                f"initial Segments Left ({num_addrs}) >= Hop Limit after "
                f"forwarding decrement ({orig_hl - 1}) — no route"
            ),
            "original_hop_limit": orig_hl,
            "num_addrs": num_addrs,
            "root_addr_hex": hx(root_addr),
            "route_hops_hex": [hx(h) for h in route],
            "inner_packet_hex": hx(inner),
            "expect": "no_route",
        })

    # --- Decapsulation: valid, inner-dst mismatch, malformed ---------------
    # decapsulate_ipv6 operates on the packet AFTER SRH consumption at the
    # final hop: the SRH has been stripped and next_header promoted to 41,
    # so the "outer" here is a 40-byte IPv6 header + inner packet.
    inner_ok = udp_inner(src, final, 60)
    outer_ok = ipv6_packet(root_addr, final, NH_IPV6_IN_IPV6, 64, inner_ok)

    vectors["decapsulation"].append({
        "name": "decap_valid",
        "description": "well-formed tunnel addressed to this node unwraps",
        "outer_packet_hex": hx(outer_ok),
        "expected_dst_hex": hx(final),
        "expected_inner_hex": hx(inner_ok),
        "expect": "decapsulate",
    })

    outer_mismatch = bytearray(outer_ok)
    vectors["decapsulation"].append({
        "name": "decap_inner_dst_mismatch",
        "description": "inner destination is not the authorized primary — reject",
        "outer_packet_hex": hx(outer_mismatch),
        "expected_dst_hex": hx(other),
        "expect": "reject",
    })

    # Malformed: inner payload-length field shorter than the actual body.
    outer_short = bytearray(outer_ok)
    # inner payload_len := 0x00FF (255) while only 8 payload bytes follow:
    # 40 + 255 != frame length -> inconsistent -> reject.
    outer_short[44] = 0x00
    outer_short[45] = 0xFF
    vectors["decapsulation"].append({
        "name": "decap_inner_len_inconsistent",
        "description": "inner IPv6 payload-length inconsistent with frame — reject",
        "outer_packet_hex": hx(outer_short),
        "expected_dst_hex": hx(final),
        "expect": "reject",
    })

    # Malformed: outer next_header is not 41.
    outer_nh = bytearray(outer_ok)
    outer_nh[6] = 17
    vectors["decapsulation"].append({
        "name": "decap_outer_not_ipv6_in_ipv6",
        "description": "outer next_header is not 41 — reject",
        "outer_packet_hex": hx(outer_nh),
        "expected_dst_hex": hx(final),
        "expect": "reject",
    })

    # Malformed: truncated inner (frame ends mid-header).
    outer_trunc = outer_ok[:50]
    vectors["decapsulation"].append({
        "name": "decap_inner_truncated",
        "description": "inner header truncated — reject",
        "outer_packet_hex": hx(outer_trunc),
        "expected_dst_hex": hx(final),
        "expect": "reject",
    })

    corpus = {
        "vector_type": "tunnel_encapsulation",
        "format_version": 1,
        "description": (
            "IPv6-in-IPv6 tunnel encapsulation/decapsulation conformance "
            "for spec/05-routing.md 8.9 (R-05-063/R-05-066): root-side "
            "inner Hop-Limit decrement with hop-budget rejection, and "
            "fail-closed E-side decapsulation with inner-destination "
            "verification."
        ),
        "oracle": {
            "basis": "spec/05-routing.md 8.9 (R-05-063, R-05-066) + RFC 2473 model",
            "implementation": "independent generator; no lichen package imports",
            "generator_command": (
                "python3 test/vectors/generate_tunnel_encapsulation.py "
                "test/vectors/tunnel_encapsulation.json"
            ),
        },
        "constants": {
            "outer_hop_limit": OUTER_HOP_LIMIT,
            "outer_next_header": NH_ROUTING,
            "inner_next_header": NH_IPV6_IN_IPV6,
            "forwarding_decrement": 1,
        },
        **vectors,
    }

    with open(out_path, "w") as handle:
        json.dump(corpus, handle, indent=2)
        handle.write("\n")
    print(f"wrote {out_path}: "
          f"{len(vectors['encapsulation'])} encapsulation, "
          f"{len(vectors['decapsulation'])} decapsulation vectors")


if __name__ == "__main__":
    main()
