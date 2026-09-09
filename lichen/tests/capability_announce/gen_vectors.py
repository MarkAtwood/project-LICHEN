#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Translate the canonical capability announcement corpus into a C fixture.

The corpus wire bytes are CBOR tag 18 wrapped (see
test/vectors/generate_capability_announcements.py); the C module decodes
strictly untagged COSE_Sign1, so the fixture emits both the tagged bytes
as carried and the untagged array encoding (the tag content).  The tag
wrapper is a single 0xd2 byte followed by the content encoding, so
stripping it is loss-free; the untagged form is byte-identical to what
python to_cose_sign1() emits for the same announcement.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def array(name: str, value: str) -> str:
    octets = bytes.fromhex(value)
    body = ",".join(f"0x{byte:02x}" for byte in octets)
    return f"static const uint8_t {name}[] = {{{body}}};\n"


def main() -> None:
    root = Path(__file__).resolve().parents[3]
    data = json.loads((root / "test/vectors/capability_announcements.json").read_text())
    out = ["/* Generated from test/vectors/capability_announcements.json. */\n"]

    rows: list[str] = []
    for vector in data["vectors"]:
        name = vector["name"]
        wire = bytes.fromhex(vector["cose_sign1"])
        if wire[0] != 0xD2:
            raise ValueError(f"{name}: expected CBOR tag 18 wrapper, got 0x{wire[0]:02x}")
        expected = vector.get("expected", {})
        kid_mismatch = expected.get("iid_match", True) is False
        reserved_zero = expected.get("reserved_bits_zero", True)
        out.append(f"/* {name}: {vector.get('description', '')} */\n")
        out.append(array(f"wire_{name}", wire[1:].hex()))
        out.append(array(f"wire_tagged_{name}", vector["cose_sign1"]))
        out.append(array(f"pubkey_{name}", vector["public_key"]))
        announcer = f"announcer_iid_{name}" if "announcer_iid" in vector else "NULL"
        if "announcer_iid" in vector:
            out.append(array(f"announcer_iid_{name}", vector["announcer_iid"]))
        has_prefix = "prefix" in vector and "prefix_len" in vector
        prefix_ref = "NULL"
        if has_prefix and vector["prefix"]:
            out.append(array(f"prefix_{name}", vector["prefix"]))
            prefix_ref = f"prefix_{name}"
        if "capabilities" in vector:
            out.append(f"static const uint32_t capabilities_{name} = {vector['capabilities']}U;\n")
        if "expiry" in vector:
            out.append(f"static const uint64_t expiry_{name} = UINT64_C({vector['expiry']});\n")
        if "seq" in vector:
            out.append(f"static const uint64_t seq_{name} = UINT64_C({vector['seq']});\n")
        rows.append(
            f"\t{{ .name = \"{name}\", .wire = wire_{name}, .wire_len = sizeof(wire_{name}),\n"
            f"\t  .wire_tagged = wire_tagged_{name}, .wire_tagged_len = sizeof(wire_tagged_{name}),\n"
            f"\t  .pubkey = pubkey_{name}, .announcer_iid = {announcer},\n"
            f"\t  .prefix = {prefix_ref}, .has_prefix_len = {'true' if has_prefix else 'false'}, .prefix_len = {vector['prefix_len'] if has_prefix else '0'},\n"
            f"\t  .has_capabilities = {'true' if 'capabilities' in vector else 'false'}, .capabilities = {f'capabilities_{name}' if 'capabilities' in vector else '0'},\n"
            f"\t  .has_expiry = {'true' if 'expiry' in vector else 'false'}, .expiry = {f'expiry_{name}' if 'expiry' in vector else '0'},\n"
            f"\t  .has_seq = {'true' if 'seq' in vector else 'false'}, .seq = {f'seq_{name}' if 'seq' in vector else '0'},\n"
            f"\t  .kid_mismatch = {'true' if kid_mismatch else 'false'}, .reserved_zero = {'true' if reserved_zero else 'false'} }},\n")

    out.append(
        "struct capability_vector {\n"
        "\tconst char *name;\n"
        "\tconst uint8_t *wire;\n"
        "\tsize_t wire_len;\n"
        "\tconst uint8_t *wire_tagged;\n"
        "\tsize_t wire_tagged_len;\n"
        "\tconst uint8_t *pubkey;\n"
        "\tconst uint8_t *announcer_iid;\n"
        "\tconst uint8_t *prefix;\n"
        "\tbool has_prefix_len;\n"
        "\tuint8_t prefix_len;\n"
        "\tbool has_capabilities;\n"
        "\tuint32_t capabilities;\n"
        "\tbool has_expiry;\n"
        "\tuint64_t expiry;\n"
        "\tbool has_seq;\n"
        "\tuint64_t seq;\n"
        "\tbool kid_mismatch;\n"
        "\tbool reserved_zero;\n"
        "};\n"
        "static const struct capability_vector vectors[] = {\n"
        + "".join(rows)
        + "};\n")

    Path(sys.argv[1]).write_text("".join(out))


if __name__ == "__main__":
    main()
