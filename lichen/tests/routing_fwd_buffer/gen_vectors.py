#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Generate API-compatible forwarding-buffer fixtures from canonical vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def generate(input_path: Path) -> str:
    document = json.loads(input_path.read_text(encoding="utf-8"))
    if document.get("vector_type") != "forwarding_buffer" or document.get("format_version") != 1:
        raise ValueError("unexpected forwarding-buffer vector document")
    oracle = document.get("oracle")
    if not isinstance(oracle, dict):
        raise ValueError("forwarding-buffer oracle is missing")

    rows = []
    for vector in document.get("vectors", []):
        if vector.get("operation") != "try_buffer":
            continue
        inputs = vector.get("inputs", {})
        expected = vector.get("expected", {})
        precondition = vector.get("precondition", {}).get("state", {})
        source_order = precondition.get("source_order", [])
        source = inputs.get("source_iid")
        if not isinstance(source, str) or len(source) != 16:
            raise ValueError(f"invalid source_iid in {vector.get('name')}")
        if expected.get("result") not in {"ACCEPTED", "BACKPRESSURE", "EVICTED"}:
            raise ValueError(f"unsupported result in {vector.get('name')}")
        if expected.get("result") == "EVICTED" and len(source_order) != int(
            oracle["max_forwarding_sources"]
        ):
            continue
        setup = ", ".join(
            "{ 0, 0, 0, 0, 0, 0, 0, %d }" % int(iid[-2:], 16)
            for iid in source_order
        )
        rows.append(
            "    { \"%s\", { 0, 0, 0, 0, 0, 0, 0, %d }, UINT32_C(%d), %s, %du, { %s } },"
            % (
                vector["name"],
                int(source[-2:], 16),
                inputs["now_ms"],
                {"ACCEPTED": "FWD_ACCEPTED", "BACKPRESSURE": "FWD_BACKPRESSURE", "EVICTED": "FWD_EVICTED"}[expected["result"]],
                len(source_order),
                setup,
            )
        )
    if not rows:
        raise ValueError("no try_buffer vectors")
    return """/* Generated from test/vectors/forwarding_buffer.json. */
#ifndef FORWARDING_BUFFER_VECTORS_H_
#define FORWARDING_BUFFER_VECTORS_H_

#include <stdint.h>

#define FWD_MAX_SOURCES %du
#define FWD_MAX_PER_SOURCE %du
#define FWD_TOTAL_CAPACITY %du

enum forwarding_vector_result { FWD_ACCEPTED, FWD_BACKPRESSURE, FWD_EVICTED };
struct forwarding_vector {
    const char *name;
    uint8_t source_iid[8];
    uint32_t now_ms;
    enum forwarding_vector_result result;
    uint8_t setup_count;
    uint8_t setup_sources[FWD_MAX_SOURCES][8];
};

static const struct forwarding_vector forwarding_vectors[] = {
%s
};

#define FORWARDING_VECTOR_COUNT \
    (sizeof(forwarding_vectors) / sizeof(forwarding_vectors[0]))

#endif
""" % (
        oracle["max_forwarding_sources"],
        oracle["max_packets_per_source"],
        oracle["total_capacity"],
        "\n".join(rows),
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} INPUT.json OUTPUT.h", file=sys.stderr)
        return 2
    Path(sys.argv[2]).write_text(generate(Path(sys.argv[1])), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
