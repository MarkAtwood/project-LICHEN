# SPDX-FileCopyrightText: The contributors to the LICHEN project
# SPDX-License-Identifier: GPL-3.0-or-later

"""DTN store-and-forward IPv6 hop-by-hop option (spec/05-routing.md 9.8).

Option Type=0x03, Length=5: one flags byte (S=0x80, reserved bits MUST be
ignored on receive) followed by the absolute expiry as a 4-byte big-endian
Unix timestamp. Clockless nodes MUST NOT drop messages based on expiry
alone (spec/05-routing.md 9.8 clockless rule; docs/firmware-time-provider.md).

Vectors: test/vectors/dtn_sflag_hbh.json (spec-derived independent oracle).
"""

from __future__ import annotations

from dataclasses import dataclass

OPT_PAD1 = 0x00
OPT_PADN = 0x01
OPT_DTN = 0x03
DTN_OPTION_LEN = 5
DTN_FLAG_S = 0x80


@dataclass(frozen=True)
class DtnOption:
    """Parsed DTN hop-by-hop option."""

    s_flag: bool
    expiry_unix: int


def parse_dtn_option(hbh_data: bytes) -> DtnOption | None:
    """Extract the DTN intent from Hop-by-Hop option data.

    Returns ``None`` when the DTN option is absent, duplicated,
    malformed (wrong length), or carries a zero expiry — the caller
    cannot distinguish "no DTN intent" from "malformed", and both mean
    "no store-and-forward for this packet".
    """
    found: DtnOption | None = None
    pos = 0
    while pos < len(hbh_data):
        opt_type = hbh_data[pos]
        if opt_type == OPT_PAD1:
            pos += 1
            continue
        if pos + 2 > len(hbh_data):
            return None
        opt_len = hbh_data[pos + 1]
        end = pos + 2 + opt_len
        if end > len(hbh_data):
            return None
        if opt_type == OPT_DTN:
            if found is not None or opt_len != DTN_OPTION_LEN:
                return None
            flags = hbh_data[pos + 2]
            expiry = int.from_bytes(hbh_data[pos + 3 : end], "big")
            # expiry==0 is the C fail-open "no validated deadline"
            # sentinel (routing/dtn.h) and never a valid wire expiry;
            # rejecting it keeps Python parity with the C parser.
            if expiry == 0:
                return None
            found = DtnOption(s_flag=bool(flags & DTN_FLAG_S), expiry_unix=expiry)
        pos = end
    return found


def decide_expiry_action(
    expiry_unix: int, now_unix: int, wall_clock_valid: bool
) -> str:
    """Expiry decision per spec/05-routing.md 9.8 clockless rule.

    Returns ``"drop_silently"`` when the wall clock is valid and the
    message has expired; otherwise ``"store_or_forward"`` (a clockless
    node MUST NOT drop based on expiry alone — spec/05-routing.md 9.8).
    """
    if wall_clock_valid and expiry_unix < now_unix:
        return "drop_silently"
    return "store_or_forward"
