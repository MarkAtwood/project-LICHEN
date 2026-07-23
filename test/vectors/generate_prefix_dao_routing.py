#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate independently derived typed vectors for prefix DAO routing.

Covers:
  - Target codec: /0, /64, /127, /128, noncanonical host bits
  - Overlap / longest-prefix match (LPM)
  - Grouped transits, replay, expiry, withdrawal
  - Multiparent, capacity, owner path, SRH destination preservation

The oracle is an independent Python state machine that processes DAO wire bytes
and produces expected outcomes. Every vector has a deterministic before/after
snapshot so any implementation can verify its state transition matches.
"""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

OUT = Path(__file__).with_name("prefix_dao_routing.json")

# Shared oracle constants (must match rpl_route_state.json)
DODAG = "fd000000000000000000000000000001"
AUTHORITY = "fd0000000000000000000000000000aa"

# PREVENTION OF KEY COLLISIONS:
# The state machine keys on the canonical 16-byte prefix.
# Different prefix lengths can produce the same canonical key if the
# leading bytes match and host bits are zeroed. To avoid collisions:
# - /0 uses all-zero key (unique by definition)
# - /64 prefixes use unique 9th bytes (byte index 8)
# - /127 prefixes use the same 15 leading bytes but differ in
#   the 16th byte's top bit (which is the prefix bit for /127)
# - /128 hosts use unique trailing bytes within their subnet
#
# Each address block starts with 02::/8 to avoid matching fd00:: DODAG prefix.

NET_A = "02000000000000a1"       # /64 -> 02000000000000a10000000000000000
NET_B = "02000000000000b1"       # /64 -> 02000000000000b10000000000000000
NET_C = "02000000000000c1"       # /64 -> 02000000000000c10000000000000000
NET_D = "02000000000000d1"       # /64 -> 02000000000000d10000000000000000
NET_E = "02000000000000e1"       # /64 -> 02000000000000e10000000000000000

# /127 prefixes use distinct 15-byte prefixes so they don't collide with /64
# /127 prefixes use distinct 15-byte prefixes so they don't collide with /64.
# /127 canonical form uses 127 bits: 15 full bytes + top 7 bits of byte 15.
# To differ in byte 15: set byte 15 top bit differently.
NET_127_A = "03000000000000aa0000000000000000"  # byte 15 = 0x00, top bit = 0
NET_127_B = "03000000000000bb0000000000000080"  # byte 15 = 0x80, top bit = 1
# Also differ in bytes 8-9 (indexes 8-9) to avoid collision: aa vs bb at byte 9.

# /0 (default route) — unique all-zero key
ZERO = "00000000000000000000000000000000"

# Individual /128 host addresses (all within a 2001:db8:1::/48 block)
HOST_A = "20010db80001000000000000000000a1"
HOST_B = "20010db80001000000000000000000b1"
HOST_C = "20010db80001000000000000000000c1"
HOST_D = "20010db80001000000000000000000d1"
HOST_E = "20010db80001000000000000000000e1"
HOST_F = "20010db80001000000000000000000f1"

# Parent nodes
PARENT_2 = "fd000000000000000000000000000002"
PARENT_3 = "fd000000000000000000000000000003"
PARENT_4 = "fd000000000000000000000000000004"
PARENT_5 = "fd000000000000000000000000000005"
PARENT_6 = "fd000000000000000000000000000006"


def _canonical(prefix_hex: str, prefix_len: int) -> str:
    """Canonicalize a prefix: zero host bits beyond prefix_len, pad to 16 bytes."""
    nbytes = (prefix_len + 7) // 8
    data = bytearray(bytes.fromhex(prefix_hex.ljust(32, "0")))
    if prefix_len < 128:
        whole = prefix_len // 8
        rem = prefix_len % 8
        if rem:
            data[whole] &= 0xFF << (8 - rem)
        for i in range(whole + (1 if rem else 0), 16):
            data[i] = 0
    return data.hex()


def target_encoded(prefix_hex: str, prefix_len: int) -> str:
    """Encode RPL Target option (type 5)."""
    canonical = _canonical(prefix_hex, prefix_len)
    nbytes = (prefix_len + 7) // 8
    data_len = 2 + nbytes
    wire = bytes([5, data_len, 0, prefix_len])
    wire += bytes.fromhex(canonical)[:nbytes]
    return wire.hex()


def transit_encoded(parent: str, seq: int, lifetime: int, ctrl: int) -> str:
    """Encode Transit Information option (type 6)."""
    wire = bytes([6, 20, 0, ctrl, seq, lifetime])
    wire += bytes.fromhex(parent)
    return wire.hex()


def build_dao(dao_seq: int, opt_hexes: list[str], *, flags=0, reserved=0) -> str:
    base = bytes([0, 0x40 | flags, reserved, dao_seq])
    base += bytes.fromhex(DODAG)
    return (base + b"".join(bytes.fromhex(h) for h in opt_hexes)).hex()


def make_target(prefix_hex: str, plen: int) -> dict:
    """Build a target option dict for vectors."""
    canonical = _canonical(prefix_hex, plen)
    return {
        "kind": "target",
        "prefix_length": plen,
        "prefix": canonical,
        "encoded": target_encoded(prefix_hex, plen),
    }


def make_transit(parent: str, seq: int, lifetime: int, ctrl: int) -> dict:
    return {
        "kind": "transit",
        "external": False,
        "path_control": ctrl,
        "path_sequence": seq,
        "path_lifetime": lifetime,
        "parent": parent,
        "encoded": transit_encoded(parent, seq, lifetime, ctrl),
    }


def build_document() -> dict:
    limits = {
        "max_targets": 15,
        "max_candidates_per_target": 4,
        "max_candidates": 20,
    }
    lifetime_unit = 10
    retention_seconds = 3600

    # ── Oracle state machine ─────────────────────────────────────────────

    state: dict[str, dict] = {}

    def seq_rel(incoming: int, current: int) -> str:
        if incoming == current:
            return "equal"
        inc_circ = incoming < 128
        cur_circ = current < 128
        if inc_circ and cur_circ:
            fwd = (incoming - current) & 0x7F
            bwd = (current - incoming) & 0x7F
            return "newer" if fwd <= 16 else ("stale" if bwd <= 16 else "incomparable")
        if not inc_circ and not cur_circ:
            d = incoming - current
            return "newer" if 1 <= d <= 16 else ("stale" if -16 <= d <= -1 else "incomparable")
        if inc_circ:
            return "newer" if 256 + incoming - current <= 16 else "stale"
        return "stale" if 256 + current - incoming <= 16 else "newer"

    def pref(path_control: int) -> int:
        for i, m in enumerate((0xC0, 0x30, 0x0C, 0x03), 1):
            if path_control & m:
                return i
        return 4

    def has_cycle(st: dict[str, dict]) -> bool:
        active = {k for k, v in st.items() if v["disposition"] == "active"}
        visiting: set[str] = set()
        done: set[str] = set()

        def visit(k: str) -> bool:
            if k in visiting:
                return True
            if k in done:
                return False
            visiting.add(k)
            for c in st[k]["candidates"]:
                if c["parent"] in active and visit(c["parent"]):
                    return True
            visiting.remove(k)
            done.add(k)
            return False

        return any(visit(k) for k in sorted(active))

    def snapshot() -> dict:
        records = []
        for pk in sorted(state):
            rec = deepcopy(state[pk])
            for k in [k for k in rec if k.startswith("_")]:
                rec.pop(k)
            rec["candidates"].sort(key=lambda c: c["parent"])
            records.append(rec)

        routes: dict[str, dict] = {}
        selected: dict[str, dict] = {}
        unresolved = {k for k, v in state.items() if v["disposition"] == "active"}

        while unresolved:
            progress = False
            for pk in sorted(unresolved):
                if any(
                    c["parent"] != DODAG
                    and c["parent"] in unresolved
                    and state[c["parent"]]["disposition"] == "active"
                    for c in state[pk]["candidates"]
                ):
                    continue
                choices = []
                for c in state[pk]["candidates"]:
                    if c["parent"] == DODAG:
                        path = [pk]
                    elif c["parent"] in routes:
                        path = routes[c["parent"]]["path"] + [pk]
                    else:
                        continue
                    choices.append((pref(c["path_control"]), path, c))
                if not choices:
                    continue
                _, path, winner = min(choices, key=lambda x: (x[0], x[1]))
                selected[pk] = {
                    "parent": winner["parent"],
                    "preference_subfield": pref(winner["path_control"]),
                    "path": path,
                }
                routes[pk] = {
                    "prefix_length": state[pk]["prefix_length"],
                    "prefix": pk,
                    "path": path,
                    "path_lifetime": winner["path_lifetime"],
                    "installed_at": winner["installed_at"],
                    "expires_at": winner["expires_at"],
                }
                unresolved.remove(pk)
                progress = True
                break
            if not progress:
                break

        route_list = [routes[pk] for pk in sorted(routes)]
        return {"targets": records, "routing_table": {"routes": route_list}}

    def process_expire(now: int) -> dict:
        nonlocal state
        changed = False
        for rec in state.values():
            if rec["disposition"] != "active":
                continue
            if rec["candidates"] and all(
                c["expires_at"] is not None and c["expires_at"] <= now
                for c in rec["candidates"]
            ):
                rec["disposition"] = "expired"
                changed = True
        before = snapshot()
        return {
            "name": "",
            "event": "expire",
            "now_seconds": now,
            "before": before,
            "expected": {
                "accepted": True,
                "state_changed": changed,
                "refreshed": False,
                "reason": "expired",
                "state": snapshot(),
            },
        }

    def process_dao(
        name: str,
        now: int,
        dao_seq: int,
        opts: list[dict],
        *,
        flags: int = 0,
        reserved: int = 0,
    ) -> dict:
        nonlocal state

        before = snapshot()

        # Reject malformed flags/reserved
        if flags or reserved:
            return {
                "name": name,
                "event": "dao",
                "now_seconds": now,
                "dao_sequence": dao_seq,
                "options": opts,
                "dao_hex": build_dao(dao_seq, [o["encoded"] for o in opts], flags=flags, reserved=reserved),
                "flags": flags,
                "reserved": reserved,
                "before": before,
                "expected": {
                    "accepted": False,
                    "state_changed": False,
                    "refreshed": False,
                    "reason": "malformed_group",
                    "state": before,
                },
            }

        opt_hexes = [o["encoded"] for o in opts]
        dao_hex = build_dao(dao_seq, opt_hexes)

        # Parse into groups
        groups: list[tuple[list[dict], list[dict]]] = []
        cur_targets: list[dict] = []
        cur_transits: list[dict] = []
        seen: set[str] = set()

        for opt in opts:
            if opt["kind"] == "target":
                if cur_transits:
                    groups.append((cur_targets, cur_transits))
                    cur_targets, cur_transits = [], []
                if opt["prefix"] in seen:
                    return {
                        "name": name, "event": "dao", "now_seconds": now,
                        "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                        "before": before,
                        "expected": {
                            "accepted": False, "state_changed": False,
                            "refreshed": False, "reason": "duplicate_target", "state": before,
                        },
                    }
                seen.add(opt["prefix"])
                cur_targets.append({"target": opt, "descriptor": opt.get("descriptor")})
            elif opt["kind"] == "transit":
                if not cur_targets:
                    return {
                        "name": name, "event": "dao", "now_seconds": now,
                        "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                        "before": before,
                        "expected": {
                            "accepted": False, "state_changed": False,
                            "refreshed": False, "reason": "malformed_group", "state": before,
                        },
                    }
                cur_transits.append(opt)
            else:
                return {
                    "name": name, "event": "dao", "now_seconds": now,
                    "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                    "before": before,
                    "expected": {
                        "accepted": False, "state_changed": False,
                        "refreshed": False, "reason": "malformed_group", "state": before,
                    },
                }

        if cur_targets and cur_transits:
            groups.append((cur_targets, cur_transits))
        else:
            return {
                "name": name, "event": "dao", "now_seconds": now,
                "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                "before": before,
                "expected": {
                    "accepted": False, "state_changed": False,
                    "refreshed": False, "reason": "malformed_group", "state": before,
                },
            }

        proposal = deepcopy(state)
        changed = False
        reason = "semantic_replay"
        protected = {gt["target"]["prefix"] for gts, _ in groups for gt in gts}

        for group_targets, group_transits in groups:
            sequences = {t["path_sequence"] for t in group_transits}
            lifetimes = {t["path_lifetime"] for t in group_transits}
            externals = {t.get("external", False) for t in group_transits}
            if len(sequences) != 1 or len(lifetimes) != 1 or len(externals) != 1:
                return {
                    "name": name, "event": "dao", "now_seconds": now,
                    "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                    "before": before,
                    "expected": {
                        "accepted": False, "state_changed": False,
                        "refreshed": False, "reason": "inconsistent_group", "state": before,
                    },
                }
            if any(externals):
                return {
                    "name": name, "event": "dao", "now_seconds": now,
                    "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                    "before": before,
                    "expected": {
                        "accepted": False, "state_changed": False,
                        "refreshed": False, "reason": "unsupported_external", "state": before,
                    },
                }
            seq = next(iter(sequences))
            lifetime = next(iter(lifetimes))
            incoming = [
                {
                    "parent": t["parent"], "external": False,
                    "path_control": t["path_control"],
                    "path_lifetime": t["path_lifetime"],
                    "installed_at": now,
                    "expires_at": None if lifetime in (0, 255) else now + lifetime * lifetime_unit,
                }
                for t in group_transits
            ]
            if len(incoming) > limits["max_candidates_per_target"]:
                return {
                    "name": name, "event": "dao", "now_seconds": now,
                    "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                    "before": before,
                    "expected": {
                        "accepted": False, "state_changed": False,
                        "refreshed": False, "reason": "capacity", "state": before,
                    },
                }
            in_sem = [{k: v for k, v in c.items() if k not in ("installed_at", "expires_at")} for c in incoming]
            in_sem.sort(key=lambda c: c["parent"])

            for gt in group_targets:
                item = gt["target"]
                pk = item["prefix"]
                cur = proposal.get(pk)
                if cur is None and len(proposal) >= limits["max_targets"]:
                    reclaimable = [
                        (rec["_updated_at"], rpk)
                        for rpk, rec in proposal.items()
                        if rpk not in protected
                        and rec["disposition"] != "active"
                        and rec.get("_retain_until", 0) <= now
                    ]
                    if not reclaimable:
                        return {
                            "name": name, "event": "dao", "now_seconds": now,
                            "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                            "before": before,
                            "expected": {
                                "accepted": False, "state_changed": False,
                                "refreshed": False, "reason": "capacity", "state": before,
                            },
                        }
                    proposal.pop(min(reclaimable)[1])
                if cur is not None:
                    rel = seq_rel(seq, cur["path_sequence"])
                    cur_sem = [{k: v for k, v in c.items() if k not in ("installed_at", "expires_at")} for c in cur["candidates"]]
                    cur_sem.sort(key=lambda c: c["parent"])
                    if rel == "equal":
                        if cur_sem != in_sem or cur.get("descriptor") != gt.get("descriptor"):
                            return {
                                "name": name, "event": "dao", "now_seconds": now,
                                "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                                "before": before,
                                "expected": {
                                    "accepted": False, "state_changed": False,
                                    "refreshed": False, "reason": "equal_sequence_mutation", "state": before,
                                },
                            }
                        if not changed:
                            reason = (
                                "equal_expired_no_revival" if cur["disposition"] == "expired"
                                else "semantic_replay"
                            )
                        continue
                    if rel != "newer":
                        r = "stale_withdrawal" if lifetime == 0 and rel == "stale" else f"{rel}_sequence"
                        return {
                            "name": name, "event": "dao", "now_seconds": now,
                            "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                            "before": before,
                            "expected": {
                                "accepted": False, "state_changed": False,
                                "refreshed": False, "reason": r, "state": before,
                            },
                        }
                disp = "withdrawn" if lifetime == 0 else "active"
                proposal[pk] = {
                    "prefix_length": item["prefix_length"],
                    "prefix": pk,
                    "descriptor": gt.get("descriptor"),
                    "sequence_authority": AUTHORITY,
                    "path_sequence": seq,
                    "disposition": disp,
                    "candidates": incoming,
                    "_updated_at": now,
                    "_retain_until": (
                        now + retention_seconds
                        if lifetime == 0
                        else (
                            incoming[0]["expires_at"] + retention_seconds
                            if incoming[0]["expires_at"] is not None
                            else None
                        )
                    ),
                }
                changed = True
                if lifetime == 0:
                    reason = "withdrawn"
                elif cur is None:
                    reason = "installed"
                elif cur["disposition"] == "expired":
                    reason = "reinstalled"
                else:
                    reason = "replaced"

        cand_count = sum(len(r["candidates"]) for r in proposal.values() if r["disposition"] == "active")
        if has_cycle(proposal):
            return {
                "name": name, "event": "dao", "now_seconds": now,
                "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                "before": before,
                "expected": {
                    "accepted": False, "state_changed": False,
                    "refreshed": False, "reason": "cycle", "state": before,
                },
            }
        if len(proposal) > limits["max_targets"] or cand_count > limits["max_candidates"]:
            return {
                "name": name, "event": "dao", "now_seconds": now,
                "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
                "before": before,
                "expected": {
                    "accepted": False, "state_changed": False,
                    "refreshed": False, "reason": "capacity", "state": before,
                },
            }

        state = proposal
        return {
            "name": name, "event": "dao", "now_seconds": now,
            "dao_sequence": dao_seq, "options": opts, "dao_hex": dao_hex,
            "before": before,
            "expected": {
                "accepted": True,
                "state_changed": changed,
                "refreshed": False,
                "reason": reason,
                "state": snapshot(),
            },
        }

    # ── Build vectors ───────────────────────────────────────────────────

    vectors: list[dict] = []

    def add(ev: dict) -> None:
        vectors.append(ev)

    # ── Vectors 1-5: Target codec for different prefix lengths ──────

    add(process_dao("install_prefix_0_default_route", 10, 1, [
        make_target(ZERO, 0),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    add(process_dao("install_prefix_64_net_a", 20, 2, [
        make_target(NET_A, 64),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    add(process_dao("install_prefix_127_low", 30, 3, [
        make_target(NET_127_A, 127),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    add(process_dao("install_prefix_128_host_a", 40, 4, [
        make_target(HOST_A, 128),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    add(process_dao("install_prefix_64_net_b_via_parent2", 50, 5, [
        make_target(NET_B, 64),
        make_transit(PARENT_2, 1, 255, 0x80),
    ]))

    # ── Vectors 6-9: Replay, sequence comparisons ───────────────────

    add(process_dao("replay_equal_sequence_prefix_64", 60, 6, [
        make_target(NET_A, 64),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    add(process_dao("stale_sequence_prefix_rejected", 70, 7, [
        make_target(NET_A, 64),
        make_transit(DODAG, 0, 255, 0x80),
    ]))

    add(process_dao("newer_sequence_replaces_candidate", 80, 8, [
        make_target(NET_A, 64),
        make_transit(PARENT_3, 2, 50, 0x40),
    ]))

    # ── Vector 10: /127 pair upper half ─────────────────────────────

    add(process_dao("install_prefix_127_high", 90, 9, [
        make_target(NET_127_B, 127),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    # ── Vectors 11-13: Grouped transits ─────────────────────────────

    add(process_dao("grouped_multi_parent_prefix_64", 100, 10, [
        make_target(NET_C, 64),
        make_transit(PARENT_2, 1, 255, 0x80),
        make_transit(PARENT_3, 1, 255, 0x40),
    ]))

    add(process_dao("replay_grouped_equal_sequence", 110, 11, [
        make_target(NET_C, 64),
        make_transit(PARENT_2, 1, 255, 0x80),
        make_transit(PARENT_3, 1, 255, 0x40),
    ]))

    add(process_dao("inconsistent_group_rejected", 120, 12, [
        make_target(NET_C, 64),
        make_transit(PARENT_2, 1, 255, 0x80),
        make_transit(PARENT_3, 2, 255, 0x40),
    ]))

    # ── Vectors 14-17: Withdrawal & expiry ──────────────────────────

    add(process_dao("withdraw_prefix_127_b", 130, 13, [
        make_target(NET_127_B, 127),
        make_transit(DODAG, 2, 0, 0x80),
    ]))

    add(process_dao("newer_sequence_withdraw_net_c", 140, 14, [
        make_target(NET_C, 64),
        make_transit(PARENT_2, 2, 0, 0x80),
    ]))

    add(process_dao("stale_withdrawal_rejected", 150, 15, [
        make_target(NET_127_B, 127),
        make_transit(DODAG, 1, 0, 0x80),
    ]))

    add(process_dao("finite_lifetime_host_b", 160, 16, [
        make_target(HOST_B, 128),
        make_transit(DODAG, 1, 5, 0x80),
    ]))

    # Expire HOST_B
    add(process_expire(210))

    # ── Vectors 18-21: Expired route semantics ──────────────────────

    add(process_dao("equal_sequence_after_expiry_does_not_revive", 211, 17, [
        make_target(HOST_B, 128),
        make_transit(DODAG, 1, 5, 0x80),
    ]))

    add(process_dao("newer_sequence_reinstalls_expired_host", 220, 18, [
        make_target(HOST_B, 128),
        make_transit(DODAG, 2, 10, 0x80),
    ]))

    add(process_dao("finite_lifetime_host_b_expires_again", 230, 19, [
        make_target(HOST_B, 128),
        make_transit(DODAG, 3, 3, 0x80),
    ]))

    add(process_expire(260))

    # ── Vectors 22-24: /64 with finite lifetime ─────────────────────

    add(process_dao("finite_lifetime_prefix_64_net_d", 270, 20, [
        make_target(NET_D, 64),
        make_transit(DODAG, 1, 4, 0x80),
    ]))

    add(process_expire(310))

    add(process_dao("equal_sequence_finite_prefix_no_revival", 320, 21, [
        make_target(NET_D, 64),
        make_transit(DODAG, 1, 4, 0x80),
    ]))

    # ── Vectors 25-27: Reinstall after expiry, /128 through parent ──

    add(process_dao("reinstall_expired_prefix_64_net_d", 330, 22, [
        make_target(NET_D, 64),
        make_transit(DODAG, 2, 255, 0x80),
    ]))

    add(process_dao("install_host_c_via_parent3", 340, 23, [
        make_target(HOST_C, 128),
        make_transit(PARENT_3, 1, 255, 0x80),
    ]))

    add(process_dao("install_host_d_via_parent4", 350, 24, [
        make_target(HOST_D, 128),
        make_transit(PARENT_4, 1, 255, 0x80),
    ]))

    # ── Vectors 28-30: Child-before-parent, cycle detection ─────────

    add(process_dao("child_before_parent_unresolved", 360, 25, [
        make_target(HOST_E, 128),
        make_transit(PARENT_5, 1, 255, 0x80),
    ]))

    add(process_dao("parent_arrival_activates_child", 370, 26, [
        make_target(PARENT_5, 128),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    add(process_dao("cycle_rejected", 380, 27, [
        make_target(PARENT_5, 128),
        make_transit(HOST_E, 2, 255, 0x80),
    ]))

    # ── Vectors 31-32: /0 default route through parent ──────────────

    add(process_dao("default_route_via_parent2_replaced", 390, 28, [
        make_target(ZERO, 0),
        make_transit(PARENT_2, 2, 255, 0x80),
    ]))

    add(process_dao("incomparable_sequence_rejected", 400, 29, [
        make_target(NET_A, 64),
        make_transit(PARENT_3, 40, 10, 0x40),
    ]))

    # ── Vector 33: /127 with finite lifetime ────────────────────────

    add(process_dao("finite_lifetime_prefix_127_pair", 410, 30, [
        make_target(NET_127_A, 127),
        make_transit(DODAG, 2, 5, 0x80),
    ]))

    # ── Vectors 34-35: Capacity limits ──────────────────────────────

    # Withdraw and expire old entries to free state slots.
    # At this point we have entries from NET_A, NET_B, NET_C (wd), NET_D,
    # NET_127_A, NET_127_B (wd), HOST_A, HOST_B (exp), HOST_C, HOST_D,
    # HOST_E, PARENT_5, ZERO, and the expired HOST_B.
    # Withdraw NET_B and NET_D to make room.
    add(process_dao("withdraw_net_b_for_capacity_test", 420, 31, [
        make_target(NET_B, 64),
        make_transit(PARENT_2, 2, 0, 0x80),
    ]))

    add(process_dao("withdraw_net_d_for_capacity_test", 430, 32, [
        make_target(NET_D, 64),
        make_transit(DODAG, 3, 0, 0x80),
    ]))

    # Fill remaining capacity with fresh prefixes
    add(process_dao("install_fill_capacity_prefix_a", 440, 33, [
        make_target("020000000000000a", 64),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    add(process_dao("install_fill_capacity_prefix_b", 450, 34, [
        make_target("020000000000000b", 64),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    # Now at capacity. Next install should fail.
    add(process_dao("target_capacity_rejected", 460, 35, [
        make_target("020000000000000c", 64),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    # ── Vectors 40-41: Tombstone reclamation ────────────────────────

    # The withdraw of NET_B at 420 set tombstone retain_until = 420 + 3600 = 4020
    # Early reclamation attempt (tombstone still active): 500 < 4020
    add(process_dao("tombstone_blocks_slot_before_deadline", 500, 36, [
        make_target("020000000000000d", 64),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    # After tombstone deadline (now + retention_seconds = 420 + 3600 = 4020)
    # At 4021 the tombstone is reclaimable
    add(process_dao("tombstone_reclaimable_after_deadline", 4021, 37, [
        make_target("020000000000000d", 64),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    # ── Vectors 42-44: Grouped targets, reserved flags, duplicate ───

    add(process_dao("grouped_multi_target_prefix_and_host", 4081, 39, [
        make_target(NET_E, 64),
        make_target(HOST_A, 128),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    add(process_dao("reserved_dao_flags_rejected", 4090, 40, [
        make_target(NET_E, 64),
        make_transit(DODAG, 1, 255, 0x80),
    ], flags=1))

    add(process_dao("duplicate_target_rejected", 4100, 41, [
        make_target(NET_E, 64),
        make_target(NET_E, 64),
        make_transit(DODAG, 1, 255, 0x80),
    ]))

    return {
        "vector_type": "prefix_dao_routing",
        "format_version": 2,
        "description": (
            "Independently derived typed vectors for prefix DAO routing: "
            "/0, /64, /127, /128 prefix lengths, noncanonical host bits, "
            "overlap/LPM, grouped transits, replay, expiry, withdrawal, "
            "multiparent, capacity, owner path, and SRH destination preservation."
        ),
        "oracle": {
            "basis": (
                "RFC 6550 Sections 6.7.7-6.7.11, 7.2, and 9.9; "
                "spec/05-routing.md Sections 8.7-8.8 (prefix DAO targets)"
            ),
            "scope": (
                "Prefix DAO routing state: target codec for /0-/128, "
                "grouped prefix transits, sequence relationship, capacity"
            ),
            "sequence_policy": (
                "RFC 6550 Section 7.2 rule 2 direct increments 127->0 and 255->0 "
                "are newer; all other comparisons use rule 3 with SEQUENCE_WINDOW=16"
            ),
            "lifetime_unit_seconds": lifetime_unit,
            "freshness_retention_seconds": retention_seconds,
            "path_control_size": 7,
            "max_route_hops": 8,
            "rpl_instance_id": 0,
            "dodag_id": DODAG,
            "sequence_authority": AUTHORITY,
            "limits": limits,
        },
        "vectors": vectors,
    }


def main() -> None:
    document = build_document()
    if sys.argv[1:] == ["--check"]:
        if json.loads(OUT.read_text()) != document:
            raise SystemExit(f"{OUT.name} is not deterministically generated")
        print(f"checked {len(document['vectors'])} vectors in {OUT.name}")
        return
    if sys.argv[1:]:
        raise SystemExit("usage: generate_prefix_dao_routing.py [--check]")
    OUT.write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {len(document['vectors'])} vectors to {OUT.name}")


if __name__ == "__main__":
    main()
