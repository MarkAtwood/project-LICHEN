<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# spec/appendix-schc.md — flagged for verification (sweep 2026-09-09)

2 of 35 requirements flagged. Neither is section 06-security, and no row concerns
oscore/EDHOC internal semantics (A.4 is SCHC framing around the OSCORE option, with
round-trip test evidence in all three stacks), so both flags are confidence/verbatim
-reference driven.

## F1 — R-SCHC-019: "RET X=10s; MAX_ACK_REQUESTS=4 (initial All-1 plus at most three later request emissions)"

- **Classification:** implemented+tested in Rust and Python; implemented+untested in C
  (Confidence: low)
- **Evidence:**
  - Rust: `RETRANSMISSION_TIMEOUT_S=10` (rust/lichen-schc/src/fragment.rs:18-19), attempt
    budget 4 with abort (fragment.rs:1966, 2277-2303); timer test
    `authenticated_fixed_retransmission_timer_is_exact_and_bounded` (fragment.rs:3908-3938).
  - Python: `RETRANSMISSION_TIMEOUT_SECONDS=10.0` (fragment.py:56), `MAX_ACK_REQUESTS=4`
    (fragment.py:42), tests test_fragment.py:742/759/770-795.
  - C: `SCHC_RETRANSMISSION_TIMEOUT_S 10` is **declared** in
    lichen/subsys/lichen/schc/include/lichen/schc.h:107, but `rg SCHC_RETRANSMISSION_TIMEOUT_S`
    across `lichen/` (all .c/.h, apps, tests) returns only the definition — no enforcement
    site. The generic engine (`lichen/subsys/schc/schc.c` SENDER_RETRANSMIT) bounds attempts
    (`SCHC_FRAGMENT_MAX_ATTEMPTS 4u`) but owns no time constant; the session layer enforces
    the ACK budget (4) and the 60 s hold-down, but not the 10 s sender timer.
  - constants.toml `[schc.fragment] retransmission_timeout_s = 10` (:71) and the draft
    (§5.1 "Retransmission timer | 10 seconds, fixed") agree with the spec value.
- **Question for Opus:** Is caller-owned retransmission timing an accepted design in the C
  stack (in which case the appendix should note it and the constant is a provisioning value
  only), or is the missing 10 s enforcement a conformant-implementation gap for any Zephyr
  node built on `lichen/subsys/lichen/schc/`? If the latter, where should the timer live
  (session wrapper vs. Zephyr integration layer)? Bead: [spec-gap][R-SCHC-019].

## F2 — R-SCHC-018: fragmentation profile constants ("TILE_SIZE=179 … from [schc.fragment]")

- **Classification:** implemented+tested for all values in all three stacks; the spec's
  **source attribution is divergent** (Confidence: high on values, the reference defect is
  bead-tracked)
- **Evidence:**
  - Values correct everywhere: Rust `TILE_SIZE=(185*8-15-32)/8=179` (fragment.rs:28-29);
    Python `TILE_SIZE=179` (fragment.py:37, derived from FRAGMENT_ENVELOPE_MTU=185); C
    `SCHC_FRAGMENT_TILE_SIZE 179u` (lichen/subsys/schc/include/schc/schc.h:125) with
    `_Static_assert(... == 179u)` in lichen/tests/schc_fragment_generation/main.c:205.
  - Divergence: spec/appendix-schc.md lines 8 and 56 cite "constants.toml [schc.fragment]"
    as the source of TILE_SIZE=179, but `[schc.fragment]` (constants.toml:64-74) contains
    m, n, t, window_size, rcs_bytes, retransmission_timeout_s, max_ack_requests,
    inactivity_timeout_s, bitmap_msb_first — **no `tile_size` key** (grep over
    constants.toml: 0 hits). Every other fragmentation constant the appendix cites IS in
    `[schc.fragment]`.
  - Minor adjacent nuance: C fragmentation constants are split across two headers — rule IDs
    + timers in `lichen/subsys/lichen/schc/include/lichen/schc.h` (the file the appendix
    points to), TILE_SIZE/WINDOW_SIZE/bitmap in the generic engine header
    `lichen/subsys/schc/include/schc/schc.h`.
- **Question for Opus:** Should `tile_size = 179` be added to `constants.toml [schc.fragment]`
  (making the spec citation true and giving the derived Rust/Python constant a shared source),
  or should spec lines 8/56 be amended to stop citing constants.toml for TILE_SIZE? Note the
  Rust/Python values are *derived* (envelope 185 minus header/RCS), so a hardcoded key could
  itself drift — the C static-assert pattern is the existing anti-drift mechanism. Bead:
  [spec-gap][R-SCHC-018].
