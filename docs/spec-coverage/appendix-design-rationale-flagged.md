<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# appendix-design-rationale — flagged set for Opus verification

Sweep: 2026-09-09. All rows below are divergent or not-implemented
(classification per docs/spec-coverage/appendix-design-rationale.md). No low
confidence rows and no 06-security/oscore/EDHOC content in this section; the
R-ADR-003 privacy row (which cross-references 06-security §15.5) classified
implemented+tested with high confidence and is not flagged.

## R-ADR-002 — §3.2 SCHC baseline byte counts and "native-address" wording

- Requirement: "The baseline compresses link-local IPv6+UDP to 18 bytes and
  native-address IPv6+UDP to 32-33 bytes without synchronized per-peer key
  context." (spec/appendix-design-rationale.md:107-110)
- Classification: divergent (spec text vs normative section).
- Evidence: spec/03-adaptation.md §5.3/§5.5 (:55-60, :84-87, :145) states 23
  bytes (link-local Rule 0) and 37 bytes (Yggdrasil Rule 1) for IPv6+UDP+CoAP;
  the word "native" appears in neither 03-adaptation.md nor appendix-schc.md;
  the SHA-512 "native" profile is the one rejected by the settled
  upstream-yggdrasil-addressing decision. appendix-misc.md:38 hedges
  "18-33 bytes". Bead: b7z9.205.
- Question for Opus: were 18/32-33 ever valid figures (e.g. pure IPv6+UDP
  before the CoAP term was added), or were they always wrong? Decide whether
  the fix is "23/37 + Yggdrasil terminology" or a pure-IPv6+UDP restatement,
  and whether appendix-misc.md:38's "18-33 bytes" should change in the same
  edit.

## R-ADR-004 — §7.4/7.5 PHY parameter summary (sync word clause)

- Requirement: PHY params SF10 / 125 kHz / CR 4-5 / sync word 0x34; LICHEN and
  Meshtastic cannot hear each other. (lines 342-382)
- Classification: divergent (sync word, Rust only).
- Evidence: C lr1110.c:502-504 programs 0x34; Py constants.py:11; Rust
  LORA_SYNC_WORD=0x34 (rust/lichen-core/src/constants.rs:4) has zero
  consumers — lichen-embassy never programs a sync word. Existing bead
  b7z9.103 (from R-02-006). SF/BW/CR conform (02-physical-link matrix
  R-02-002/003/004).
- Question for Opus: does the Rust sync-word gap invalidate this appendix's
  "zero processing cost for foreign packets" claim on Rust-driven hardware,
  or is lichen-embassy hardware out of the appendix's scope? Confirm whether
  b7z9.103's scope statement should be extended to cover this appendix row.

## R-ADR-007 — §7.6 slot duration minimum 2,346 ms

- Requirement: "Slot duration is at least the configured profile's maximum
  permitted PHY-payload airtime plus the single 50 ms guard. The SF10/125 kHz
  profile minimum is 2,346 ms." (line 391)
- Classification: divergent (C).
- Evidence: Py timing/sfn.py:12-13 and Rust lichen-core/constants.rs:95,97
  carry 2346/50; C link.h:88 LICHEN_TDMA_SLOT_MS=250 (guard correct at :87);
  test-only 2346 literal at lichen/tests/link_crypto/src/main.c:737. Existing
  bead b7z9.17. The computed ceil(airtime)+guard formula exists as code in no
  stack (02b matrix R-02b-012).
- Question for Opus: should the appendix (or 02a) require the formula as code
  (profile-parameterized computation) rather than a pinned constant, or is the
  constant sufficient? Determines whether fixing b7z9.17 is a constant edit or
  a small feature.

## R-ADR-008 — §7.6 TX suppressed outside slot

- Requirement: "TX suppressed outside slot (tdma_tx_allowed())." (line 392)
- Classification: divergent (gate inert in production).
- Evidence: tdma.c:303-338 correct and tested (link_crypto/main.c:641-693);
  sole production call lichen_link_tx.c:110 passes now_ms=0 (FIXME :99-109)
  and nothing sets tdma->synced in production, so the gate is a no-op. Rust
  tdma_clock::tx_allowed has no production caller. Existing bead b7z9.164.
- Question for Opus: none new — confirm b7z9.164 already subsumes the
  appendix site (it cites spec 02a-tdma.md:63; the appendix restates the same
  obligation).

## R-ADR-009 — §7.6 "Node uses lichen_link_set_slot() in subsys"

- Requirement: "Node uses lichen_link_set_slot() in subsys." (line 391)
- Classification: not-implemented (production wiring).
- Evidence: defined tdma.c:263-284, declared link.h:563; test-only callers
  (link_crypto/main.c:653+; tdma_guard_budget/main.c:168; desync_fsm/main.c:234);
  zero production call sites. Existing bead b7z9.164 (same root cause as
  R-ADR-008).
- Question for Opus: should the beacon-reception path auto-install the slot
  (tdma.c:85 comment implies yes) as part of b7z9.164, or is explicit
  application-layer installation the intended contract?

## R-ADR-010 — §7.6 stale "density >8" threshold

- Requirement: "density-aware overrides and CH0 fallback apply only on
  explicit thresholds (density >8 triggers specific SF and control channel
  rules)" (line 394) — conflicts with the adjudicated density-high decision
  (">10").
- Classification: divergent (spec text vs adjudicated decision).
- Evidence: decision `density-high` (spec/decisions.jsonl, 2026-08-31) sets
  >10; 02a:488,628,648 and all implementations use 10 (rf_health.rs:16,
  link_ctx.c:716). Bead b7z9.204 (sweep could not edit the file — section not
  in the decision's `specs` array).
- Question for Opus: none on the value — the decision is final. Confirm only
  that a one-character spec fix (">8" → ">10" at line 394) needs no other
  coordination.

## R-ADR-011 — §7.6 ccp_load_balancing.json MUST-match

- Requirement: "Implementations MUST match test/vectors/ccp16.json and
  ccp_load_balancing.json exactly." (line 394)
- Classification: divergent (consumer asymmetry).
- Evidence: Py test_tdma.py:212-227 pins slot assignment + guard values; Rust
  rf_health.rs:1192-1229 reads and discards expected_ppm/slot_adjust_ticks
  (:1213-1219); C has no consumer. Existing bead b7z9.163.
- Question for Opus: should the Rust test be upgraded from
  presence/bounds-only to value-assertion as part of b7z9.163, or is the
  corpus deliberately presence-only for Rust?

## R-ADR-014 — §7.6 root-assigned data channels via DAO-ACK channel_map

- Requirement: "Data channels via hash or root-assigned (RPL DAO-ACK carries
  channel_map)." (line 416)
- Classification: divergent (root-assigned clause not-implemented).
- Evidence: hash-based data channels implemented+tested (CCP-12); no DAO-ACK
  in any stack carries a channel map (Rust lichen-rpl/src/message.rs:71-85,
  address_assignment.rs:385-471; C rpl_messages.h:59-78; Py none). GCP
  channel_map (gateway/src/resources.rs:1173) is CoAP, not RPL. Related prior
  finding R-02-013 (gateway-assigned channel DIO option, not-implemented, was
  left bead-less as a spec-simplification candidate). Bead: b7z9.207.
- Question for Opus: is the DAO-ACK channel_map a real planned mechanism
  (implement it) or stale wording superseded by the GCP channel_map (amend the
  appendix)? This decides b7z9.207 vs a spec amendment.

## R-ADR-015 — §7.6 DIO option neighbor_count + channel_util (percent*2.55)

- Requirement: "Nodes report neighbor_count (u8), channel_util (percent*2.55)
  in DIO option." (line 417)
- Classification: divergent.
- Evidence: C 0x16 RF-metrics TLV exists (rpl_messages.h:78,101-115,
  messages.c:935-960, roundtrip-tested) but has a different field set (no
  neighbor_count; util plain u8; the 2.55 factor exists nowhere) and is never
  emitted into a DIO; Rust 0x16 is DODAG-Version-Auth (b7z9.147 collision); Py
  nothing. Existing beads b7z9.187 + b7z9.74.
- Question for Opus: is the appendix's exact encoding (neighbor_count u8 +
  util = percent*2.55) the intended wire format to fold into the b7z9.187
  wire-form decision, or should the appendix be amended to match whatever 02a
  2a.10.3 settles on? The ×2.55 encoding appears in no other spec section.

## R-ADR-016 — §7.6 root-side central collision optimizer

- Requirement: "Root (Rust gateway/rpl) runs central optimizer: minimize
  collisions using density map." (line 418)
- Classification: not-implemented.
- Evidence: no optimizer code anywhere (rg "optimiz" → only airtime.rs:86-111
  low-data-rate optimization); "density_map" zero hits repo-wide; lichen-gateway
  has no density logic. Bead: b7z9.208.
- Question for Opus: is this a committed feature (root-side planner consuming
  DIO-reported density) or aspirational prose that should be marked as future
  work? Note §6.2 of the same appendix argues *against* automatic congestion
  avoidance — the optimizer sentence and the "Backpressure: Data Collection
  Only" simplification may be in tension.

## R-ADR-017 — §7.6 "<5% loss at 50 nodes/km²" sim validation

- Requirement: "Python sim/schc: models multi-channel propagation, TDMA
  collisions, validates <5% loss at 50 nodes/km2." (line 419)
- Classification: divergent (validation absent; modeling present).
- Evidence: sim/protocol.py:625-654 hop_channel, sim/medium.py:162 collisions
  + capture, sim/tdma.py:48-49,94-117; no km²-normalized loss test anywhere;
  closest python/tests/sim/test_scale.py:349-423 (collision_rate<0.5, no area
  units). Folded into bead b7z9.210.
- Question for Opus: what is the intended density normalization (nodes per
  km² at what range/spreading profile) and is <5% loss a stable gate for CI,
  or should the appendix state a softer target?

## R-ADR-018 — §7.6 Kconfig symbols

- Requirement: "CONFIG_LICHEN_CCP16=y, CONFIG_LICHEN_TDMA_SLOTS=8,
  CONFIG_LICHEN_ADAPTIVE_SF=y." (lines 423-425)
- Classification: divergent (2 of 3 symbols missing).
- Evidence: only CONFIG_LICHEN_ADAPTIVE_SF exists (rpl/Kconfig:164-168,
  default y); CONFIG_LICHEN_CCP16 and CONFIG_LICHEN_TDMA_SLOTS have zero
  Kconfig occurrences; nearest real symbols are
  CONFIG_LICHEN_LINK_CCP16_LOAD_BALANCING (no default y, b7z9.177) and
  LICHEN_TDMA* booleans. Bead: b7z9.209.
- Question for Opus: add the two symbols as named, or amend the appendix to
  the real symbol names? If added, should CCP16 default y (the appendix says
  =y) given b7z9.177 tracks the existing gate's non-default status?

## R-ADR-019 — §7.6 epoch/num_slots "extended RPL config option"

- Requirement: "Root includes epoch and num_slots (default 8) in extended RPL
  config option (see draft-lichen-rpl-lora)." (lines 387-389)
- Classification: divergent (cross-ref unbacked; mechanism lives elsewhere).
- Evidence: draft-lichen-rpl-lora-00.md §4.2 (:141-148) and Appendix A
  (:520-540) contain neither field; all three stacks' DODAG Config option
  (type 4) lacks both; epoch+num_slots ride the TDMA beacon header
  (tdma_beacon.rs:5-15, tdma_beacon.py:10-11, beacon.c:41). Default 8 real
  (tdma.c:53,89; link/Kconfig:167-168). Bead: b7z9.206.
- Question for Opus: amend the appendix cross-ref to the TDMA beacon, or add
  epoch/num_slots to the draft's config option (which would duplicate the
  beacon fields on the wire)?

## R-ADR-020 — §7.6 Interop & Tests block cites nonexistent paths

- Requirement: "pytest in python/tests/sim/test_ccp16.py; cargo test in
  rust/rpl, rust/gateway; west build -b native_sim && west build -t run for
  Zephyr; Renode scenarios for multi-node density test." (lines 427-432)
- Classification: divergent (path/test drift).
- Evidence: python/tests/sim/test_ccp16.py absent (real consumers test_ccp.py,
  test_channel_plan.py, test_vectors.py); rust/rpl and rust/gateway don't
  exist (lichen-rpl/lichen-gateway, neither consumes ccp16.json — b7z9.179);
  all .resc files single-machine, no density scenario. Zephyr
  west/native_sim leg is real (lichen/tests/rf_health_vectors). Bead:
  b7z9.210.
- Question for Opus: should the appendix be amended to the real paths, or are
  the cited paths the intended target layout (create test_ccp16.py and rename
  crates)? If the latter, is a multi-machine Renode density scenario actually
  planned, given Renode multi-node determinism is a known open problem (bead
  lora_ipv6_mesh-f7sx)?
