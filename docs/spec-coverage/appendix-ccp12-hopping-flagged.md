<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# spec/appendix-ccp12-hopping.md — flagged set (sweep 2026-09-09)

Every row with low confidence, ambiguous or divergent classification, or an
unresolved spec/implementation tension. oscore/EDHOC: none in this section.

## F1. R-CCP12-001 / R-CCP12-018 — normative priority chain (divergent, high-confidence divergence, low-confidence resolution)

- Requirement: §1 priority table (1=announce CCP-9, 2=hash CCP-16,
  3=synchronized hop CCP-12, 4=CH0) and §6 pseudocode (announce → hash with
  density inside → CH0; no CCP-12 step).
- Classification: divergent.
- Evidence: python link chain = announce → GNSS-synced CCP-12 → hash(eui64 +
  epoch + sfn, no density) → CH0 (python/src/lichen/link/channel.py:112-158,
  tested in tests/link/test_channel.py:217-278); rust = GNSS → hash → CH0
  (rust/lichen-core/src/lib.rs:165-201); density fallback exists only in
  python channel_plan.py (not the chain modules) and C (Kconfig-gated).
  The spec contradicts itself (§1 vs §6) and both.
- Question for Opus: which chain is normative? If the implemented
  announce → CCP-12(GNSS) → CCP-16 → CH0 order is intended (reasonable:
  prefer locked sync over epoch rendezvous), amend §1/§6 and state when
  density>10 overrides GNSS-synced selection (currently: nowhere — a
  GNSS-synced node in a >10-density network will NOT fall back to CH0 under
  either code chain). If the §1 order is intended, python/rust chain code
  must change — a rendezvous-interop breaking fix.

## F2. R-CCP12-003 / R-CCP12-009 — density>10 → CH0 absent from Rust; Kconfig-gated in C (divergent)

- Requirement: §3.1 step 1 / §3.3 "When Density > 10, all nodes fall back to
  CH0 for both control and data."
- Classification: divergent (python implemented+tested; C gated+untested;
  rust absent).
- Evidence: python/src/lichen/channel_plan.py:295-296 +
  tests/test_ccp.py:107; lichen/subsys/lichen/link/link_ctx.c:716 behind
  `CONFIG_LICHEN_LINK_CCP16_LOAD_BALANCING` (Kconfig:148, no `default y`;
  `#else` variant ignores density :737-766); rust
  select_channel_with_gnss has no density parameter
  (rust/lichen-core/src/lib.rs:165-201).
- Question for Opus: (1) Should `LICHEN_LINK_CCP16_LOAD_BALANCING` default y
  (or be selected by `LICHEN_MULTI_CHANNEL_ENABLED`) so C nodes conform by
  default? (2) Should rust gain a density parameter (API change to
  select_channel_with_gnss) or is the GNSS/hash chain deliberately
  density-free pending F1?

## F3. R-CCP12-008 / R-CCP12-023 — ccp16.json provenance: NChannels=3, unstated (divergent)

- Requirement: "Implementations MUST match test/vectors/ccp16.json exactly"
  (§3.2, §9).
- Classification: divergent (as an inter-stack pin, the file under-specifies).
- Evidence: all ccp16.json channel outputs equal `1 + hash_32 MOD 2`; the
  NChannels=3 provenance is documented only in
  python/tests/test_channel_plan.py:275-277 ("generated with NChannels=3 ...
  legacy formula ... verify hash_32 against the vectors and select_channel
  against the spec oracle"). Spec §3.2 example uses NChannels=8 and gets the
  arithmetic wrong (926423932 MOD 7 = 0 → channel 1, not 2; hex should be
  0x37381B7C not 0x373854FC); spec §9 quotes the vector as channel 2/2 but
  the file says 1/1.
- Question for Opus: should ccp16.json gain an explicit
  `n_channels`/`num_channels` field per vector (plus a regenerated
  description), or should the spec examples be corrected to state the
  3-channel vector plan? (Related: §9's "Example vector (from file)" is a
  near-quote with a wrong expected_channel — confirm the file wins, per the
  "vectors are authoritative" claim in §8.1.)

## F4. R-CCP12-005 — Rust epoch width u8 vs spec u32 (divergent edge, flagged)

- Requirement: §3.1 input table — Epoch is u32 (source: RPL DIO / TDMA
  beacon).
- Classification: implemented+tested overall, but rust
  `select_channel_with_gnss(..., epoch: u8, ...)` truncates the network
  epoch to 8 bits (rust/lichen-core/src/lib.rs:169,188) while the TDMA
  beacon wire epoch is u32 BE (rust/lichen-core/src/tdma_beacon.rs:6,42)
  and python truncates to u32 (channel_plan.py:299) and C uses u32
  (link_ctx.c:720-724). For epochs > 255 the rust function selects a
  different channel than python/C with identical inputs.
- Question for Opus: widen rust's parameter to u32 (matching the beacon
  wire field), or is the u8 epoch deliberate because the *link* epoch is u8
  (spec 15.3 epoch-never-wrap, exhaustion at 255)? Note the function
  currently has no production callers (only lib.rs unit tests), which makes
  this cheap to fix now and expensive after wiring.

## F5. R-CCP12-012 — 2000ms superframe default not pinned by any test (implemented+untested)

- Requirement: §4.2 "Default: 2000ms (2 seconds) - fits SF10 packets with
  margin for RX window."
- Classification: implemented+untested.
- Evidence: constants exist in all three stacks (python link/channel.py:20;
  rust lib.rs:11,43; C Kconfig `LICHEN_SYNC_HOP_SUPERFRAME_MS default 2000`,
  Kconfig:258-261) but no test asserts the default value (sfn tests use
  custom durations).
- Question for Opus: pin the default (one-line constant test per stack) or
  accept Kconfig/source constants as the record?

## F6. R-CCP12-013 — "hop between packets, not mid-packet" sequence (ambiguous)

- Requirement: §4.2 4-step sequence — compute channel from current SFN → TX
  → after TX compute new SFN → hop if changed → RX.
- Classification: ambiguous (vacuously satisfied; nothing hops mid-packet,
  nothing implements the discrete sequence).
- Evidence: python TDMAScheduler.get_hop_channel per-SFN query
  (sim/tdma.py:183-186); C `LICHEN_MIN_DWELL_MS default 100` anti-flap dwell
  (Kconfig:274-284); no explicit post-TX recompute-and-hop step found.
- Question for Opus: is per-SFN channel computation at TX/RX time conformant
  with the intent, or should a hop-state machine (explicit "hop if changed
  after TX") exist and be tested? If the latter, which stack owns it first?

## F7. R-CCP12-014 — §4.3a sync-accuracy/guard table (ambiguous, informational)

- Requirement: CCP-12 requires SFN alignment; guard 200ms @ 2000ms SF,
  ~100ms accuracy achievable via GNSS PPS/NTS/mesh-sync; "mesh-derived sync
  IS sufficient".
- Classification: ambiguous (no MUST keyword; no code constants).
- Evidence: no CCP-12 guard-window constant in any stack; TDMA_GUARD_MS=50
  is slot-level (02a), not hop-guard.
- Question for Opus: confirm this table is deployment guidance (no code
  required), or decide whether CCP-12 guard constants belong in code and
  vectors. Also: the spec has two "### 4.3" headings (numbering bug) —
  renumber §4.3b → §4.4 etc. (folded into spec-fix bead).

## F8. R-CCP12-015 — desync recovery step 1 "fall back to CH0 listening" (not-implemented, partial)

- Requirement: §4.4 — (1) fall back to CH0 listening; (2) wait 3 consecutive
  valid beacons on CH0; (3) re-sync SFN from beacon timestamp; (4) resume
  hopping.
- Classification: steps 2-4 implemented+tested in all three stacks (rust
  desync.rs:44,140-158 + ccp16-desync.json consumers; python
  timing/sfn.py:14,60-174 + sim/tdma.py:67-92; C desync_fsm test + static
  assert ==3). Step 1 has no explicit channel action anywhere; beacon
  listening is implicitly on CH0 because beacons are control traffic.
- Question for Opus: does implicit CH0 beacon listening satisfy step 1's
  intent (data-channel TX suppressed while DESYNCED/RECOVERING — check
  `is_tx_allowed`/TX gating during desync), or does CCP-12 require an
  explicit "abandon hop sequence, park on CH0" radio action in the desync
  FSM? If the latter, suggest placement (rust desync.rs, python
  timing/sfn.py, C tdma desync FSM).

## F9. R-CCP12-016 — CCP-9 announce-driven priority missing in Rust (divergent)

- Requirement: §5 — use peer's recent Announce `rx_channel` directly
  (priority 1).
- Classification: divergent (python implemented+tested; C has the CCP-5
  `announce_driven` mechanism enum + ccp9-rendezvous.json mapping; rust
  absent from channel selection).
- Evidence: python link/channel.py:113-119 + tests (test_channel.py:217-278);
  rust lib.rs:165-201 has no announce parameter; rust only sets its own
  advertised rx_channel (lichen-node/src/scheduler.rs:189-195). No rust
  consumer of ccp9-rendezvous vectors found.
- Question for Opus: is rust's omission intentional (rust nodes rendezvous
  via CCP-16 hash only, advertising rx_channel=0), or a gap? Note the
  interop asymmetry: a rust peer ignores a python peer's advertised
  rx_channel while python honors rust's.

## F10. R-CCP12-019 — §7.1/§8.2 US915 "8 channels" stale (divergent)

- Requirement: §7.1 table "50 hopping channels ... Current Status: 8
  channels"; §8.2 enhancement "expand US915 plan ... from 8 to 50+".
- Classification: divergent (spec text stale vs code).
- Evidence: US915 plan has 64 channels + `DWELL_TIME, dwell_time_ms=400`
  (python/src/lichen/channel_plan.py:139-150); AU915 64 (:152-159).
- Question for Opus: confirm the spec should be amended to "64 channels
  present; FCC 15.247 digital-modulation documentation path still open" and
  §8.2's enhancement 1 dropped. The dwell-time row ("400ms maximum dwell —
  Not enforced") may also need a pointer to the DWELL_TIME regulatory rule
  that now exists.

## F11. Rust test-harness mirror carries the pre-decision `density > 8` threshold (test integrity note)

- Location: rust/lichen-core/tests/ccp16_utilization_vectors.rs:52-53
  ("Step 3: density (spec 2a.8: > 8)" then `if density > 8 || utilization
  > 150`). Production rust rf_health.rs uses `DENSITY_HIGH: u8 = 10`
  (rf_health.rs:16) per the `density-high` decision; ccp16.json outputs
  implement >10. The utilization vectors contain only densities {5, 11}, so
  the stale mirror still passes. No test was modified during this sweep.
- Question for Opus: the mirror should be corrected to >10 (it mirrors spec
  2a.8, not this appendix — but the decision density-high explicitly covers
  "SF upshift"); additionally consider adding a density=9/10 utilization
  vector so the boundary is actually pinned. Requires owner decision because
  it touches test files (out of sweep scope).