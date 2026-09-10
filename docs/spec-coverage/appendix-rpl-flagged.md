<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# spec/appendix-rpl.md — flagged set for verification (sweep 2026-09-09)

Scope: every requirement in `docs/spec-coverage/appendix-rpl.md` classified
**divergent**, **not-implemented-with-judgment-calls**, or **low-confidence** —
20 rows, grouped into 8 verification clusters. Full file:line evidence is in the
matrix rows. This section touches no oscore/EDHOC internals.

| Row | Classification | Cluster | Bead filed? |
|-----|----------------|---------|-------------|
| R-RPL-001 | divergent | F1 | no (spec-text defect) |
| R-RPL-002 | divergent | F2 | yes (max_rank_increase split) |
| R-RPL-004 | divergent | F2b | no (cross-refs existing beads) |
| R-RPL-007 | divergent | F2b | yes (C root MOP=0) |
| R-RPL-012 | divergent | F3 | yes (MRHOF formula cluster) |
| R-RPL-013 | not-implemented | F3 | (same bead) |
| R-RPL-014 | not-implemented | F3 | (same bead) |
| R-RPL-015 | divergent | F4 | no (deliberate, documented) |
| R-RPL-018 | divergent | F5b | yes (trickle reset triggers) |
| R-RPL-019 | implemented+untested (low) | F8 | no |
| R-RPL-020 | divergent (decision conflict) | F5 | no (decision wins; spec-text defect) |
| R-RPL-023 | divergent | F6b | yes (450 s refresh bug) |
| R-RPL-025 | divergent | F6b | (same bead) |
| R-RPL-026 | divergent | F6b | yes (root DAO-ACK) |
| R-RPL-027 | implemented+tested (low) | F7 | no |
| R-RPL-031 | divergent | F7b | no (existing bead 99sg) |
| R-RPL-032 | divergent | F8b | yes (Python DODAG Config) |
| R-RPL-037 | divergent | F9 | yes (CCP-16 signaling) |
| R-RPL-038 | divergent | F9 | (same bead) |
| R-RPL-039 | divergent | F4 | no (spec-amend candidate) |
| R-RPL-040 | divergent | F9 | (same bead) |

---

## F1 — Appendix claims the draft contains a "DAO Origin Signature Option" (R-RPL-001)

- Requirement: appendix lines 8-10 name `draft-lichen-rpl-lora-00.md` as the canonical
  normative spec covering, among others, "DAO Origin Signature Option with Schnorr48".
- Evidence: `rg -in "origin|schnorr" spec/drafts/draft-lichen-rpl-lora-00.md` hits only
  §7.1 (source-address model) and §8.2 (link-layer signatures). The option itself is
  implemented and swept (R-RPL-003; prior rows R-05-053/056; vectors
  test/vectors/dao_origin_signature.json + Rust-local dao_origin_signature_upstream.json).
- **Question for Opus:** Should the draft gain a normative DAO Origin Signature Option
  section (wire format, transcript, replay floor, verification order — presumably
  mirrored from spec/05-routing.md §8.6-8.7), or should the appendix pointer be reworded
  to cite spec/05-routing.md for that option? Edit bar note: this is the RPL draft, not
  oscore/EDHOC internals.

## F2 — max_rank_increase value split and constants.toml not machine-read (R-RPL-002)

- Classification: divergent.
- Evidence: constants.toml:52 `max_rank_increase = 2048`; Rust loop guard
  `MAX_RANK_INCREASE: u16 = 1024` (rust/lichen-rpl/src/dodag.rs:28); C Kconfig default
  1024 (Kconfig:111-118) but C DIO-config wire default 2048 (messages.c:604); Python
  constants.py:51 says 1024 while python/src/lichen/rpl/dodag.py:50 uses 2048. The wire
  DODAG-Configuration default is 2048 in all three builders (Rust message.rs:680-681,
  Py messages.py:104, C messages.c:604). Documented as a live interop risk in
  test/vectors/ccp_beacon_sig_gate.json:140-150. Also: no stack parses constants.toml
  (header claims Python `lichen.constants` / Rust `include_str!` / C generated
  `constants.h` — none exist; all hand-synced). Appendix line 13's line references
  (44-55 / 57-61) are also stale (actual blocks 46-56 / 58-62), though values match.
- **Question for Opus:** Which value is canonical — 1024 or 2048? Unify admission guards
  with the advertised default, and amend constants.toml or actually machine-read it?
  Python currently admits parents Rust/C would reject (admission-control divergence).

## F2b — Appendix "matching the Rust behavior for interop" claim vs C reality (R-RPL-004)

- Classification: divergent (the C subsystem exists — dodag.c:242 `lichen_rpl_dodag_init`,
  rpl_dodag.h:145 — but parity is partial).
- Evidence: C gateway root emits MOP=0 DIOs its own RX rejects (see F2b/R-RPL-007, bead
  filed); C lacks the RX-side DAO replay floor (tracked b7z9.135/.11); the C RPL library
  is exercised only by `lichen/tests/rpl_*` suites (root-sig receiver unwired, R-06-305;
  puck app does not use the subsystem).
- **Question for Opus:** Should the appendix's interop-parity claim be qualified (e.g.
  "library-level parity; live node integration pending"), or is full parity a near-term
  commitment that justifies leaving the text as-is?

## F3 — MRHOF link-metric machinery diverges from §5.1-5.2 (R-RPL-012, R-RPL-013, R-RPL-014)

- Classification: divergent (formula) / not-implemented (ETX delivery-ratio, RTT EWMA).
- Evidence: Step = MHRI×ETX in Rust (dodag.rs:242) and Python (dodag.py:152-163); C adds
  `load_factor*8` (dodag.c:126-129), a term absent from the spec. ETX_factor=0.5,
  Latency_factor=0.1, RTT EWMA 0.875/0.125, and ETX=1/(fwd×rev) exist in NO stack; ETX is
  a caller-supplied parameter everywhere. standards/ietf-drafts.ai.md:61 records the
  factor formula as operative — the standards note sides with the spec, the code does not.
  Bead filed for the cluster.
- **Question for Opus:** Implement the spec formula (needs RTT estimation and
  delivery-ratio ETX from the link layer) or amend §5.1-5.2 (and the standards note) to
  the implemented `Step = MHRI×ETX` (+ C load term)? The C-only `load_factor*8` term is
  in neither document.

## F4 — PARENT_SWITCH_THRESHOLD 384 vs 192; DEFAULT_PARENT_COUNT 3 vs 16/4/16 (R-RPL-015, R-RPL-039)

- Classification: divergent (logic implemented+tested; constants differ).
- Evidence: all three stacks use 192 (Rust dodag.rs:29; C rpl_dodag.h:49; Py dodag.py:51,
  citing RFC 6719 MRHOF default); standards/ietf-drafts.ai.md:61 records
  SWITCH_THRESH=192. Parent table: Rust 16, C default 4 (Kconfig 2-8), Py 16; §10.3
  says 3. Hysteresis behavior tested (Rs dodag.rs:942; C rpl_dodag/main.c:700;
  Py dodag.py:791).
- **Question for Opus:** Amend §5.1/§5.3/§10.3 to 192 and realistic parent counts, or are
  384/3 real requirements the stacks missed? Also confirm the path-cost hysteresis compare
  (vs the literal `Rank(new)+Step+T < Rank(cur)` expression) is an acceptable reading.

## F5 — Draft §6.4 "Targeted DIS: unicast response with DIO" vs settled decision `unicast-dio-admission` (R-RPL-020)

- Classification: divergent (decision wins; draft text is the regression).
- Evidence: decision `unicast-dio-admission` (2026-08-31): send_dio() always targets
  ff02::1a; RFC 6550 8.3 unicast-response SHOULD superseded by profile contract R-09-005;
  verify grep confirmed in `rust/lichen-node/src/rpl_stack/transmit.rs`. Multicast-DIS→
  Trickle-reset implemented in all three stacks; "respond probabilistically" implemented
  nowhere.
- **Question for Opus:** Amend draft §6.4 to the adjudicated multicast-only contract, and
  either specify or drop the probabilistic-response clause. Not edited in this sweep: the
  decision's `verify` target is outside this section and the sweep forbids editing other
  files.

## F5b — Trickle reset triggers implemented in C only (R-RPL-018)

- Classification: divergent.
- Evidence: C dodag.c:540-551 (version/rank/parent/config-change → reset) + rpl_dis.c:118;
  Rust resets only on multicast DIS (receive.rs:644-653; trickle.rs:126-127 leaves
  caller-driven resets unwired); Python rpl/dis.py:108 only — python/src/lichen/rpl/dodag.py
  contains no Trickle integration at all (version adoption never resets DIO timing).
  Bead filed.
- **Question for Opus:** Confirm Rust/Python should adopt the C trigger set (or the draft
  should narrow the trigger list). Also note the C Kconfig-vs-code constant split noted in
  the matrix (Kconfig vs messages.c defaults) is part of F2's constants question.

## F6 — Draft §6.1 Trickle table says "Imax 17.5 minutes" (R-RPL-017)

- Classification: implemented+tested; the spec text is the regression.
- Evidence: 2^8 × 4 s = 1024 s = 17.07 min, matching §6.2 of the same draft,
  constants.toml, all three stacks, the `trickle_constants` vector, and decision
  `trickle-imax-1024s` ("Amend the spec table to Imax = 17.07 minutes (1024 s)"). The
  decision's `specs` array lists only 09-packets-timing.md, so the draft table was missed.
- **Question for Opus:** Confirm amending draft §6.1 "17.5 minutes" → "17.07 minutes
  (1024 s)" under the settled decision; no implementation change warranted.

## F6b — Root DAO-ACK and DAO refresh timing divergences (R-RPL-023, R-RPL-025, R-RPL-026)

- R-RPL-023/025 (divergent): Rust `dao_tx_sched.rs:19` computes
  `DAO_REFRESH_INTERVAL_MS = DAO_REFRESH_INTERVAL_SECONDS * 1000 / 2` = 450 000 ms — a
  double-halving (the oracle constant is already the 900 s half-life; lichen-rpl
  dao_timing.rs:19-33); test `initial_due_then_refresh_on_success` (dao_tx_sched.rs:182-189)
  pins the wrong value; scheduler items are `expect(dead_code)` in non-test builds pending
  b7z9.16.1(b), verified this sweep. Bead filed (P1).
- R-RPL-026 (divergent): "Root MUST send DAO-ACK for every DAO received" — Rust emits no
  root DAO-ACK (node.rs:394-453; gateway tdma_fsm.rs:35 awaits an event nothing produces);
  C/Python ACK only when the DAO's K flag is set (rpl_dao_process.c:989-995;
  dao_manager.py:714) and C's own DAOs set K=0 (rpl_dao_build.c:250), so C↔C is never
  ACKed. Bead filed.
- **Question for Opus:** (a) Confirm the intended §7.3 contract: unconditional root
  DAO-ACK as the draft says, or the K-flag-gated contract the C code comments cite
  ("7.3,7.5")? (b) Confirm 900 s is the intended refresh (draft §7.1/§7.2 + all vectors
  agree), making the Rust `/2` a plain bug.

## F7 — C root-side SRH insertion status (R-RPL-027, low confidence)

- Classification: implemented+tested (Rust/Python) with a C caveat; confidence low.
- Evidence: C codec + intermediate advance implemented+tested (rpl_srh.c;
  lichen/subsys/lichen/routing/router.c:274-277,462-505; lichen/tests/rpl_srh, 10 tests),
  but no live C root-side insertion found: `lichen/apps/gateway/src/forwarding.c:193`
  "ponytail: multi-hop SRH route extraction is not wired"; rpl_root.c has no SRH insert.
  Prior sweep row R-05-038 lists C router.c/rpl_root.c as implemented.
- **Question for Opus:** Does any C path insert an SRH at the root today (is the ponytail
  comment stale)? If not, R-05-038's C evidence needs a correction and the missing
  insertion needs a bead.

## F7b — Root legitimacy verification partial (R-RPL-031, SHOULD)

- Classification: divergent.
- Evidence: TOFU pinning implemented+tested in all three; root-sig DODAGID↔key binding
  wired in Rust RX only (receive.rs:695-804) — C library+tests only (R-06-305), Python
  oracle-only; root-change operator alerting Python-only (dodag.py:736-745 → node.py:1231),
  tracked as project-LICHEN-worker6-99sg. SHOULD-level, so no new bead.
- **Question for Opus:** Confirm the existing bead (99sg) covers the Rust/C alerting gap
  and whether unwired C/Python root-sig verification should block any release claim about
  root legitimacy (cross-ref R-06-305).

## F8 — Two low-stakes sign-offs (R-RPL-011, R-RPL-019)

- R-RPL-011 (§4.3 MAY multi-DODAG join): implemented+tested for BR-per-DODAG federation
  (GCP-5 multi-root, shared instance 0); literal "nodes MAY join multiple DODAGs" absent
  (one DodagState per node in all stacks). MAY-level absence conforms; confirm the
  federation-not-multi-join reading is intended.
- R-RPL-019 (§6.3 "Do NOT reset on new node joining / metric updates"): implemented+
  untested (evidence is absence of reset call sites + doc comments, e.g.
  python/src/lichen/rpl/trickle.py:139-160). Question: is a pinning test (metric update
  does not shrink the DIO interval) worth requiring?

## F9 — CCP-16 DIO metric signaling incomplete (R-RPL-037, R-RPL-038, R-RPL-040, with R-RPL-010)

- Classification: divergent.
- Evidence: pseudocode + ccp16-family vectors implemented+tested in all three
  (Py ccp.py:220-299; Rust lichen-core rf_health.rs; C link/rf_health.c:154; consumers in
  lichen-core/tests/ccp16_*.rs, lichen-rpl/tests/ccp16_desync_vectors.rs:14,
  tests/rf_health_vectors/main.c:171, Py test_ccp.py:170-427). DIO side: no DAG Metric
  Container anywhere (option-type constant only, Py messages.py:47); ASSIGNED_SF wired
  C+Rust only (C rpl_root.c:215-227/dodag.c:673-680; Rust router.rs:1047-1078); C
  RF-metrics TLV 0x16 helpers exist but are never emitted into a DIO (sole callers
  lichen/tests/rpl_messages/main.c:807-840); Python rpl/ has zero DIO metric signaling;
  0x16 wire-type collision (Rust DODAG Version Authorization vs C RF-metrics) tracked in
  b7z9.147; parent selection consumes none of it (R-RPL-040). Bead filed.
- **Question for Opus:** Is the intended wire form dedicated LICHEN options (current
  direction) or a real RFC 6551 DAG Metric Container? Whichever wins, Python needs the
  signaling and the 0x16 collision must resolve (b7z9.147) before the §9.2 MUSTs can be
  claimed.
