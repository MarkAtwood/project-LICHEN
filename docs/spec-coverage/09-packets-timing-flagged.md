## spec/09-packets-timing.md — flagged set for Opus verification (sweep 2026-09-01)

Included per protocol: (a) low confidence, (b) ambiguous or divergent classification, (c) §06-security/oscore-EDHOC rows — none (this section has none). Meta-question first.

### M-0. Requirement-ID namespace collision (process)

`spec/decisions.jsonl` decision `unicast-dio-admission` (specs: 09-rpl-profile.md) cites "R-09-005" for 09-rpl-profile.md's admission-gate row. This sweep numbers R-09-001…153 for 09-packets-timing.md, and R-09-005 here is the §13.3 Rule-Version admissibility row — a different requirement with the same ID. **Question for Opus:** should section-scoped IDs (e.g. `R-09PT-NNN` / `R-09RP-NNN`) be mandated for the two spec/09 files, and should the decisions.jsonl reference be re-pointed? No beads were filed under the ambiguous IDs.

---

### R-09-007 — DIO Trickle Imax: spec says 17 min, all stacks use 1024 s

- **Requirement:** §14.1 table: Imin 4 s, **Imax 17 minutes**, k 10.
- **Classification:** divergent (high confidence in the divergence itself).
- **Evidence:** Spec text spec/09-packets-timing.md:118 (17 minutes = 1020 s). All three stacks: Rs `LICHEN_TRICKLE_IMAX_DOUBLINGS=8` → `LICHEN_TRICKLE_IMAX_MS=1_024_000` (rust/lichen-rpl/src/trickle.rs:7-13); C `LICHEN_RPL_TRICKLE_IMAX_MS 1024000U` (lichen/subsys/lichen/rpl/include/lichen/rpl_trickle.h:23); Py `TRICKLE_IMAX_EXACT_MS == 1_024_000` (python/src/lichen/timing/trickle.py:22,40) — oracle docstring even says "Imax=17min (≈1_024_000 ms)". Canonical vector packets-timing.json `trickle_constants` pins 1024 s. Imin and k=10 match exactly. Bead filed: b7z9.54.
- **Question for Opus:** Adjudicate: amend spec §14.1 to "Imax = 1024 s (Imin 4 s × 2⁸ doublings ≈ 17.07 min)" (cheap; matches all implementations + vectors), or change all three stacks + vectors to 1020 s (expensive; breaks trickle_constants vector). Recommend the former + decisions.jsonl entry.

### R-09-031 — Time AND SCHC-version consumers must derive from the same sealed result

- **Requirement:** "Time and SCHC-version consumers derive fixed evidence from that same result and MUST NOT consume or parse the caller-visible receive object independently." (§14.6, spec line ~218)
- **Classification:** ambiguous.
- **Evidence:** Time consumer confirmed (Py StratumTracker consumes the sealed DIO result + one-use receipt). No code object identifiable as the "SCHC-version consumer" of the sealed result — SCHC Rule-Version validation happens inside DIO admission (C dodag.c:674-686; Rs codec.rs:1961-1979) during the same parse, not via the sealed-result fan-out. rg for schc_version/rule_version "consumer"/"fan out" in timing/ and rust link/rpl: clean.
- **Question for Opus:** Is the MUST satisfied (rule-version is validated within the same authenticated parse, so no independent consumption occurs), or does §14.6 require a distinct SCHC-version consumer object consuming the sealed result (in which case this is a gap)? Suggest clarifying the spec sentence either way.

### R-09-075 — IANA reallocation atomicity: process MUST with no code object

- **Requirement:** "An IANA allocation that differs from this table MUST be applied atomically to every specification, implementation, parser, and test vector before deployment." (§14.6 registry, spec line ~360)
- **Classification:** ambiguous (process/governance requirement; trigger condition not met; no automated consistency tooling found).
- **Question for Opus:** Should this be re-classified N/A-process (no runtime code), or should a registry-consistency check (script asserting the five option-type values across spec/impl/parser/vectors) be required so the atomicity is mechanically enforceable when the trigger occurs?

### R-09-093 — Sealed-result fan-out to both consumers without second receipt/parse (MAY)

- **Requirement:** "The one sealed DIO result MAY then fan out to the time and SCHC version consumers without a second receipt or a second packet parse." (§14.6)
- **Classification:** implemented+untested; low confidence (entangled with R-09-031).
- **Evidence:** Fan-out exists structurally for the time consumer; no test named for fan-out-without-second-parse; SCHC-version consumer not identified.
- **Question for Opus:** Confirm whether the MAY is satisfied by the current single-parse admission design, or needs an explicit consumer split with a test.

### R-09-106 — Projected value must be used for the initial epoch-lead bound

- **Requirement:** "The projected value, rather than the stale wire value, MUST be used for the initial epoch-lead bound." (§14.6)
- **Classification:** implemented+tested; low confidence (coverage is indirect).
- **Evidence:** Py stratum.py projects the accepted sample before policy evaluation; C time_sync.c rejects projected-below-floor (:188, :714); C test_epoch_floor_and_desync_invalidate_wall_clock (lichen/tests/time_source_class/src/main.c:242-249). No test named specifically for "epoch-lead bound evaluated against projected (not wire) value".
- **Question for Opus:** Does a direct test exist (or should one be added) pinning that the epoch-lead bound consumes the projected time rather than the raw wire timestamp — e.g. a stale wire timestamp below floor with a projected value above floor?

### R-09-109 — Projection beyond u32 DIO range must invalidate DIO advertisement with observable diagnostic (MUST)

- **Classification:** not-implemented (high confidence); bead b7z9.56.
- **Evidence:** rg for advertise/dio_range/4294967295/u32_max in python/src/lichen/timing/ clean; no tracker-side advertisement invalidation; DioTimeOption.encode would raise struct.error (crash) rather than produce an observable diagnostic.
- **Question for Opus:** Confirm the intended site: tracker invalidating DIO advertisement (provider-level state) vs codec-level encode error. Suggested placement in bead assumes tracker-level invalidation per spec wording.

### R-09-132 — Time-sensitive operation suppression without wall clock

- **Requirement:** Nodes without valid wall clock "MUST NOT originate time-sensitive operations (scheduled check-in, message TTL that requires wall-clock comparison)." (§14.6 constrained node)
- **Classification:** divergent (partial).
- **Evidence:** C gates DTN ops (lichen/subsys/lichen/coap/coap_dtn.c:73) and slot coordination (coap_slot_coord.c:1499) on `lichen_wall_clock_valid()`. Rust: no production gating found. Python: link/slot_coordination.py has no wall-clock gate; no check-in/TTL-named gating or pinning test anywhere. Bead b7z9.57.
- **Question for Opus:** Does the check-in/roll-call feature (spec 18, test/vectors/checkin_rollcall.json) require origination gating in the Rust node and Python node loop, or is the C-only gating an acceptable profile subset? Also confirm TTL comparison sites (DTN expiry) in Rust/Python are wall-clock-gated or floor-safe.

### R-09-141 — Desync recovery FSM in TDMA subsystem + documented timeouts

- **Requirement:** "Implementations MUST implement this FSM in the TDMA subsystem … and document timeout values (RECOMMENDED: 3 superframes for RECOVERING)." (§14.7)
- **Classification:** divergent.
- **Evidence:** C and Python implement the full FSM (C tdma.c:102-162 + link.h LICHEN_DESYNC_RECOVERY_BEACONS 3u; Py timing/sfn.py:77-133 with on_missed_superframe). Rust DesyncFSM (rust/lichen-core/src/desync.rs:42-152) lacks on_missed_superframe/RECOVERING-timeout entirely. Separately, C regressed: `LICHEN_TDMA_BEACON_TIMEOUT_SUPERFRAMES` removed from link.h by commit 656e367b29 but still used at tdma.c:156 — `lichen/tests/desync_fsm` cannot compile (verified by rg + agent gcc -fsyntax-only). Beads: b7z9.52 (C build break, P1), b7z9.53 (Rust FSM gaps).
- **Question for Opus:** Confirm the Rust RECOVERING timeout omission is a real gap (vs. intentionally deferred to the beacon-scheduler layer) and confirm the C build break is an unintended regression of 656e367b29 (the commit also added SFN-reset-on-version-change, which kept tdma.c compiling only because the macro's use site apparently predates the define removal — check whether any Kconfig-generated alias was intended).

### R-09-142/143/144/145 — Density-aware boot startup (boot storm)

- **Requirement:** MUST listen-only random [30,60] s; MUST count unique nodes heard (dedup); MUST delay random(0, min(300, n×5)) before first announce/DIO/DIS. (§14.7 tail)
- **Classification:** divergent (all four rows).
- **Evidence:** Py library spec-faithful (python/src/lichen/timing/startup_delay.py; tests test_startup_delay.py:43,133,200,228; vectors packets-timing.json density_startup_delay) but the simulator uses a different algorithm: log1p(heard)×scale (python/src/lichen/sim/simulation/base.py:282-300; TestDensityAwareStartup asserts "log not linear"). Rust: constants only (rust/lichen-core/src/desync.rs:11-38), no boot-path wiring. C: no implementation (rg clean under lichen/). Bead b7z9.55.
- **Question for Opus:** (1) Should the simulator's log1p heuristic be conformed to the spec formula or is it intentionally a sim-level approximation? (2) Confirm density startup belongs in C firmware boot (puck app) and Rust node boot as shipped behavior, not just library/sim.

### R-09-147 — Slot duration ≥ ceil(max airtime) + 50 ms (2346 ms at 255B SF10)

- **Classification:** divergent (C default slot 250 ms vs 2346 ms minimum). Already beaded `project-LICHEN-worker6-b7z9.17`; not re-filed.
- **Question for Opus:** None new — verify b7z9.17's plan covers whether LICHEN_TDMA_SLOT_MS=250 is a contention-profile default needing a separate data-slot constant, or must itself become 2346.

### R-09-149/152 — Rust production sfn_delta and combined pre-TX gate

- **Classification:** divergent (Rust side). Included in bead b7z9.53.
- **Evidence:** No production `sfn_delta` in Rust (only test-local `wrapping_sub` oracle, rust/lichen-node/tests/sfn_wrap_vectors.rs:56-60); tdma_scheduler.rs is slot-math only with no identity+replay+DODAG+time/SFN gate (C has the full gate chain in lichen_link_tx.c:63-106).
- **Question for Opus:** Does Rust assigned-slot TX currently rely on an upstream caller to enforce the §14.8 preconditions (in which case document the contract), or is the missing gate a real hole enabling out-of-slot TX?

### R-09-153 — FSM timers (BEACON_TIMEOUT 3×; rejoin 10×; reset-all-timers)

- **Classification:** divergent. Rejoin-10× absence in C/Rust already beaded `b7z9.19`; C BEACON_TIMEOUT build break beaded `b7z9.52`.
- **Question for Opus:** None new.

### R-09-151 — Spec's vector-file citations for SFN edge cases

- **Requirement:** "All SFN edge cases … MUST be covered by test vectors (see `test/vectors/ccp16.json`, `ccp_tdma.json`)." (§14.8)
- **Classification:** implemented+tested, high confidence the edge cases are covered — but the spec's file citations appear wrong.
- **Evidence:** ccp16.json covers synchronized-hop channel selection (FNV-1a32 oracle, epoch wrap hop change), not SFN-wrap/FSM. The canonical SFN-wrap vectors are ccp_sfn_wrap_slot_hash.json (19 cases), desync-FSM/multi-root vectors live in ccp16-desync.json and tdma_ccp_fsm.json; ccp_tdma.json does hold guard/slot-hash vectors.
- **Question for Opus:** Should §14.8 (and §14.7's matching citation) be amended to cite ccp_sfn_wrap_slot_hash.json + ccp16-desync.json + tdma_ccp_fsm.json alongside ccp_tdma.json? (Spec-only edit; no code impact.)

### R-09-017 — Duty-cycle numeric anchor (informational, low-priority flag)

- **Requirement:** EU868 10% example: 369.664 ms @ 60B SF9 ⇒ 973 packets/hour. (§14.4)
- **Classification:** implemented+tested, high confidence — flagged only because the regional duty-cycle tracker defaults EU868 to the ETSI 1% limit while §14.4's worked example uses the 10% sub-band; both budgets are pinned in duty_cycle_calculation.json.
- **Question for Opus:** Confirm §14.4 is intentionally a sub-band example (10%) and that the 1% tracker default is the general-case requirement carried by 02-physical-link — i.e., no divergence to adjudicate here.