# spec/02a-coordinated-capacity.md — flagged set (sweep 2026-09-01)

Requirements with low confidence, ambiguous/divergent classification, or security-sensitive
semantics (2a.5.5). Each entry: requirement, my classification, evidence, and the specific
question for verification. Evidence abbreviations: P = python/src/lichen, R = rust/, C = lichen/subsys/lichen.

---

## 1. R-02a-080/108 — density threshold: spec+decision say >10, code+vectors say >8 (P0)

- **Requirement:** SelectChannel `IF Density > 10 THEN RETURN 0`; `Density>DENSITY_HIGH(10)` MUST use CH0 + SF ≥ 11 (2a.3.1, 2a.8, 2a.10.5).
- **My classification:** divergent (all three implementations + committed vectors).
- **Evidence:** P ccp.py:105,350,375; R rf_health.rs:386,653 (comment: "DENSITY_HIGH = 8 — matches ccp.py and the vector generator"); C link_ctx.c:705, gradient.c:320, lora_l2_tx.c:587. Vectors pin 8: ccp16.json `select_channel_timing_test` (density=9 → CH0), ccp13.json `dense_start_region0` (density=9 → 5‰). Commit `521ce0968d` ("density threshold 8 in all AdaptiveSFSelect oracles").
- **Conflict:** decision.jsonl `density-high` (2026-08-31, by mark) is FINAL: decision `>10`, and its rationale claims "All implementations, vectors, and 02-physical-link.md already use >10." That rationale is factually wrong for implementations+vectors as of this sweep.
- **Question for Opus:** I treated the decision as controlling (no re-adjudication) and filed a gap bead requiring implementations+vectors move to >10. Confirm this is the intended remediation direction (vs. the possibility the decision was recorded from stale information and should be re-adjudicated by mark — that call is mark's, not mine).

## 2. R-02a-045..053 — join rate limiting + PoW (2a.5.5.2) entirely absent (all implementations)

- **Classification:** not-implemented (bead filed).
- **Evidence:** rg for pow_challenge/pow_response/join-rate/backoff 20/40/80/320, per-IID 6/60s, global 60/60s, LRU 1024: zero production hits in P/R/C. Closest pieces are unrelated (CoAP 5.03 peer backoff, BroadcastRateLimiter, SOS ratelimit).
- **Question:** Spec commit `380396613a` added these requirements. Was an implementation ever planned under a different name (e.g., part of GCP-6.5 slot-claim limiting, which exists separately)? Confirm no duplicate bead before implementation starts.

## 3. R-02a-002/003/006/007/012 — CCP TDMA beacon wire format gaps

- **My classification:** divergent/partial. Rust has a codec (tdma_beacon.rs:83-268) + vector test (ccp_beacon_format.json); Python asserts layout from the vector but has NO pack/unpack/verify path; C has NO beacon format at all (no beacon_sig, setup_window, occupied_time, channel_mask, rx_chains symbols under lichen/).
- **Question:** C is the hardware shipping implementation. Is the intended architecture that C consumes beacons only via RPL DIOs (i.e., the 2a.2 beacon is Python/Rust-sim-only), or is the C absence a true interop gap? This determines whether bead "ccp-tdma-beacon-format-gaps" is P1 or a spec-scope clarification.

## 4. R-02a-012/013 — beacon_sig verification path

- **My classification:** divergent (Rust exposes signed_data/signature_bytes but no verify-gate; Python/C verify frames, not beacons).
- **Evidence:** R tdma_beacon.rs:151-174; P link_layer.py:1547-1621 (frame-level); C lichen_link_rx.c (-LICHEN_EAUTH) + root_selection.c:42-44.
- **Question:** Does any code path actually verify the Schnorr48 signature over beacon bytes 0..E-48 (as opposed to generic L2 frames)? If not, "Receivers MUST verify the signature against the sender's public key before accepting slot assignments or time updates" (2a.2) is unmet everywhere.

## 5. R-02a-021 — C slot duration 250 ms vs spec minimum 2,346 ms

- **My classification:** divergent (bead filed).
- **Evidence:** C link.h:88 `LICHEN_TDMA_SLOT_MS 250`; spec 2a.2 mandates ≥ ceil(2,295.808 ms) + 50 = 2,346 ms for profile 0x01; ccp_tdma.json vectors use 2346; Python TDMA_SLOT_MS=2346. C link_crypto test passes ccp_tdma vectors with guard offsets 199/200 — question: does that test substitute its own slot duration (test-local constant), masking the production 250 ms?
- **Question for Opus:** Verify whether 250 ms is a deliberate alternative profile (contradicting "profile 0x01 is fixed" in 2a.7) or a stale default. If deliberate, spec needs a profile table; if stale, bead stands as P1.

## 6. R-02a-040/041 — constant-time beacon signature verification

- **My classification:** implemented+tested for C (Monocypher crypto_verify16, schnorr48.c:201); Python uses plain `==` (crypto/schnorr48.py:193) — I did NOT flag this because the project threat model (AGENTS.md) explicitly waives Python constant-time requirements; Rust Schnorr48 verify path was not located by the sweep.
- **Question:** (a) Confirm the Rust implementation tree has no Schnorr48 beacon/frame verify path (i.e., Rust relies on ring/ed25519-dalek internally — if so, cite the primitive and whether its comparison is constant-time). (b) Confirm the Python `==` waiver extends to the 2a.5.5.1 spec text or whether the spec should carve out a Python exception.

## 7. R-02a-060 — root key revocation

- **My classification:** ambiguous.
- **Evidence:** No revocation API found in P trust.py, R trust crates, or C. 2a.5.5.3 requires OOB revocation capability holders to mark keys revoked and discard beacons.
- **Question:** Does revocation exist elsewhere (LCI /keys resource? GCP-3 delegation tokens? DANE)? If nowhere, this is a not-implemented MUST that fell below my 10-bead cap — should it be promoted to a bead?

## 8. R-02a-064 — desync timing parameters are partially implemented everywhere

- **My classification:** divergent (two beads filed: C undefined macros/build break; Python missing GUARD_PPM).
- **Evidence:** C: LICHEN_TDMA_BEACON_TIMEOUT_SUPERFRAMES referenced at tdma.c:156 with no #define in-tree (gcc -fsyntax-only fails); LISTEN_PERIOD 30/60, DELAY_PER_NODE 5, MAX_STARTUP_DELAY 300, REJOIN_TIMEOUT 10 absent in C. P: DESYNC_CONSTANTS 30/60/5/300 exist (sfn.py:60-65) but no drift>GUARD_PPM→DESYNCED transition exists; decision `guard-ppm` says "All implementations ... use 5000" — Python uses none. R: guard_ppm is an unnamed parameter (5000 in tests + ccp7_holdover.json).
- **Question for Opus:** Which implementation is the canonical desync FSM, and should the 14.8 CCP FSM (UNJOINED/ACQUIRING/SYNCED/DRIFTING/REJOINING, in P tdma_fsm.py / R lichen-gateway/tdma_fsm.rs / C lichen_ccp_fsm_event) and the 2a.6 DesyncFSM (SYNCED/DESYNCED/RECOVERING, in P sfn.py / R desync.rs / C tdma.c) be merged? They coexist in all three stacks with different states.

## 9. R-02a-067 — stratum ordering inside RECOVERING acceptance

- **My classification:** ambiguous.
- **Evidence:** Stratum ordering exists in root selection (P slot_coordination.py, R multi_instance.rs, C root_selection.c) but the 2a.6.4 requirement is specifically that a beacon in RECOVERING is not accepted as valid before stratum comparison. No impl shows that hook inside the desync FSM's on_beacon.
- **Question:** Is the root-selection stratum gate (which runs before/around FSM input) an adequate implementation of this clause, or is a pre-acceptance check inside the FSM required?

## 10. R-02a-069 — RPL version change during recovery

- **My classification:** divergent — handled by the parallel §14.8 FSM, not the 2a.6 FSM.
- **Evidence:** P timing/tdma_fsm.py:10-44 (`rpl_version_increment` → DRIFTING); R lichen-gateway/src/tdma_fsm.rs:42-55; C tdma.c:196-234. The 2a.6 DesyncFSM in P/R has no version input; "reset consecutive_valid=0 and remain in RECOVERING" not evidenced.
- **Question:** Same as #8 — which FSM is normative for 2a.6.5?

## 11. R-02a-096 — CAD immediately before every scheduled transmission

- **My classification:** divergent (C yes; P/R invocation wiring not evidenced).
- **Evidence:** C: CAD run inside TX path (lora_l2_tx.c:122-278) + csma.c enforcement. P: CsmaState (timing/csma.py) exists; no located call in the sim TX path feeding it per-opportunity. R: CcaState::on_cad_result pure function; per-TX call site not found (gateway slot allocator is schedule-side only).
- **Question:** Confirm whether Python sim and Rust have a per-transmission CAD hook (search terms tried: cad, cca, clear_channel, on_cad_busy).

## 12. R-02a-104 — consolidated MitigateInterference procedure

- **My classification:** divergent — pieces exist (slot gate, guard, CCA, SF select, duty check) but no implementation executes the 13-step chain per transmit opportunity, and Rust's pieces are not wired into a node TX path at all.
- **Question:** Is the consolidated procedure intended as a reference algorithm (equivalent behavior suffices) or must it exist as a discrete module? If the former, the bead can be closed as spec-interpretation with a note; if the latter, the node-TX wiring gap (Rust) should be fixed.

## 13. R-02a-073/074 — profile 0x01 ADR freeze + future-profile gating

- **My classification:** ambiguous (process requirements with thin code surface).
- **Evidence:** SF baseline 10 + Kconfig exist; no located enforcement of "ADR MUST NOT change these parameters inside a schedule generation"; no ADR module found interacting with schedule generations.
- **Question:** Is there an ADR implementation anywhere that this clause binds, or is ADR entirely absent (making the clause vacuous)?

## 14. R-02a-076/109 — "listen continuously on CH0"

- **My classification:** ambiguous.
- **Evidence:** CH0 reserved + failover-to-CH0 paths exist in all three stacks; but continuous listening (radio duty cycle, wake-on-CAD semantics) has no located implementation point in P sim, R, or C RX loops.
- **Question:** Is continuous CH0 listen implemented implicitly (radio always in RX between slots) or is it a real gap in duty-cycled nodes (which cannot listen continuously under duty-cycle limits — the spec clause may itself conflict with 2a.9 budgets)?

## 15. R-02a-113 — FNV-1a32 full-width DODAG ID hashing

- **My classification:** implemented+tested (low confidence on one sub-clause).
- **Evidence:** 8-byte EUI64 and 12-byte (EUI64+epoch) inputs pinned by hash_32.json + ccp15.json in P/R/C. The 16-byte DODAG-ID full-width rule (2a.10.7 rule 2) has no located test vector or call site hashing a full 128-bit DODAG ID.
- **Question:** Is full-width DODAG-ID hashing exercised anywhere (RPL rank/path computations?), or should a hash_32.json extension vector be added?

## 16. R-02a-004 — beacon flags bit semantics

- **My classification:** implemented+tested (low confidence).
- **Evidence:** flags field parsed/asserted at offset 13 (R codec, P layout test) but I found no test asserting the meaning of individual bits (bit0 scheduled, bit1 CSMA, bit2 CH0-RX, bit3 GNSS-PPS).
- **Question:** Which consumer reads these bits, and do any tests pin them?

## 17. R-02a-059 — cache clear on root key rotation (not-implemented MUST, overflow bead)

- **My classification:** not-implemented (below bead cap).
- **Evidence:** Trust-store rotation exists (P crypto/trust.py, R trust crates) but no code clears TDMA slot_map/SFN/schedule state on acceptance of a rotation.
- **Question:** Confirm no hidden linkage (e.g., epoch counter in C link_ctx named "key-rotation counter" at tdma.c:244 comment — is `ctx->epoch` the u8 key-rotation counter referenced there, and does rotating it reset schedule state?).

## 18. Oracle-strength concern: ccp_slot_hash_carry.json

- **Finding:** `test/vectors/generate_ccp_slot_hash_carry.py` imports the production implementation (`from lichen.timing.sfn import hash_32, slot_for`) — the vector is generated by the code under test, not an independent oracle. The u32-carry property is separately hand-checked in tests/test_ccp_sync_vector_consumers.py:511-530, so the exposure is limited, but per the repo's test-integrity rules this vector family cannot serve as an independent oracle.
- **Question for Opus:** Should the generator be rewritten as an independent oracle (like generate_hash_32.py, which imports no LICHEN code), and should the regenerated vectors be treated as the interop reference?

## 19. Python internal divergence: two adaptive-SF/channel selectors disagree

- **Finding:** `python/src/lichen/ccp.py` (density>8) vs `python/src/lichen/link/adaptive_sf.py` (density>10 at :137, plus a heuristic short-circuit at :128-132) implement AdaptiveSFSelect differently; `channel_plan.py:270-289` is a second select_channel. The two Python paths can return different SF/channel for identical inputs at density 9-10.
- **Question for Opus:** Which Python module is the production path (sim vs link layer)? The density bead (item 1) must unify both, and the duplicate should likely be deleted.

## 20. Pre-existing bead b7z9.21 contradicts the final decision `rule-0x08-tdma-beacon`

- **Finding:** Bead `project-LICHEN-worker6-b7z9.21` ("SCHC Rule 0x08 (TDMA_BEACON) absent from all implementations, spec 02a 2a.2") demands implementing SCHC Rule 0x08 for TDMA beacons. The adjudicated decision `rule-0x08-tdma-beacon` (spec/decisions.jsonl, 2026-08-31) explicitly abandoned Rule 0x08: "TDMA beacon is not an IPv6/UDP packet… No implementation ever built Rule 0x08. Spec amended to describe the uncompressed format all three implementations use." The spec now conforms (grep_absent "Rule 0x08" passes).
- **Question for Opus/mark:** The bead contradicts a final decision and should be superseded or closed. I did not close another worker's bead — flagging for mark.

## 21. Duplicate-discovery note: prior 02a sweep already filed most gap beads

- **Finding:** Beads b7z9.17 (C slot duration), b7z9.22 (slot_map end-to-end), b7z9.23 (channel_mask intersection), b7z9.25 (Py/Rust desync + multi-root FSM gaps), b7z9.26 (join rate limiting), b7z9.28 (root key rotation), b7z9.29 (CCP-15 metrics layer), b7z9.30 (C adaptive-SF floors), b7z9.19 (C rejoin timeout) already cover most 2a MUST-gaps. This sweep filed 5 new unique beads (.58, .60, .62, .63, .65), closed its own 3 duplicates (.59, .61, .64) with pointers, and cross-references the prior beads in the matrix rather than re-filing.
- **Question for Opus:** None — informational for the wave runner, so the `/do-beads` pass works b7z9.17-.30 rather than re-implementing what my closed duplicates described.
