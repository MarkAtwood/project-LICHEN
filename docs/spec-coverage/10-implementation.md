## spec/10-implementation.md — coverage (sweep 2026-08-31)

8 requirements extracted (1 MUST, 1 explicit MAY, 6 keyword-less normative).
§16.1 (repository tree), §16.3 (stack tables), §16.5 (dependency tables), and
§16.6 (I-D list) are informative with no behavioral requirements — not
extracted. The section's normative core is §16.7 (DAO Origin Persistence).
Gap beads filed under epic `project-LICHEN-worker6-b7z9`: **0** (the only MUST
is implemented+tested; keyword-less divergences noted in matrix per preamble,
not beaded). Gap-bead overflow: 0 (0 MUST-gaps; cap 10). The C stack persists
no DAO state at all (no TX record, no RX floor) — the largest real gap in this
section, surfaced via the keyword-less rows R-10-001..004.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-10-001 | (no kw) TX persists public-key identity + last reserved Origin Sequence + complete last signed DAO bytes, crash-safe (§16.7) | divergent | Rs: `DaoTxState{public_key, last_reserved, last_signed_dao}` persistence.rs:122-131, `reserve_next` :252, `finalize_signed` :284 (unit tests :764+). Py: `TxState(sequence, dao_bytes)` dao_persistence.py:74-78 + `store_tx_state` :123, TwoSlotFilePersistence crash-safe :256-302 — but the record itself carries no pubkey field (manager single-identity; see flagged set). C: no DAO TX persistence — RAM-only manager rpl_routing.h:541-555; TX is builder-only, no caller sends (matches R-08N-006 finding) | high |
| R-10-002 | (no kw) On reboot the TX API exposes the exact retained bytes for retransmission; never reconstructs or re-signs (§16.7) | divergent | Rs: `DaoTxState::open` persistence.rs:187, `last_signed_dao()` :248. Py: `_restore_tx_state` dao_manager.py:315-332 (missing/corrupt = hard failure) + `test_get_last_dao_bytes_returns_persisted_bytes` test_dao_persistence.py:933. C: absent (no TX record exists) | high |
| R-10-003 | (no kw) RX persists only pubkey + accepted high-water sequence + digest; not the complete DAO or route table (§16.7) | divergent | Rs: `OriginReplayStore` get/set_floor(pubkey, seq, dao_digest) dao_origin.rs:136-140; `DaoRxState` + `encode_high_water` persistence.rs:367, :643 (round-trip tests :765, :786). Py: `RxFloor(sequence, digest)` dao_persistence.py:82-86, `store_rx_floor(pubkey,…)` :148. C: `root_state` RAM-only rpl_routing.h:508-513, no NVS/settings binding (rg clean rpl_root.c); link-layer floors replay_persist.h:56-61 are 16-bit LLSec state, not DAO origin state | high |
| R-10-004 | (no kw) Fresh receive: persist the RX floor before exposing the route or returning success (§16.7) | divergent | Rs: `unavailable_replay_storage_leaves_dao_state_unchanged` dao_origin_vectors.rs:265-300 (forced persist failure → `Persistence` outcome, route None, storage snapshot unchanged). Py: documented order "7. replay-floor persistence for a fresh DAO → 8. atomic in-memory route mutation" dao_manager.py:660-671 + `test_fresh_dao_higher_sequence_commits_floor` test_dao_origin.py:1263. C: ordering documented only rpl_dao_process.c:243-244 — no persistence backing to order | high |
| R-10-005 | (no kw) Equal-sequence/equal-digest retransmission does not rewrite persistence; idempotent re-parse + exact self-Target revalidation (§16.7) | implemented+tested | Py: `test_idempotent_retransmission_does_not_rewrite_floor` test_dao_origin.py:1212. Rs: retransmission flag dao_origin.rs (`is_retransmission`, "False for idempotent retransmissions") + `version_floor_rejects_stale_root_authorization_and_replays_are_idempotent` lichen-node/src/routing/tests.rs. C: "Equal-seq exact digest = idempotent retransmission … MUST NOT rewrite floor. Matches Rust" rpl_dao_process.c:244-246 | high |
| R-10-006 | MUST snapshot complete route + replay-floor + storage state around rejected DAOs to test no partial mutation (§16.7) | implemented+tested | Rs: `unavailable_replay_storage_leaves_dao_state_unchanged` dao_origin_vectors.rs:265 (storage_snapshot compare :280-297), `fixed_dao_origin_vectors_match_rpl_node_handler` :144 (52 vectors from test/vectors/dao_origin_signature.json, floor-mutation asserts), `delegated_prefix_is_allowed_and_denial_leaves_no_state_mutation` dao_prefix_authorization.rs:327, `foreign_slash64_and_default_route_fail_closed_without_mutation` :723. Py: `test_zero_sequence_dao_persists_no_floor_and_installs_no_route` test_dao_origin.py:1494-1526 (route snapshot + no RX floor), `test_multi_floor_batch_is_rejected_without_partial_commit` test_dao_persistence.py:361, `test_ninth_hop_dao_is_rejected_atomically` test_dao.py:490. C: gate-denial zero-mutation rpl_dao_auth/src/main.c:239 (byte-identical route), :293, :612 — route/replay legs only; storage leg vacuous (C persists no DAO state; see flagged set) | high |
| R-10-007 | MAY disable store-and-forward on STM32WL (§16.4) — explicit MAY | not-implemented (conformant — MAY) | No platform-gated toggle: lichen Kconfigs carry no store-and-forward option (rg clean); DTN store-and-forward ungated in Rs lichen-node/src/routing/dtn.rs and Py routing/router.py; absent in C. No bead (MAY) | high |
| R-10-008 | (no kw) Non-Neo R1 display variants and LR1121 radios require separate board files + validation evidence before being advertised as supported (§16.2) | ambiguous | No non-Neo R1 or LR1121 board files exist (find: only lichen/boards/muzi/r1_neo/*) — constraint currently satisfied by absence. Unclear whether product-scoping prose belongs in a normative matrix (see flagged set) | low |

### Histogram (rows)

- implemented+tested: 2 (R-10-005, R-10-006)
- implemented+untested: 0
- divergent: 4 (R-10-001, 002, 003, 004 — all on the C stack's absent DAO persistence; Rs/Py conformant and tested)
- not-implemented: 1 (R-10-007 — explicit MAY, absence conformant)
- ambiguous: 1 (R-10-008 — scope question)

### Gap beads filed (0; cap 10; overflow 0)

The section's only MUST (R-10-006) is implemented+tested in all three stacks at
their respective layers, so no gap beads are due. The C stack's total absence
of DAO persistence (TX record and RX floor, R-10-001..004) is keyword-less
normative text — noted here per matrix preamble, not beaded. Adjacent
already-beaded work: `project-LICHEN-worker6-d5bw` (equal-generation DAO
persistence slots, python). C DAO TX being builder-only was already recorded
as divergence under R-08N-006 (spec/08-nodes sweep).
