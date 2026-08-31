# Flagged set — spec/10-implementation.md (sweep 2026-08-31)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or section 06-security/OSCORE-semantics sensitive. Each entry:
requirement, classification, evidence, and the specific question to answer.
The section is not 06-security and no row touches oscore/EDHOC protocol
internals; §16.7's persistence semantics descend from spec 8.6 (security) but
concern durability ordering, not crypto — no human-only edit bar applies.

## R-10-006 — MUST snapshot complete route + replay-floor + storage state around rejected DAOs to test no partial mutation (§16.7)

- Classification: implemented+tested (confidence high).
- Evidence: Rs `unavailable_replay_storage_leaves_dao_state_unchanged`
  dao_origin_vectors.rs:265-300 (forced storage-write failure → `Persistence`
  outcome, `lookup_route` None, `storage_snapshot` byte-identical) and the
  52-vector `fixed_dao_origin_vectors_match_rpl_node_handler` harness
  (dao_origin_vectors.rs:144, floor-mutation asserts) against
  `test/vectors/dao_origin_signature.json`; Py
  `test_zero_sequence_dao_persists_no_floor_and_installs_no_route`
  test_dao_origin.py:1494-1526, `test_multi_floor_batch_is_rejected_without_partial_commit`
  test_dao_persistence.py:361, `test_ninth_hop_dao_is_rejected_atomically`
  test_dao.py:490; C gate-denial zero-mutation tests
  rpl_dao_auth/src/main.c:239 (byte-identical route), :293, :612.
- Question: C asserts route/replay invariance around rejections but snapshots
  no *storage* state — because C persists no DAO state at all (RAM-only
  `root_state`, rpl_routing.h:508-513, no NVS binding). Does the MUST's
  "storage state" leg demand the persistence exist first (making C divergent
  and bead-worthy), or is the leg vacuous for an implementation with nothing
  durable to snapshot? My call: vacuous, no bead — second opinion wanted,
  since this is the only MUST in the section.

## R-10-001 — (no kw) TX record stores public-key identity + last reserved Origin Sequence + complete last signed DAO bytes, crash-safe (§16.7)

- Classification: divergent (confidence high) — driven by C's total absence of
  DAO TX persistence (RAM-only manager rpl_routing.h:541-555, builder-only TX).
- Evidence: Rs `DaoTxState{public_key, last_reserved, last_signed_dao}`
  rust/lichen-rpl/src/persistence.rs:122-131 matches §16.7 field-for-field.
  Py `TxState(sequence, dao_bytes)` dao_persistence.py:74-78 — the persisted
  record carries **no public-key identity field**; the identity is implicit in
  the single-identity `DaoManager` that owns the store.
- Question: Does §16.7 require the public key *inside* the persisted TX record
  (Py divergent even aside from C), or is manager-level single-identity
  binding conformant? If the former, Python needs a record-schema change and
  this row's status for Py flips to divergent.

## R-10-004 — (no kw) Fresh receive: persist the RX floor before exposing the route or returning success (§16.7)

- Classification: divergent (confidence high) — Rs/Py implement and test the
  ordering (dao_origin_vectors.rs:265-300 proves route never exposed when the
  floor write fails; dao_manager.py:660-671 documents persist-then-apply);
  C documents the ordering (rpl_dao_process.c:243-244 "Root MUST send success
  DAO-ACK after replay-floor persistence") but has no persistence layer, so
  the ordering is unenforceable there.
- Evidence: as above; C floor update is "done by caller (link/OSCORE)"
  (rpl_dao_process.c:257) and no such caller persists (rg clean for NVS/
  settings in lichen/apps/gateway/src/rpl_root.c and the rpl subsys).
- Question: For C, is "documented ordering with no persistence backing"
  divergent (my classification) or not-implemented? And given the matrix
  preamble notes keyword-less divergences without beads, should this one be
  escalated to a gap bead anyway — it is the concrete mechanism behind the
  abstract "C persists no DAO state" finding shared by R-10-001..004?

## R-10-008 — (no kw) Non-Neo R1 display variants and LR1121 radios require separate board files + validation before being advertised as supported (§16.2)

- Classification: ambiguous (confidence low).
- Evidence: no non-Neo R1 or LR1121 board files exist (find over
  lichen/boards returns only lichen/boards/muzi/r1_neo/*), so nothing is
  advertised that lacks the required evidence — the constraint is currently
  satisfied by absence.
- Question: Is this product-scoping prose rather than a normative requirement
  (i.e., should the row be dropped from the matrix), or is it a standing
  constraint future board work must honor? If the latter, is
  "ambiguous" the right bucket versus a conformant-by-absence note?
