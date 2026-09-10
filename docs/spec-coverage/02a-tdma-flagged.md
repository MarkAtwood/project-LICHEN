<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# spec/02a-tdma.md — flagged set for verification (sweep 2026-09-09)

Scope: every requirement with low confidence, or an ambiguous/divergent
classification. 18 of 35 requirements flagged. Section is not 06-security and
contains no oscore/EDHOC semantics, so criterion (c) does not apply.

## Divergent

### R-02AT-004 / R-02AT-005 — slot duration ≥ ceil(max airtime)+guard; not from typical frame
- Classification: divergent (C stack).
- Evidence: TDMA_SLOT_MS=2346 py sfn.py:13, rust constants.rs:97; C
  LICHEN_TDMA_SLOT_MS=250 link.h:88; vectors ccp_tdma.json /
  ccp_load_balancing.json guard_time_boundary_sf10; existing bead b7z9.17.
- Question for Opus: Does any C deployment profile legitimately justify 250 ms
  (i.e. is 02a-tdma.md:19's "configured schedule profile" meant to make 250
  conformant for small payloads), or is C non-conformant as b7z9.17 assumes?
  Decide whether the fix is a C constant change or a spec clarification that
  slot duration is profile-relative.

### R-02AT-007 — beacon wire format (0xBE / stratum / next-beacon-delta / SCHC-on-CH0)
- Classification: divergent (spec text stale vs both the implementation and
  adjudicated decision rule-0x08-tdma-beacon).
- Evidence: implemented 24B fixed uncompressed header + CBOR slot_map + 48B
  Schnorr48 (rust tdma_beacon.rs:84-131, py tdma_beacon.py:46-123, C beacon.c
  beacon.c:26-98); no 0xBE, no beacon stratum field, no next-beacon-delta
  field, no bitmap anywhere in code; decision rule-0x08-tdma-beacon says the
  beacon is NOT SCHC-compressed.
- Question for Opus: Confirm 02a-tdma.md:23-30 should be rewritten to the
  coordinated-capacity §2a.2 layout (R-02AT-007 bead asks for a spec amendment
  coordinated with existing bead 0aod). Is any field from the old format
  (notably next-beacon-delta u16 and a beacon-level stratum byte) still wanted
  on the wire, or dropped deliberately?

### R-02AT-008 — N_slots default 8-32
- Classification: divergent (upper bound unenforced).
- Evidence: only nonzero validation (rust tdma_beacon.rs:123-125); default 8
  (tdma.c:53, ccp.py:434).
- Question for Opus: Should "8-32" be a normative parser bound in all stacks,
  or is "nonzero u8" the intended contract (making the spec text descriptive)?

### R-02AT-012 — ANNOUNCE_DRIVEN rendezvous uses rx_channel
- Classification: divergent.
- Evidence: rx_channel never used for unicast TX in any stack (existing bead
  b7z9.107); encoding/parsing and ccp16-hop vectors exist (py link/channel.py,
  test_channel.py:494-501).
- Question for Opus: Is ANNOUNCE_DRIVEN a real mechanism in the current
  architecture or vestigial? If vestigial, 02a-tdma.md:39 and the priority
  list should be annotated.

### R-02AT-014 — rendezvous matches ccp9-rendezvous.json and ccp16-hop.json exactly
- Classification: divergent (Python-only vector consumption).
- Evidence: consumers py-only (test_vectors.py:1819-1887,
  test_ccp_sync_vector_consumers.py:395-495); Rust/C none; gap bead filed.
- Question for Opus: Confirm Rust/C consumers belong in lichen-node /
  lichen tests respectively, and whether the duplicate
  ccp9-rendezvous.json / ccp9_rendezvous.json pair (different consumers, one
  schema-exempt) should be merged first.

### R-02AT-020 — ACQUIRING admission → adopt SFN/time, send DAO with slot request
- Classification: divergent.
- Evidence: all FSMs go ACQUIRING→SYNCED directly on VALID_BEACON (C tdma.c:
  204-209, py tdma_fsm.py:26-27, rust gateway tdma_fsm.rs:45); no DAO slot
  request step; REJOINING is exit-only (C tdma.c:251-257); admission
  predicates (epoch floor time_sync.c:574-579, stratum stratum.py:303-325)
  exist but are not composed into the FSM.
- Question for Opus: Is the spec's DAO-with-slot-request handshake still the
  design (in which case the FSMs need a REJOINING/REQUESTING state and the
  DAO-ACK slot assignment path), or has the hash-based slot derivation
  (slot_for from beacon SFN) replaced DAO-requested slots, making the spec
  stale? Note lichen_link_set_slot (C tdma.c:263-284) supports both an
  explicit slot_id and 0xff auto-derivation, and no production caller exists.

### R-02AT-025 — rejoin timeout = 10 × superframe (Kconfig default 10 s)
- Classification: divergent.
- Evidence: C constant link.h:109 unreferenced; py constant sfn.py:15
  defined-but-unused; rust none; no Kconfig 10 s default (existing bead
  b7z9.19 covers C only).
- Question for Opus: Confirm the py defined-but-unused case belongs in b7z9.19
  (extend) and whether "Kconfig default 10s" means a Kconfig option should
  exist or the 10 s figure itself is stale.

### R-02AT-028 — equal strata → lowest IID MUST win
- Classification: divergent (spec-vs-spec conflict).
- Evidence: all five comparators insert dodag preference + 2×RSSI+SNR score
  before IID (C root_selection.c:29-52 / tdma_root_select.c:56-92 /
  multi_root.c:22-48; rust multi_instance.rs:984-991; py
  slot_coordination.py:196-199), following cc §2a.5.2; tests pin that order.
- Question for Opus: This is a genuine inter-spec conflict (02a-tdma.md:74,76
  vs 02a-coordinated-capacity.md §2a.5.2), and the "all nodes converge
  deterministically" claim of 02a-tdma.md:76 fails when RF scores differ.
  Flag for Mark: which order is authoritative? (Gap bead filed with label
  human.)

### R-02AT-030 — root switch → new DAO + SFN reset
- Classification: divergent (half-implemented).
- Evidence: SFN reset exists (C tdma.c:223-238; py on_version_change
  slot_coordination.py:485-556; rust multi_instance.rs:1183-1245); no stack
  sends a DAO on root switch (rust rpl_stack/mod.rs:207-221 only restarts DAO
  scheduling when unjoined; py node.py:1218-1251 sends capability re-announce,
  not DAO); gap bead filed.
- Question for Opus: Verify there is truly no root-change→DAO path in
  rust/lichen-node/src/rpl_stack (agent survey was not exhaustive over the
  dao_tx modules) before the gap bead is worked.

### R-02AT-033 — all implementations MUST match ccp_tdma.json, ccp_load_balancing.json, ccp9*.json
- Classification: divergent (consumer asymmetry).
- Evidence: see matrix row; tdma_ccp_fsm.json Rust/C unconsumed;
  ccp16-hop.json/ccp9*.json Rust/C unconsumed; ccp_load_balancing.json C
  unconsumed and py/rust skip drift_compensation_two_beacons values;
  slot_adjust_ticks=8 asserted nowhere. Gap bead filed.
- Question for Opus: Pick the canonical file for the ccp9 rendezvous twins
  (hyphen vs underscore) and confirm which of the unconsumed vectors are
  still normative for 02a-tdma vs superseded by coordinated-capacity sweeps.

## Ambiguous

### R-02AT-003 — superframe = beacon slot + N data slots + contention slots
- Classification: ambiguous.
- Evidence: no stack models a dedicated beacon slot or contention slot;
  contention = CH0 ALOHA (C link.h:110-112); superframe durations disagree
  across stacks (60 s rust superframe.rs:22-25; 8×2346 ms C
  recovery_countdown.c:28; 2 s py link/channel.py:20).
- Question for Opus: Is the beacon slot / contention slot structure a real
  scheduling requirement (needing slot-index 0 = beacon, contention slots in
  the map) or a conceptual description of CH0 + hash slots? Which superframe
  definition is canonical?

### R-02AT-019 — UNJOINED: CH0 listen only, no TX
- Classification: ambiguous.
- Evidence: FSM state exists but unwired (zero production callers of
  lichen_ccp_fsm_event); C tdma_tx_allowed returns true while unsynced
  (tdma.c:305), so the no-TX intent is unenforced; 02a-tdma.md:17 says
  contention slots serve new nodes (implying unjoined TX is expected there).
- Question for Opus: Reconcile "UNJOINED: no TX" (02a-tdma.md:61) with
  "Contention slot(s): new nodes" (02a-tdma.md:17): may an unjoined node TX
  join traffic in contention slots, or is strict listen-only intended until
  ACQUIRING? The C unsynced-pass (tdma.c:305) currently implements the former.

### R-02AT-034 — 60 s superframe ≤ 25 whole 2346 ms slots
- Classification: ambiguous.
- Evidence: arithmetic in no stack; three conflicting superframe definitions
  coexist (60 s GCP, 8×2346 ms TDMA, 2 s channel).
- Question for Opus: Low stakes (appendix arithmetic), but confirm whether
  this constant set is meant to constrain N_slots given the 60 s coordination
  superframe, and note it in the spec or drop it.

## Low confidence (implemented rows needing a second opinion)

### R-02AT-001 — MUST implement beacon sync mode
- Classification: implemented+tested (library/vector level), low confidence.
- Evidence: codecs + FSMs + vectors exist in all three stacks; no production
  beacon TX and no end-to-end sync loop (beads b7z9.22, C-bead 3).
- Question for Opus: Is "implement beacon sync mode" satisfied by
  library+vector conformance, or does it require the wired end-to-end path
  (making this a not-implemented)?

### R-02AT-009 — beacon uses sync word 0x34 or LLSec flag; old nodes MUST ignore
- Classification: implemented+untested, low confidence.
- Evidence: 0x34 set in rust constants.rs:4, C lr1110.c:504; known gap: Rust
  SX1262 paths never program it (b7z9.103); no test pins old-node-ignore.
- Question for Opus: Is there any test at any layer that would catch a sync
  word regression in the C or Python stacks (not just Rust), and does the
  "or LLSec flag" alternative exist as a selectable mode anywhere?

### R-02AT-010 — rendezvous priority SCHEDULED > HASH_BASED > ANNOUNCE_DRIVEN > FALLBACK
- Classification: implemented+tested, low confidence.
- Evidence: enum + priority comment link.h:173-191; ccp9 vector consumers
  pin mechanism strings (py test_ccp_sync_vector_consumers.py:454-495).
- Question for Opus: Find where the priority order is actually APPLIED at
  runtime (TX channel/mechanism selection) in any stack; if nowhere, the
  priority is decorative and the row should be divergent.

### R-02AT-013 — FALLBACK: CH0 contention
- Classification: implemented+untested, low confidence.
- Evidence: py fallback vector consumer (test_ccp_sync_vector_consumers.py:
  495); C contention constants link.h:110-112 with no verified call site.
- Question for Opus: Verify whether LICHEN_TDMA_CONTENTION_RETRIES/backoff
  are consumed by any C production TX path (DAO retransmission?) or are dead
  constants.

### R-02AT-022 — SYNCED: TX only in assigned slot; enforce tdma_tx_allowed()
- Classification: implemented+untested, low confidence.
- Evidence: C production call site exists (lichen_link_tx.c:110-112) but
  inert (now_ms=0 FIXME :99-109; set_slot never called in production, so
  synced=false and the gate always passes); rust tx_allowed has no
  production caller; py gate simulator-only.
- Question for Opus: Confirm there is no other production caller of
  lichen_link_set_slot() or tdma_clock::tx_allowed() that my sweep missed
  (searched lichen/, rust/lichen-{node,link,gateway,core}).

### R-02AT-023 — DRIFTING: extended CH0 listen, suppress TDMA TX
- Classification: implemented+tested (transitions), low confidence.
- Evidence: transitions vector-pinned (tdma_ccp_fsm.json py consumer;
  ccp16-desync.json all three); "suppress TDMA TX" unenforced — C
  synced=false makes tx_allowed return true (tdma.c:305).
- Question for Opus: Decide whether tdma_tx_allowed returning true when
  unsynced is the intended ALOHA-overlay fallback (then spec line 64 should
  say "suppress scheduled-slot TX, contention permitted") or a bug.

### R-02AT-026 — MUST follow lichen_node_init() ordering to avoid use-before-init
- Classification: implemented+untested, low confidence.
- Evidence: C ordering enforced by construction (tdma_init consumes ctx only
  after has_key; lazy-init latch lichen_link_tx.c:85-98); AGENTS.md graph is
  prose, no test.
- Question for Opus: Confirm whether any init-order test exists (e.g. in
  lichen/tests/link_ctx or util) that I missed; if not, is a static-assert
  test worth a bead, or is the comment-level guarantee acceptable?
