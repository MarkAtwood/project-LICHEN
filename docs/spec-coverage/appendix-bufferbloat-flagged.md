<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

## spec/appendix-bufferbloat.md — flagged for Opus verification (sweep 2026-09-09)

Flag criteria: low confidence, ambiguous or divergent classification, or
governance text whose testability is unclear. 7 items. The decision
`custody-best-effort` (spec/decisions.jsonl) is FINAL and governs R-BB-006 —
Opus should not re-adjudicate custody as guaranteed delivery.

### 1. R-BB-004 — Python runtime ACK/NACK deadline is 5 s, spec says 10 s (divergent)

- Requirement: datagram-service deadlines — routing 5 s, ACK/NACK 10 s,
  application data default 60 s (spec lines 76–78).
- Classification: divergent.
- Evidence: C `TX_DEADLINE_ACK_MS=10000` (lichen/subsys/lichen/link/include/lichen/tx_queue.h:73);
  Rust `DEADLINE_ACK_MS=10_000` (rust/lichen-core/src/tx_queue.rs:253); vector
  oracle `ack_deadline_ms: 10000` (test/vectors/tx_queue_expiry.json,
  bufferbloat_congestion.json). Python runtime
  `python/src/lichen/link/tx_queue.py:39 DEADLINE_ACK_MS = 5000  # alias for
  ROUTING`. Python has a second module `lichen/timing/tx_queue.py:28` with the
  correct 10000; the vector tests drive timing/ while runtime (node.py:72)
  uses link/.
- Question for Opus: Confirm the fix is to change the runtime link/ module to
  10000 (and delete or reconcile the duplicate timing/ module), not to amend
  the spec. Is the link/timing module duplication itself a tracked hazard?

### 2. R-BB-005 — custody TX-queue deadline 120 s: no implementing mapping found (ambiguous)

- Requirement: message service — custody messages carry absolute TTL per
  05 §9.8; TX queue deadline 120 s = time to reach first custodian
  (spec lines 80–82).
- Classification: ambiguous.
- Evidence: absolute TTL exists (`LICHEN_DTN_DEFAULT_TTL_SEC`,
  lichen/subsys/lichen/coap/coap_dtn.c:245-247; rust routing/dtn.rs; python
  routing/dtn_option.py). No code gives custody/message-service packets a
  120 s TX-queue deadline; P2 default is 30 s in all three stacks
  (tx_queue.h:74, tx_queue.rs:256, link/tx_queue.py:40); 120000 exists only
  as the P4 BULK deadline. `rg -i custod` over src is empty.
- Question for Opus: Is the 120 s TX-queue deadline for custody originators a
  requirement implementations must add (e.g. P2 custody packets pushed with an
  explicit 120 s deadline), or is P2/30 s + DTN absolute TTL an accepted
  reading of the table? If the former, this becomes a not-implemented MUST
  gap bead (none filed yet — waiting on this adjudication).

### 3. R-BB-006 — "custody acceptance ends TX-queue deadline" transition: no evidence (ambiguous)

- Requirement: once a custody-capable node accepts the message, the TX-queue
  deadline no longer applies; custody remains best effort (spec lines 85–90).
- Classification: ambiguous.
- Evidence: DTN store path stores with absolute expiry and clockless fail-open
  (coap_dtn.c:233-261, R-05-080 comment :557), but no explicit transition
  removes a queued message from TX-queue-deadline accounting upon custody
  acceptance; no custody vocabulary exists in src. The best-effort clause
  conforms to the FINAL decision `custody-best-effort` — not in question.
- Question for Opus: What code object would demonstrate the acceptance
  transition (message moves from TX queue to DTN store on custody-ack)? If the
  transition is only structural (accepted messages leave the TX queue by
  construction), say so and this row can be closed as implemented-by-design.

### 4. R-BB-007 — "waiting for a radio opportunity MUST NOT extend deadline" is only proven in Python (ambiguous)

- Requirement: spec line 94–95 MUST NOT.
- Classification: ambiguous.
- Evidence: Python requeue preserves original deadline
  (link/tx_queue.py:637-644; tests `test_complete_failure_preserves_original_deadline`
  tests/link/test_tx_queue.py:873). Rust `tx_queue_pop` removes the item and
  no caller re-queues after TX failure; C L2 runs synchronous push-then-pop
  (lora_l2_tx.c:475-489). Rust/C satisfy the MUST vacuously (no waiting
  requeue path exists at all), and failure-retry deadline semantics are
  untested there.
- Question for Opus: Does conformant Rust/C behavior require an explicit
  retry path that preserves the original deadline (=> implemented+untested
  gap bead), or is pop-once semantics (caller re-pushes with its own policy)
  acceptable because the queue never extends deadlines internally?

### 5. R-BB-008 — coalescing MAY + MUST NOT: vacuous (ambiguous)

- Requirement: MAY coalesce replaceable state updates under owning-resource
  semantics; MUST NOT coalesce arbitrary messages/commands/receipts/custody
  (spec lines 95–97).
- Classification: not-implemented (MAY), MUST NOT vacuously satisfied.
- Evidence: only coalescing found is RPL DIS solicitation (rpl_dis.c:113),
  unrelated. No position-update coalescing, no arbitrary-message coalescing.
- Question for Opus: Confirm vacuous satisfaction of the MUST NOT is the
  right matrix reading, and that the unimplemented MAY (07 §10.3
  position coalescing) stays bead-free per the MAY rule.

### 6. R-BB-012 (with R-BB-011 mesh clause) — NACK-upstream intent in docs/vectors vs "record locally, no invented NACK" spec text (low confidence)

- Requirement: without an existing response mechanism, record the forwarding
  drop locally rather than inventing a MAC ACK/NACK or unsolicited mesh error;
  existing-protocol failure response only where that protocol permits
  (spec lines 124–128).
- Classification: implemented+tested (behavior conforms), low confidence
  because documentation and vectors express the opposite intent.
- Evidence: no MAC ACK/NACK exists (behavior conforms); drops recorded
  locally (python stats asserted tests/routing/test_no_silent_drops_vectors.py:47;
  rust forward_buffer.rs:319; C router.c). But forward_buffer.rs:5-6,29-30,106-107
  and stack.rs:95,738 say "a NACK should/SHOULD be sent upstream";
  test/vectors/no_silent_drops.json B.2.5.2 lists "NACK to mesh source (if
  routable)" as a requirement implemented via ICMPv6 Destination Unreachable
  ADMIN_PROHIBITED (helper exists+tested in python icmpv6.py:407, never called
  in runtime); test/vectors/bufferbloat_congestion.json fairness vector pins
  `expected: "nack_when_source_full"`. Gap bead filed.
- Question for Opus: Is ICMPv6 Dest-Unreachable(ADMIN_PROHIBITED) the
  "existing protocol failure response" the spec permits (=> wire it in all
  three stacks and keep the vectors), or does the current spec text intend
  local-only recording (=> fix the doc comments and regenerate the vectors)?
  Either resolution is a spec/impl alignment change — do not weaken tests
  without fixing the underlying intent.

### 7. R-BB-023 — new-wire-behavior governance clauses: testability unclear (low confidence)

- Requirement: new wire behavior requires exact versioned encodings and
  independent conformance oracles; more channels do not grant more airtime;
  experiments do not establish production readiness (spec lines 229–231).
- Classification: implemented+untested (governance observed in vector files:
  format_version 2, spec-literal generators).
- Evidence: test/vectors/bufferbloat_congestion.json and no_silent_drops.json
  carry format_version/schema and spec-derived literals;
  test/vectors/generate_forwarding_buffer.py generates from spec. No test
  asserts the governance clauses themselves.
- Question for Opus: Should this row be reclassified as informational (no
  code requirement), or does the sweep need a process-level check (e.g. a
  lint that every new wire vector file carries format_version + independent
  oracle provenance)?
