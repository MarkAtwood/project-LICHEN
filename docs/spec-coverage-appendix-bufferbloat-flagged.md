# Flagged set — spec/appendix-bufferbloat.md (sweep 2026-08-31)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or section 06-security / oscore-EDHOC-semantics sensitivity.
Each entry: requirement, classification, evidence, and the specific question
to answer. Companion rows: "spec/appendix-bufferbloat.md — coverage (sweep
2026-08-31)" in docs/spec-coverage.md (`R-ABF-001` .. `R-ABF-016`). No rows
touch oscore/EDHOC internals, so nothing carries the `human-only` label.

## Section-level policy question — no capitalized RFC 2119 keywords

- Spec: whole file. The appendix contains zero capitalized MUST/SHOULD/MAY.
  Three lowercase "must"s: line 27 (regulatory wait arithmetic — informative),
  line 90 ("Senders must handle this" — Design Principle 4), line 175
  ("Bufferbloat avoidance must be tested under congestion" — Testing).
- The sweep followed the established matrix preamble ("keyword-less normative
  rows are noted, not beaded"), consistent with the spec/08-nodes and
  spec/01-architecture sweeps (0 keyword rows → 0 beads) and the
  appendix-border-router precedent (only the capitalized MUST was
  bead-eligible).
- Question for Opus: do the lowercase "must"s at lines 90 and 175 carry
  normative force here? The vector set treats the appendix as normative
  (test/vectors/tx_queue_expiry.json: "All implementations … MUST match these
  vectors exactly"), and the appendix defines the project's only quantitative
  queue contract. If lines 90/175 are ruled normative, R-ABF-011 (NACK) and
  R-ABF-016 (missing congestion scenarios) become MUST-gaps → file the
  pre-authorized beads below. If not, 0 gap beads stands.

## R-ABF-003 — Forwarding: 2 packets per source max; total 16 packets max

- Spec: Design Principles 1 ("Forwarding: 2 packets per source max") and
  Implementation Guidelines → Forwarding Buffer (MAX_FORWARDING_SOURCES 8,
  MAX_PACKETS_PER_SOURCE 2, "Total forwarding buffer: 16 packets max").
- Classification: divergent (confidence high on facts; disposition is the
  question).
- Evidence, mechanism implemented+tested at unit level in all three stacks:
  - Rust: `MAX_FORWARDING_SOURCES=8` / `MAX_PACKETS_PER_SOURCE=2`
    (rust/lichen-node/src/forward_buffer.rs:20-23) with unit tests
    per_source_limit_enforced / multiple_sources_independent_limits /
    max_sources_eviction (forward_buffer.rs:319-384); `ForwardBuffer` is a
    field of the node Stack (stack.rs:216) with public accessors
    (stack.rs:712-761); oracle constants asserted in
    rust/lichen-core/tests/bufferbloat_vectors.rs:95-100.
  - Python: `ForwardingBuffer` twice — link/forwarding_buffer.py:91 and
    embedded in Router (python/src/lichen/routing/router.py:144-239, field
    router.py:401) — consumed by python/tests/link/test_forwarding_buffer.py
    (13 vectors from test/vectors/forwarding_buffer.json) and
    python/tests/routing/test_router.py:958.
  - C: Kconfig defaults 8/2/16 (lichen/subsys/lichen/routing/Kconfig:121-144,
    router.h:65-75) + suite lichen/tests/routing_fwd_buffer (asserts
    nacks_sent==1 at src/main.c:123).
- Evidence, not wired into any relay datapath:
  - Rust: `Stack::queue_forward` (stack.rs:704) has zero callers (rg across
    rust/); the IPv6 receive/forward path never enqueues into the buffer.
  - Python: `try_buffer`/`dequeue` have zero callers in python/src; node.py's
    forward path (node.py:1451 router.route → forward) never touches
    `router.forwarding_buffer`.
  - C: `lichen_router_fwd_enqueue` has zero callers outside router.c/router.h,
    and `lichen_router_init` has zero callers in any app (gateway sets
    CONFIG_LICHEN_ROUTING=y, apps/gateway/prj.conf:31, which compiles the
    router in but never instantiates it).
- Question for Opus: is "library component + unit tests + shared vectors"
  sufficient for a design-principle row, or does the principle regulate the
  relay datapath (making this divergent-by-unwiring in all three stacks)?
  Note the same unwired pattern was classified divergent for R-04-013
  (broadcast limiter) and R-07-045-adjacent components.
- Pre-authorized disposition: if ruled a MUST-gap, file one bead (labels
  `bufferbloat` + `spec-gap`, parent = the sweep epic): "Wire per-source
  forwarding buffer into relay datapaths (R-ABF-003)" — suggested placement:
  rust/lichen-node/src/receive path + python/src/lichen/node.py forward path
  + C router instantiation (lichen_router_init caller), each feeding
  try_buffer/queue_forward/lichen_router_fwd_enqueue and the NACK hook
  (R-ABF-011).

## R-ABF-007 — ACK/NACK: 10 s deadline

- Spec: Design Principles 2 deadline table, "ACK/NACK: 10 s deadline".
- Classification: divergent (confidence low — flagged).
- Evidence, constant exists and is vector-pinned:
  - Rust `DEADLINE_ACK_MS = 10_000` (rust/lichen-core/src/tx_queue.rs:253);
    C `TX_DEADLINE_ACK_MS 10000` (lichen/subsys/lichen/link/include/lichen/
    tx_queue.h:73); Python timing module `DEADLINE_ACK_MS = 10000`
    (python/src/lichen/timing/tx_queue.py:28); vector
    test/vectors/tx_queue_expiry.json `default_deadline_ack` + constants.
- Evidence, the effective default is 5 s:
  - ACK is an alias of ROUTING priority in all stacks (C tx_queue.h:63
    `TX_PRIORITY_ACK = TX_PRIORITY_ROUTING`; Rust doc tx_queue.rs:250-252;
    Python tx_queue_expiry.json note "Priority.ACK == Priority.ROUTING …
    Callers must pass deadline_ms=DEADLINE_ACK_MS explicitly").
  - No found send path passes the 10 s deadline explicitly: Rust
    push_tx_queue maps Routing→5 s (lichend.rs:547-553); Python link_layer
    ACK-priority SCHC-frag controls (link_layer.py:1364-1365) use the
    default deadline; python/src/lichen/link/tx_queue.py:36 goes further and
    defines `DEADLINE_ACK_MS = 5000` ("alias for ROUTING").
- Questions for Opus:
  1. Is the alias-with-explicit-override calling convention conformant (the
     10 s constant + vector documentation satisfy "configurable"), or must
     the queue apply 10 s by default to ACK-priority traffic?
  2. Which Python module is canonical — link/tx_queue.py (live, imported by
     node.py/coap/transport.py, ACK constant = 5000) or timing/tx_queue.py
     (test-consumed only, ACK constant = 10000)? See adjacent observation.

## R-ABF-009 — Priority table (0 routing / 1 link ACKs / 2 urgent / 3 bulk); higher preempts lower

- Spec: Design Principles 3 table (4 levels).
- Classification: divergent (confidence high on facts; the coherence question
  is the point).
- Evidence:
  - Preemption behavior itself implemented+tested everywhere (Rust
    try_preempt tx_queue.rs:578-633 + tests :1255-1331; Python
    timing/tx_queue.py:181 + link tx_queue; C test_priority_preemption
    lichen/tests/tx_queue/main.c:306; vectors tx_queue_priority.json,
    tx_queue_bounded.json preemption_higher_evicts_lower).
  - The implemented model is 5-level P0=SOS, P1=ROUTING(+ACK alias),
    P2=URGENT, P3=NORMAL, P4=BULK (Rust tx_queue.rs:273-284; Python
    link/tx_queue.py:42-70; C tx_queue.h:60-68) — matching main spec
    07-transport §10.2.4 (matrix row R-07-033, implemented+tested), not the
    appendix's 4-level table (no SOS level; routing=P0; ACK=P1 as its own
    row; bulk=P3).
  - Downstream nuance: because app-default priority is BULK at the C L2 and
    Python link boundaries (lora_l2_tx.c:406, link_layer.py:1285), the
    appendix's "application data default 60 s" (R-ABF-008) holds for P3
    Normal, but default-priority sends get BULK's 120 s.
- Question for Opus: is the appendix table a stale pre-07-transport draft
  (→ file a spec erratum aligning it to P0-P4, like the existing
  `worker6-5brg` erratum precedent) or is the appendix a distinct profile
  that implementations must also satisfy? Both cannot be true
  simultaneously for priority numbering.

## R-ABF-010 — Sender gets ENOBUFS/QueueFull; senders must handle it (caveat)

- Spec: Design Principles 4 ("When a queue is full, the sender gets an
  error…"). Row classified implemented+tested; flagged for one caveat only.
- Evidence, conformant: C lora_l2_tx propagates push failure to its caller
  (lora_l2_tx.c:406-413); Python send raises QueueFullError to the caller
  (link_layer.py:1428 + python/tests/link/test_link_tx.py); Rust TxQueue::push
  returns `Err(TxQueueError::QueueFull)` (API tests tx_queue.rs:1112-1133).
- Caveat: the Rust gateway daemon's push helpers swallow the error into a
  warn + drop ("TX queue full, dropping outbound packet", lichend.rs:555-558,
  586-589) — callers of the daemon helpers get no error, only the log.
- Question for Opus: does "sender gets an error" reach the application in the
  Rust gateway path, or is warn+drop acceptable there as the No-Silent-Drops
  logging signal (R-ABF-013)? If the former, fold into a bead with R-ABF-003.

## R-ABF-011 — NACK to mesh source for mesh-forwarded packets

- Spec: Design Principles 4 ("Negative acknowledgment for mesh-forwarded
  packets") + Design Principles 5 ("NACK to mesh source (if routable)") +
  Forwarding Buffer pseudocode comment ("send NACK upstream").
- Classification: not-implemented (confidence high).
- Evidence, no NACK message or transmission exists in any stack (rg -i nack
  across rust/, lichen/subsys, python/src: comments, counters, and hooks
  only):
  - C: `fwd_stats.nacks_sent` counter increment + `-ENOBUFS` return, no frame
    transmitted (lichen/subsys/lichen/routing/router.c:1410-1411); the unit
    test asserts the counter, not a wire message
    (lichen/tests/routing_fwd_buffer/src/main.c:123).
  - Python: on_drop callback documented as "Caller uses this to send NACK
    upstream" (link/forwarding_buffer.py:56,121) with zero callers; the
    vector-designated NACK shape is ICMPv6 Destination Unreachable /
    ADMIN_PROHIBITED via make_resource_exhausted
    (python/src/lichen/ipv6/icmpv6.py:407, tested through
    test/vectors/no_silent_drops.json) — but it is never invoked from a drop
    path (zero callers in python/src).
  - Rust: doc comments only ("a NACK should be sent upstream",
    forward_buffer.rs:30,107; stack.rs:90,695).
- Question for Opus: (a) confirm not-implemented stands (vs. reading
  "-ENOBUFS + counter" as the negative acknowledgment); (b) confirm the
  ICMPv6 DEST_UNREACHABLE/ADMIN_PROHIBITED mapping recorded in
  no_silent_drops.json B.2.5.2 is the intended wire form (it is not defined
  in the appendix text); (c) if the lowercase musts are normative, file the
  pre-authorized bead.
- Pre-authorized disposition: bead (labels `bufferbloat` + `spec-gap`, parent
  = the sweep epic): "NACK-to-source on forwarding-buffer backpressure
  (R-ABF-011)" — suggested placement: emit make_resource_exhausted (Py) /
  ICMPv6 admin-prohibited (Rs lichen-ipv6, C icmpv6.c) toward the source when
  forwarding buffers reject, gated on routability.

## R-ABF-016 — "Bufferbloat avoidance must be tested under congestion": 5 scenarios

- Spec: Testing section, scenarios 1-5 (lowercase "must", line 175).
- Classification: divergent (confidence high).
- Evidence, the scenario set is pinned as an independent oracle:
  test/vectors/bufferbloat_congestion.json (literals copied from the spec
  Testing section) asserted by
  rust/lichen-core/tests/bufferbloat_vectors.rs:105-146
  (b5_congestion_vectors_match_spec_testing_table) and
  python/tests/test_bufferbloat_congestion_vectors.py.
- Evidence, scenario coverage:
  - Scenario 1 queue-full ENOBUFS, 2 deadline expiry, 3 priority preemption:
    real tests in all three stacks (R-ABF-001/005/009 sites).
  - Scenario 4 multihop_latency ("end-to-end delay bounded under load"): the
    vector carries only the expectation string `bounded_e2e_delay`; no
    multi-hop latency-under-load test exists in any stack (rg
    multihop_latency|bounded_e2e → the two oracle-assertion files only).
  - Scenario 5 fairness: per-source-limit unit tests exist (R-ABF-003 sites)
    but no under-load system test; and the mechanism itself is unwired from
    the relay path, so a fair-load test could not pass today.
- Question for Opus: confirm scenarios 4-5 are gaps (→ pre-authorized bead
  below if the lowercase must is normative) or whether existing e2e suites
  (rust/lichen-gateway/tests/end_to_end.rs, python multi-node tests) already
  bound end-to-end delay sufficiently.
- Pre-authorized disposition: bead (labels `bufferbloat` + `spec-gap`, parent
  = the sweep epic): "Congestion test scenarios 4-5 (R-ABF-016)" — suggested
  placement: extend bufferbloat_congestion.json consumers with a multi-hop
  latency-under-load sim test (Rust mesh_formation/e2e or Python multi-node)
  and a fairness-under-load test over the wired forwarding buffer.

## Adjacent observations (not requirements; no beads filed)

1. Duplicate Python implementations with divergent constants: two TX queues
   (link/tx_queue.py — live, imported by node.py/coap/*/link_layer;
   timing/tx_queue.py — consumed only by tests/timing/*) and two forwarding
   buffers (link/forwarding_buffer.py with on_drop/stats;
   routing/router.py:144 ForwardingBuffer embedded in Router). DEADLINE_ACK_MS
   is 5000 in the live module and 10000 in the test-consumed one (see
   R-ABF-007 question 2). Candidate for the regular review loop (consolidation),
   not a spec-gap bead.
2. C TX queue operates synchronously: push then immediate pop-and-send
   (lora_l2_tx.c:398-420, comment "A future async TX thread could drain the
   queue asynchronously for better bufferbloat handling under contention") —
   deadline/preemption machinery is exercised only by concurrent pushes, which
   the current datapath does not generate. All C app data is TX_PRIORITY_BULK
   (matrix row R-07-034). Candidate for the review loop / future async-TX bead;
   the appendix's queue numbers are still enforced at the API level.
3. The C /status/queues encoder (status_cbor.c) has no direct C test; the
   Rust client decode test (queue_stats_decode_firmware_map,
   rust/lichen-client/src/status.rs:404) mirrors the firmware key names as its
   oracle rather than consuming C output. Minor test-coverage gap; noted in
   matrix row R-ABF-015.
