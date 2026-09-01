# Flagged set — spec/04-network.md (sweep 2026-08-31)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or section 06-security/OSCORE-semantics sensitive. Each entry:
requirement, classification, evidence, and the specific question to answer.
No rows in this section touch oscore/EDHOC internals (human-only bar).

## R-04-002 — Multiple border routers MUST be tolerated (§6.1)

- Classification: implemented+tested (confidence low).
- Evidence: Rust multi_instance.rs:964-1017 (select_root, multi-DODAG
  candidates, signature filter fail-closed) + vectors; per-BR DAO-learned
  local routes gateway.rs:1582-1588; ygg_reachable gating lichend.rs:439-442.
  Anycast/failover is delegated to the external yggdrasil daemon
  (config.rs:197-203) — no failover logic in any LICHEN stack. Same wiring
  caveat as R-08-006: multi_instance machinery is not wired into a running
  gateway.
- Question: Does "tolerated" require only that multiple BRs can coexist
  without coordination (per-BR DAO routes + tested multi_instance library),
  or an in-product multi-BR failover path? Is delegation to the yggdrasil
  daemon acceptable evidence for the MUST? Is there any multi-BR e2e test,
  or only single-BR cross-mesh (yggdrasil_cross_mesh_routing)?

## R-04-007 — BR MUST NOT forward mesh multicasts to internet; drop both directions (§6.3.4)

- Classification: divergent (confidence high). Gap bead
  `project-LICHEN-worker6-b7z9.39` (P1).
- Evidence: C router.c:576-589 drops backbone-ingress multicast unless
  packet->multicast_peering (router.h:146), test routing_dispatch/main.c:277-284.
  Python router.py:493-499 drops in both directions, TestBRMulticastFilter
  (test_router.py:469-597, 8 tests). Rust gateway has no multicast check:
  upstream_to_mesh (gateway.rs:1539-1558) checks only ULA 0xfd then
  is_local_mesh — multicast dst falls through to transmit_ipv6_wire :1556
  (internet→mesh forwarded); forward_mesh_to_upstream (lichend.rs:914-951)
  TUN-writes non-local dst including multicast (mesh→internet forwarded);
  RPL stack accepts multicast dst as deliverable (stack.rs:587-595, 795-806).
- Questions: (1) Trace transmit_ipv6_wire → SCHC/link for a multicast
  destination: can ff00::/8 dst actually be encoded onto a LoRa frame, or
  does compression/tx fail downstream (which would make the internet→mesh
  leak theoretical rather than actual)? (2) Confirm the C drop path: in
  router.c the `crosses_boundary` branch returns `next` — verify
  next.route.decision is default-initialized to DROP at that point (the
  routing_dispatch test asserts it, but confirm the initializer).

## R-04-009 — Root election lowest-EUI-64; >50% vote demotion w/ Schnorr DEMOTION_REQUEST; root no ULA advertisement (§6.1, no kw)

- Classification: divergent (confidence high).
- Evidence: Implemented root selection is multi-criteria with lowest-EUI-64
  as final tiebreak (multi_instance.rs:964-981 Ord; select_root :993-1017)
  per spec 2a.5.2 — 04:32 says "lowest EUI-64 deterministic election".
  DEMOTION_REQUEST message and >50% vote counting absent in all stacks
  (rg demotion|DEMOTION|demote: only local demote() primitives dodag.rs:373-380,
  dodag.py:331-342; nothing in C; planned in docs/spec-chapter-breakdowns.md:379-385).
  Root ULA advertisement: correctly absent (conformant); residual ULA
  classification/accept code remains (Rs hybrid.rs:231-234, node.rs:196,526,
  609-616,750-757; Py headers.py:259-264).
- Questions: (1) Which spec governs election mechanics for coverage — 04:32's
  bare lowest-EUI-64 or 2a.5.2's multi-criteria-with-tiebreak (05-routing sweep
  should own the reconciliation)? (2) Should the DEMOTION_REQUEST gap be filed
  under 05-routing rather than 04 (04 references "unchanged mechanics as
  documented above")? (3) Are the residual ULA-accepting paths in
  rust/lichen-node (Echo + DAO forwarding for fd00::/8) dead legacy or live
  divergence from the single-primary model?

## R-04-010 — Off-mesh 02xx forwards to BR Yggdrasil TUN; local stays on LoRa (§6.1, no kw)

- Classification: implemented+tested (confidence low).
- Evidence: Rust gateway only: forward_mesh_to_upstream (lichend.rs:914-956),
  is_local_mesh DAO-gated (gateway.rs:1582-1588), tests
  yggdrasil_cross_mesh_routing :2371-2393 + dao_route_makes_ygg_address_local
  :2403-2435; node default route toward BR (hybrid.rs:268-306). C: no
  TUN/off-mesh forwarding code found in lichen/subsys. Python: simulator-only
  routing (no OS TUN, by design).
- Question: Is the C/Zephyr gateway expected ever to forward off-mesh traffic
  (i.e., is C absence a real gap), or is the Rust gateway the sole BR
  implementation making C absence non-divergent? Confirm Py sim intentionally
  excludes BR forwarding.

## R-04-011 — Multicast scopes + standard groups ff02::1/1a/2, ff03::1, ff03::fc (§6.3.1, no kw)

- Classification: divergent (confidence high).
- Evidence: ff02::1 and ff02::1a defined and used in all stacks. ff02::2:
  defined-unused in Rust (lichen-ipv6 lib.rs:195), absent in C, example-only
  in Python. ff03::1: tests-only in Python, no production use in Rust or C.
  ff03::fc ("All LICHEN nodes"): defined-unused everywhere (multicast.rs:15-17,
  addr.py:27) with constant tests only.
- Question: Do any documented features require ff02::2 / ff03::1 / ff03::fc
  (e.g., app-layer mesh broadcast in spec 18)? If yes → implementation gap to
  file under the owning section; if no → spec-table trim. Note ff03::1 being
  tests-only in Python suggests a feature that was planned but never wired.

## R-04-013 / R-04-014 / R-04-015 — Broadcast relay rate limiting: budgets 200/100/30/10 (SOS 3), yellow-zone 50% probabilistic drop, 2h idle expiry + ~2KB bound (§6.3.3, no kw)

- Classification: divergent (confidence high), grouped — one mechanism.
- Evidence: The spec's exact mechanism exists ONLY in Python
  (link/broadcast_limit.py:24-145): budgets match the spec table, yellow
  zone classify_broadcast :50-71 with 50% resolution :117-118, 2h idle
  expiry :30,105-107; conformance vectors test/vectors/broadcast_rate_limiting.json
  + tests link/test_broadcast_limit_vectors.py (9 tests). BUT the limiter is
  unwired: zero callers in python/src (rg BroadcastRateLimiter|admit outside
  the module: empty). C and Rust: mechanism entirely absent. SOS relay budget
  of 3 absent from the limiter in every stack (only the spec-18.3 SOS
  originator limit exists: emergency.py:30-33). The ~2KB state bound is not
  referenced anywhere.
- Questions: (1) Is an unwired-but-conformance-tested module "implemented"
  for coverage, or should the row read not-implemented? (2) Where is the
  intended integration point — node relay path at hop-limit decrement, or L2
  broadcast? (3) Does the SOS=3 relay budget belong in broadcast_budget()
  (SOS as a parameter) or at the relay-policy layer? (4) Are C/Rust ports
  planned, or is Python the reference implementation for this feature?

## R-04-017 — ICMPv6 Destination Unreachable / Packet Too Big (§6.4, no kw)

- Classification: implemented+tested (confidence low).
- Evidence: Builders + parsers exist and are vector-tested in all three
  stacks (C icmpv6.c:577-639 + tests main.c:441,468,510,673; Rs lichen-ipv6
  lib.rs:608-763 + unit tests :1485-1536; Py icmpv6.py:387-413 +
  test_icmpv6.py:194-211 + relay vectors). However NO stack emits these
  errors from its forwarding datapath — constructors have zero production
  callers.
- Question: Does "Standard ICMPv6 (RFC 4443) for: Destination Unreachable,
  Packet Too Big" require datapath emission (e.g., Dest Unreachable on
  no-route drops), or do tested builders satisfy the section? Note PTB may be
  structurally N/A: SCHC fragmentation presents 1280-byte MTU to ULPs, so
  "packet too big" never arises above the adaptation layer — confirm or refute.

## R-04-020 — Short-address assignment: derived / self-assigned random + DAD / root pool; collision → regenerate+retry (§12.3, no kw)

- Classification: divergent (confidence high).
- Evidence: Method 1 (crc32_ieee derived) + seed-mixing retry: implemented and
  vector-tested in all stacks (R-04-019). Method 2 (pick random + verify via
  DAD): no implementing function in any stack (Py docstring mention only,
  short_addr.py:672-695). Method 3 (root pool, optional): Rust std Coordinator
  (address_assignment.rs:837-1212 + short_addr_assignment.json) and Python
  CoordinatorAddressTable (short_addr.py:428-519) implemented+tested; C has
  client-side only (rpl_short_assignment.c), no root-side allocator. DAD
  probe/conflict exchange: Python DadProbeSequence tested
  (test_short_addr_dad.py); C dad.c state machine is self-contained with no
  production callers (unwired); Rust has RFC4861 semantics + coordinator
  fallback (lichen-ipv6 lib.rs:1136-1152, address_assignment.rs:1068-1090).
- Questions: (1) Is method 2 required by any documented feature, or spec trim?
  (2) Is C dad.c being unwired a gap to file (C has no root allocator either —
  is C short-address assignment expected to work end-to-end?) or pending
  integration already tracked elsewhere? (3) Given collision handling exists
  via seed-mixing retry in all stacks, is "regenerate and retry" already
  satisfied by method 1 alone, making method 2 redundant?
