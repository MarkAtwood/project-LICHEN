<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Flagged set — spec/appendix-loadng.md (sweep 2026-09-09)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or 06-security/OSCORE-semantics sensitive. No row in this
section touches oscore/EDHOC internals (human-only bar) — LOADng is an
ICMPv6-layer routing protocol.

## R-LOADNG-001 — Evidence gate: MUST NOT probe an arbitrary 0200::/8 destination (intro)

- Classification: divergent (confidence low).
- Evidence: The gate is implemented and vector-tested only in Python
  (`EvidenceTable` python/src/lichen/rpl/evidence.py:14-159,
  `AddressClassificationTable` python/src/lichen/rpl/address_classification.py:43-97,
  vectors test/vectors/local_evidence.json + address_classification.json) but no
  production routing path consults it: python
  python/src/lichen/routing/router.py:557-567 initiates discovery on any gradient
  miss, C lichen/subsys/lichen/routing/router.c:158-160 likewise, rust
  rust/lichen-node/src/hybrid.rs:276 likewise. Python additionally queues LOADng
  for EXTERNAL (non-0200::/8) destinations when the DODAG is stale
  (router.py:574-597), contradicting "mesh-internal peer-to-peer traffic only".
  There is also an intra-spec conflict: spec/05-routing.md §10.2 pseudocode
  initiates LOADng for any 02xx destination with no gradient, with no evidence
  gate, while appendix-loadng intro and README.md:129-137 mandate the gate.
- Question for Opus: Which text governs — appendix-loadng intro (gate required)
  or 05-routing §10.2 (probe on any gradient miss)? If the gate is required, the
  Python `AddressClassificationTable.LOCAL_MESH` classification is the natural
  admission check to wire into all three routers; if not, the appendix intro
  (and README) should be amended. Also decide whether the Python external-
  destination LOADng fallback (router.py `_route_external`) is conformant.

## R-LOADNG-018 — Expanding ring 4→8→15 and per-attempt wait (B2.5)

- Classification: implemented+tested (rust), implemented+untested (C),
  not-implemented (py), with a cross-stack interop divergence (confidence low).
- Evidence: Ring constants and `advance_ring` typestate are tested in rust
  (rust/lichen-core/src/loadng.rs:55,349-359, tests :823-844). C implements the
  state machine (loadng.c:589-607) with only constants tested. Python has no
  ring progression at all (originate_rreq is one-shot; bead b7z9.195), and its
  receiver handler-rejects any RREQ with hop_limit > INITIAL_HOP_LIMIT=4
  (python/src/lichen/loadng/discovery.py:149-156, deliberate per bead
  project-LICHEN-worker6-0tk2 because the reverse-route cost derivation
  `INITIAL_HOP_LIMIT - hop_limit` is meaningless for rings 5..15), so ring-2
  (8) and ring-3 (15) floods die at the first receiver. C forwards them with a
  different cost math (`MAX_HOP_LIMIT - hop_limit`, loadng.c:661). Rust has no
  RREQ receive path. Wire vectors accept hop values up to 15
  (test/vectors/loadng_messages.json).
- Question for Opus: What is the intended interop semantics — should ring-2/3
  RREQs propagate (requiring traversed-hop data in the wire format, a spec
  change), or is expanding ring intentionally capped at the 4-hop base flood
  with rings 8/15 vestigial? The appendix and 05-routing §10.7 still present
  rings 8/15 as functional. C's `MAX_HOP_LIMIT - hop_limit` cost vs python's
  `INITIAL_HOP_LIMIT - hop_limit` also cannot both be right.

## R-LOADNG-002/003 — RREQ_WAIT_TIME 5000 ms and RREQ_RETRIES 3 cross-stack wiring (B2.1)

- Classification: ambiguous (confidence medium).
- Evidence: C defines and uses RREQ_WAIT_TIME (loadng.h:80, loadng.c:564,605)
  but RREQ_RETRIES (loadng.h:83) is defined-never-used — the 3-ring expanding
  count stands in for "maximum attempts". Python conflates RREQ_WAIT_TIME with
  `pending_timeout_ms=5000` (python/src/lichen/node.py:242), a pending-queue
  expiry, not a retry wait. Rust has neither constant (timing is caller-driven,
  hybrid.rs:413). Beads b7z9.195/.196/.197 track the missing drivers.
- Question for Opus: Is "RREQ_RETRIES = 3" satisfied by the 3 expanding-ring
  attempts (ring count == retries), or does it mean full re-discovery retries
  after ring exhaustion (AODV sense)? If the latter, it is unimplemented in
  every stack and the C constant is dead.

## R-LOADNG-009 — ROUTE_REFRESH 60 s refresh-on-use (B2.2)

- Classification: divergent (confidence high on absence; ambiguity is in spec intent).
- Evidence: Constants exist (lichen/subsys/lichen/routing/include/lichen/routing/loadng.h:74;
  python/src/lichen/loadng/cache.py:22) and refresh mechanisms are unit-tested
  (loadng.c:340-360; cache.py:119-130, test_refresh_extends_validity
  python/tests/loadng/test_cache.py:51), but nothing calls refresh on route use
  in any stack — so a continuously used LOADng route expires after 300 s.
- Question for Opus: Does the B2.2 table intend refresh-on-use as binding
  behavior (then wire `cache_refresh` into each forwarding path) or as
  informational? Filed as b7z9.200.

## R-LOADNG-017 — RACK code 3 allocation (B2.4)

- Classification: implemented+tested for codes 0-2; code 3 reserved with no
  handler anywhere, and the rust codec rejects it outright (confidence high for
  behavior, low for allocation consistency).
- Evidence: rust `LoadngCode::from_u8(3)` → None → `UnknownCode` error
  (rust/lichen-core/src/loadng.rs:76-84); py reserves `LoadngCode.RACK = 3` in
  the enum but has no `_CLASS_BY_CODE` entry → "unsupported LOADng code: 3"
  (python/src/lichen/loadng/messages.py:63-69,207-211); C defines
  `LICHEN_LOADNG_CODE_RACK 3U /* Reserved */` (loadng.h:53) with no codec. The
  spec table allocates code 3 = RACK (Route Acknowledgment) but no other spec
  section uses RACK.
- Question for Opus: Should RACK stay an allocated-but-reserved code (then rust
  should at minimum reserve code 3 instead of parsing it as unknown, and the
  appendix should say "reserved"), or is RACK a planned message needing a wire
  format? A code-3 datagram today yields three different error surfaces.

## R-LOADNG-019 — RREQ suppression window (B2.6)

- Classification: implemented+tested (py), implemented+untested (C),
  not-implemented (rust) (confidence medium).
- Evidence: py fully tested (discovery.py:60,369-425; test_discovery.py:53,62
  plus RFC 1982 wrap tests). C implements the seen table (loadng.c:402-536) but
  lichen/tests/loadng/main.c has no test for `lichen_loadng_seen_check_and_mark`
  or the 10 s window — only the rate limiter is tested. Rust has no RREQ receive
  path at all (bead b7z9.197). All implementations identify RREQs by the
  (originator, destination, seq) tuple rather than the spec's
  `RREQ_ID = hash(...)`, which is functionally equivalent for suppression but is
  a text-vs-code mismatch.
- Question for Opus: Confirm the tuple-key reading is intended (hash as
  implementation detail), and whether the C seen-table tests should be added
  before the C integration bead (b7z9.196) lands.

## R-LOADNG-011/012/013/014 — B2.2 evidence MUSTs satisfied in one stack only

- Classification: implemented+tested (py); not-implemented (rust, c)
  (confidence high for py, low for protocol-wide conformance).
- Evidence: python/src/lichen/rpl/evidence.py implements every clause (1200 s
  fixed lifetime :14, authenticated-source set :18, refresh :86-137, expiry at
  equality :145, monotonic regression rejection :64-74, overflow guard
  :103-104, bounded peers with no silent eviction :118-122), pinned by
  test/vectors/local_evidence.json via python/tests/rpl/test_local_evidence_vectors.py:84-94.
  Neither rust/lichen-node nor lichen/subsys/lichen/routing has any evidence
  tracking. Bead b7z9.193.
- Question for Opus: The MUST clauses are currently satisfied only by a module
  that no router consults. Confirm the intended porting target for C/Rust
  (replicate `EvidenceTable` semantics + vectors) and that the vectors are the
  conformance oracle for those ports.

## R-LOADNG-004/020 — RREQ_RATELIMIT 10/min originated + B2.7 broadcast-limit interaction

- Classification: not-implemented (confidence high on absence).
- Evidence: The only RREQ rate limiter is C's receive-side admission control
  (10/min per source + 30/min global, from 05-routing §10.3 — a different
  requirement): loadng.c:41-56,453-492, tested main.c:575-630. No stack limits
  originated RREQs to 10/min, and §6.3.3 broadcast budgeting is never applied
  to RREQ floods because no stack drives RREQ origination (beads
  b7z9.195/.196/.197). Filed as b7z9.199.
- Question for Opus: Whether the B2.1 originate-side limit and the B2.7
  §6.3.3 interaction should be enforced in the (currently missing) discovery
  drivers, and whether B2.1's "10/min" is the same 10/min as 05-routing §10.3's
  per-source receive limit or a distinct per-node originate counter that should
  be disambiguated in the appendix.