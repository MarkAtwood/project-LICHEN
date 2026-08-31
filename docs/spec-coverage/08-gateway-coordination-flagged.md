# Flagged set — spec/08-gateway-coordination.md (sweep 2026-08-31)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or OSCORE-semantics sensitive. Each entry: requirement,
classification, evidence, and the specific question to answer.

## R-08-001 — MUST support both federation modes (GCP-1, GCP-10)

- Classification: divergent (confidence low). Gap bead `project-LICHEN-worker6-l1qw.15`.
- Evidence: C `LICHEN_GW_FEDERATION_CLOSED|OPEN|DUAL` + `LICHEN_GW_PSK` Kconfigs
  (lichen/apps/gateway/Kconfig:237-263) referenced by no C code; C open-mode
  primitives untested (gcp/gcp_trust.c:114-163, own domain-prefix transcript).
  Rust: both engines implemented+tested (trust.rs:1288-1381,
  tests/gcp_psk_oscore_vectors.rs) but `lichend.rs:512` refuses config
  mode=open; dual-mode simultaneous (GCP-3.2) unimplemented everywhere.
- Question: Does library-level support with daemon-level refusal satisfy
  "MUST support both federation modes", or is the Rust open-mode config
  refusal itself the divergence to fix? Is dual-mode simultaneous
  participation required by the MUSTs, or only by the keyword-less GCP-3.2
  sentence?

## R-08-003 — Open Federation (signatures) MUST be supported (GCP-3.2)

- Classification: implemented+tested (confidence low).
- Evidence: Rust TrustStore TOFU + Schnorr48 verify tested against
  `gcp3_trust_models.json` (trust.rs:605-630, 919-960, tests :1829-2000);
  reachable only via runtime API (`Gateway::admit_gateway`), not config. C
  gcp_trust.c untested. Python trust oracle tested (rotation subset only).
- Question: Is "supported" satisfied by tested library code that no daemon
  path activates via configuration? Confirm the Rust runtime API path
  (admit_gateway → install_gcp_context) is a complete open-mode federation
  join.

## R-08-004 — Backbone discovery multicast GET + Observe (GCP-4.1, no kw)

- Classification: divergent (confidence high).
- Evidence: Rust encoders + /info payload tested (discovery.rs:37-159,
  resources.rs:546-721, unit tests :366-431) but nothing ever sends the
  multicast GET or publishes Observe announcements; C has nothing; Python
  codec only; `gateway_discovery.json` orphaned.
- Question: Confirm no stack is expected to be the integration point, and
  whether the orphaned `gateway_discovery.json` vectors should drive a
  wire-level interop test before the behavior is wired.

## R-08-005 — GATEWAY flag in link-layer announce frames (GCP-4.2, no kw)

- Classification: divergent (confidence high).
- Evidence: C implements `LICHEN_GATEWAY_FLAG 0x80` on the routing-announce
  type byte (routing/announce.h:41, announce.c:568-626) — the link LLSec
  flag byte has no GATEWAY bit (link frame.c:13-19). Rust/Python implement a
  standalone `LoraGatewayAnnounce` format (discovery.rs:167-310,
  discovery.py:321-414) that no real frame path uses.
- Question: Does "include GATEWAY flag in link layer" mean the LLSec frame
  flag byte, the routing announce type byte (C's choice), or a dedicated
  gateway-announce frame (Rs/Py choice)? The three stacks disagree; interop
  on LoRa fallback discovery is impossible until this is pinned.

## R-08-007 — Superframe sync via backbone CoAP (GCP-6.1, no kw)

- Classification: divergent (confidence high).
- Evidence: GPS-epoch math and lowest-IID time-master election implemented
  and tested in all stacks (Py test_gcp6_vectors.py:56-77; C
  coap_slot_coord.c:196-202; Rs multi_instance.rs:405). "Others sync via
  backbone CoAP" has no implementation anywhere; `GatewayInfo.superframe_epoch`
  is advertised but never consumed for sync.
- Question: Confirm backbone time-sync is a real gap vs. covered elsewhere
  (spec 02a CCP time sync?) before filing work.

## R-08-012 — Verify signature; invalid/missing MUST be silently discarded (GCP-6.3/6.5)

- Classification: divergent (confidence low). Gap bead `project-LICHEN-worker6-l1qw.16`.
- Evidence: C conforms (return 0, no response, rate-limited WARN,
  coap_slot_coord.c:1488-1508). Rust `handle_post_slots` returns 4.01
  Unauthorized on bad signature (resources.rs:1938-1964); the runtime
  dispatch path (gateway.rs:1343-1380) does consume unauthenticable packets
  silently at the OSCORE layer. Python has no endpoint at all.
- Question: Does the Rust OSCORE-layer silent consumption satisfy "silently
  discarded" for OSCORE-authenticated peers, given spec validation order
  (step 1 OSCORE, then COSE signature)? Should `handle_post_slots`'s 4.01 be
  converted to silence, or is 4.01 acceptable for unauthenticated *senders*
  with silence required only for authenticated peers with bad COSE?

## R-08-015 — All coordination CoAP messages use OSCORE (GCP-6.4, no kw; OSCORE semantics)

- Classification: divergent (confidence high). Flagged under OSCORE-semantics criterion.
- Evidence: C GET handlers (`/info`, `/channels`) answer plaintext even for
  OSCORE-protected peers (existing bead `project-LICHEN-worker6-pttk`);
  POST path correctly gated (coap_slot_coord.c:1459-1474). Rust enforces at
  dispatch (gateway.rs:1337-1425). Python gates only /handoff.
- Question: Confirm the fix shape for C GETs (reject plaintext with 4.01 vs.
  OSCORE-protect the responses) — this touches the shared
  `coap_oscore_unprotect_resource_request()` response path.

## R-08-019 — Validation/response codes 4.03 / 2.04 / 4.09 + 305 s bound (GCP-6.5)

- Classification: divergent (confidence high). Gap bead `project-LICHEN-worker6-l1qw.19`.
- Evidence: C lacks the spec's +5 s clock tolerance (cap exactly 300 s,
  :438-442; test asserts inclusive 300). Rust: conflict = 2.05+CBOR instead
  of 4.09-with-winning-claim (resources.rs:2008-2029); no 4.03 mapping; no
  expiry validation at all. Vectors `gcp6_slot_coordination.json` /
  `gateway_coordination.json` pin stale 2.01/4.29.
- Question: Is the C behavior (strict 300 s, inclusive) a spec erratum
  candidate (drop the +5 s tolerance), or should C add the tolerance? Which
  response-code set is canonical for the Rust rewrite — and do the stale
  vectors get regenerated or dual-pinned?

## R-08-030 — Handoff flow step 4: B confirms handoff to node via CoAP (GCP-7, no kw)

- Classification: divergent (confidence high).
- Evidence: Steps 1-3 and 5 implemented+tested in Rust (handoff.rs:949-1092,
  end_to_end.rs:1075,1121) and Python (test_handoff.py:325-378); C flow
  untested (coap_handoff.c:996-1063). No stack sends the node-facing
  confirmation (step 4).
- Question: Is step 4 delivered via the existing LCI/CoAP node surface, and
  does its absence break node-side mobility, or is it covered by RPL
  parent-change signaling in practice?

## R-08-031 / R-08-032 — Handoff request/confirm validation pipelines (GCP-7.1, no kw)

- Classification: divergent (confidence high). Existing bead `project-LICHEN-worker6-3o0p.5`.
- Evidence: Rust implements a different (CBOR, non-COSE) handoff protocol
  with its own vector (`node_handoff.json`, 17 tests). C implements
  OSCORE-only handoff with a subset of validations (4.00 not 4.03,
  coap_handoff.c:878-933, 1056-1058). Python has the spec-conformant COSE
  envelope classes (handoff.py:760-1229) with zero tests and no consumer of
  `gcp_handoff_cose_sign1.json`.
- Question: Which handoff protocol is canonical going forward — the spec's
  COSE_Sign1 pair (GCP-7.1) or the Rust `node_handoff.json` protocol? Three
  stacks, three answers today; cross-impl parity is the project's core rule.

## R-08-035 — Backwards compatibility / legacy-peer detection (GCP-8, no kw)

- Classification: divergent (confidence high).
- Evidence: Single-gateway no-coordination is satisfied by construction (C
  Kconfig default n; Rust Disabled default, context-gated dispatch). "New
  gateways detect absence and run independently" has no detection code
  anywhere.
- Question: Confirm whether absence-detection is a real requirement to
  implement (heartbeat/probe on the backbone) or satisfied by the context-
  gated dispatch design (no peer contexts ⇒ coordination traffic never
  originates).

## R-08-036 — Protocol OPTIONAL but RECOMMENDED for 2+ gateways (GCP-1)

- Classification: ambiguous (deployment-level applicability statement).
- Evidence: No implementation mapping is possible or expected; recorded for
  completeness because it carries RFC 2119 keywords.
- Question: Confirm that deployment-level OPTIONAL/RECOMMENDED statements
  are out of scope for implementation coverage rows (or define the mapping
  you want future sweeps to use).
