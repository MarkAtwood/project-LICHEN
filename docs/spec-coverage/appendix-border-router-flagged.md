# Flagged set — spec/appendix-border-router.md (sweep 2026-08-31)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or section 06-security / oscore-EDHOC-semantics sensitivity.
Each entry: requirement, classification, evidence, and the specific question
to answer. This appendix has two normative statements (both in the intro
paragraph, lines 6–11); both are flagged. No rows here touch oscore/EDHOC
internals, so nothing carries the `human-only` label. Companion rows:
"spec/appendix-border-router.md — coverage (sweep 2026-08-31)" in
docs/spec-coverage.md (`R-ABR-001`, `R-ABR-002`).

## R-ABR-001 — Gateway-owned Yggdrasil daemon MUST NOT spoof node source addresses

- Spec: spec/appendix-border-router.md intro (lines 6–11), second clause.
- Classification: ambiguous (confidence low).
- Evidence, compliant half — LICHEN-owned code never rewrites source
  addresses:
  - Rust mesh→upstream writes the decompressed original IPv6 packet to the
    TUN verbatim (rust/lichen-gateway/src/bin/lichend.rs:939,947-951);
    no NAT/rewrite symbols in any stack (rg clean — cross-ref R-08N-003 and
    R-04-010 rows in docs/spec-coverage.md); src/dst byte-exact through the
    SCHC round-trip asserted in rust/lichen-gateway/tests/end_to_end.rs:283-323
    (asserts :318-323).
  - C: the Zephyr forwarding hook does stats + MTU drop only, no address
    mutation (lichen/apps/gateway/src/forwarding.c:67-91).
- Evidence, undetermined half — the regulated artifact does not exist in any
  stack:
  - The "gateway-owned Yggdrasil daemon" is operator-external per the code's
    own comment (rust/lichen-gateway/src/config.rs:150 "gateway: external
    Yggdrasil daemon on Linux; embedded: lite/proxy").
  - `[yggdrasil]` config (config.rs:197-212) is parsed and logged
    (lichend.rs:381-382) but never acted on — no spawn, no generated daemon
    config, no routed-subnet/source-policy wiring (rg "Command|spawn" in
    lichend.rs: sim task only).
  - Whether the composed deployment (lichend forwarding node-sourced packets
    into `lichen0` + operator-run yggdrasil-go + Linux routing) results in
    the daemon carrying node `/128` sources into Yggdrasil — which under the
    strict reading of the intro's first clause (R-ABR-002) is exactly the
    prohibited spoofing — is undetermined from repo evidence. Stock
    yggdrasil-go source filtering behavior is external knowledge and was not
    verified during this sweep.
- Questions for Opus:
  1. Which reading of "identity-preserving transport for the owning node" is
     normative: (a) source address preserved verbatim end-to-end (weaker), or
     (b) the owning node's own key/identity is the Yggdrasil participant
     (delegated location agent / split node / node-owned daemon — stronger,
     the reading the open research bead `project-LICHEN-zt3c.2.1` is built
     around)?
  2. Under the chosen reading, classify the shipped lichend forwarding path:
     divergent (→ file the gap bead below) or conformant-by-construction
     (→ reclassify R-ABR-001 implemented+untested, noting there is no
     adversarial/spoof negative test)?
  3. Verify against upstream yggdrasil-go source (not from memory): does a
     stock daemon drop TUN packets whose source is a third-party 0200::/8
     address? If yes, off-mesh Yggdrasil reachability for node `/128`s
     silently does not function today; if no, the spoofing concern is live.
- Pre-authorized disposition: if Opus rules divergent, file a gap bead
  (labels `gateway` + `spec-gap`, parent = the sweep epic) with suggested
  placement rust/lichen-gateway — either implement/configure an
  owning-node-preserving Yggdrasil arrangement, or gate/refuse 0200::/8-sourced
  upstream forwards and fail the Grounded advertisement closed (the
  set_ygg_reachable gating at lichend.rs:439-442 then advertises less than
  the path delivers).

## R-ABR-002 — Native node `/128`s may enter Yggdrasil only through an identity-preserving transport for the owning node

- Spec: same sentence, first clause. MAY with an "only through" constraint.
- Classification: not-implemented (conformant — MAY; never beaded per sweep
  protocol). Flagged only because its interpretation decides R-ABR-001.
- Evidence: no owning-node Yggdrasil participation exists in any stack; the
  mechanism is open research bead `project-LICHEN-zt3c.2.1`. Adjacent
  plumbing that names the concept without providing the transport:
  set_ygg_reachable Grounded gating (lichend.rs:439-442) + vector
  test/vectors/gateway_reachability.json (consumed by
  rust/lichen-gateway/tests/end_to_end.rs and
  python/tests/rpl/test_gateway_reachability_vectors.py);
  IDENTITY_PRESERVING_GLOBAL classification vocabulary
  (python/src/lichen/rpl/address_classification.py:22 + vectors
  address_classification.json); C comment "identity-preserving BR path"
  (lichen/subsys/lichen/routing/router.c:655).
- Question for Opus: confirm the reading (same question 1 as R-ABR-001). If
  the weaker verbatim-preservation reading is correct, reclassify R-ABR-002
  implemented+untested (the verbatim-forwarding path + reachability vectors
  are the evidence) and downgrade the R-ABR-001 concern accordingly.

## Adjacent observation (not a requirement; no bead filed)

deploy/lichend.toml.example:32-43 documents `[yggdrasil]` auto_peer (public
network / LICHEN registry / mDNS), manual peers, and a daemon binary path,
but lichend only parses and logs these fields (config.rs:197-212,
lichend.rs:381-382) — config-schema only, no auto-peering or daemon
management behavior. The appendix's normative text does not cover
auto-peering, so this is not a gap bead for this section; hand to the regular
review loop.
