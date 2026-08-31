# Flagged set — spec/08-nodes.md (sweep 2026-08-31)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or section 06-security/OSCORE-semantics sensitive. Each entry:
requirement, classification, evidence, and the specific question to answer.
No rows in this section touch oscore/EDHOC internals (human-only bar), and the
section contains no RFC 2119 keywords (all rows are definitional, IDs
`R-08N-NNN` to avoid collision with the spec/08-gateway-coordination sweep's
`R-08-NNN`). Internal spec headings are §11.x.

Per matrix preamble no gap beads were filed for this section (0 MUST rows);
these divergences are the candidate gap set if Opus judges any of them
MUST-strength in substance.

## R-08N-001 — Leaf role: Host IPv6, RPL Leaf, does not forward (§11.1)

- Classification: divergent (confidence high).
- Evidence: Rust `RplRole::Leaf` is a DAO-transmission gate only
  (`NotLeaf` error transmit.rs:117-120, role constructors
  provisioning.rs:24-101); a Leaf-provisioned node still forwards transit
  IPv6 (receive.rs:259-291, no role check), relays child DAOs
  (node.rs:584-630), and propagates DIOs (router.rs:840-864). C has only a
  CoAP `/config` role string (`LICHEN_CONFIG_ROLE_LEAF` coap_config.h:41-43)
  with zero RPL consumers (rg verified). Python has no leaf concept at all
  (DodagRole UNJOINED/JOINED/ROOT dodag.py:125-130).
- Questions: (1) Is the definitional table row §11.1 MUST-strength in
  substance (i.e. does a conformant Leaf need enforced non-forwarding), or
  is it descriptive of a deployment choice? (2) If MUST-strength: is the
  Rust gate-scope bug (Leaf forwards/relays/sends DIOs) one bead or should
  C/Py role-absence be tracked separately? (3) Should C's unwired
  `LICHEN_CONFIG_ROLE_LEAF` be wired to an actual RPL leaf mode or removed?

## R-08N-004 — Gateway role: Host, RPL None, L7 protocol translator MQTT-SN→MQTT (§11.1)

- Classification: not-implemented (confidence high).
- Evidence: No MQTT broker bridge/translator exists in any stack. Present
  machinery is transport-only: Rust MQTT-SN port dispatch (port_dispatch.rs:30-44,
  port 10883 constants.rs:38) + SCHC Rule 7 codec (codec.rs:1041-1133);
  Python full MQTT-SN 1.2 wire codec (mqttsn/messages.py, codec.py) with no
  broker connection; C SCHC rule tests only (lichen/tests/schc_mqtt_sn). No
  hits for any MQTT client library or port 1883; the only gateway binaries
  (`lichend`, C gateway app) are RPL DODAG roots.
- Questions: (1) This breaks the documented Gateway role itself — should a
  bead be filed here, or does the normative MQTT-SN-gateway text live in
  spec 07/18 such that those sweeps own it? (2) If filed, suggested
  placement: a new `lichen-gateway` L7 bridge crate (Rust) using the
  existing MQTT-SN codec and port dispatch? (3) Is the MQTT-SN→MQTT bridge
  still a target at all, or has it been superseded by the Meshtastic
  bridge (rust/lichen-meshtastic/src/bridge.rs)?

## R-08N-006 — Leaf sends DAO for its native /128 (§11.2)

- Classification: divergent (confidence high).
- Evidence: Rust conformant end-to-end: `send_dao` (transmit.rs:117-154),
  signed DAO via preferred parent (router.rs:788-817), canonical leaf-DAO
  wire vector (test/vectors/rpl_route_state.json, consumed Rs
  rpl_route_state_vectors.rs:306 and C rpl_routing/main.c:271-282). C:
  builder + TX-manager are library-only (rpl_dao_build.c:188-247,
  LICHEN_RPL_LEAF_DAO_LEN rpl_routing.h:557, timing rpl_dao_timing.c) —
  no application caller exists, so no shipped C node ever emits a DAO
  (rg verified). Python: `DaoManager.build_dao` (dao_manager.py:442-458)
  and `DaoTxScheduler` have zero callers in node.py/link/gateway.
- Questions: (1) Is library-only C/Py DAO sending "implemented" (the
  mechanism + vectors exist) or "not-implemented" at node level (the
  behavior never happens in a deployed node)? (2) Where should the C
  wiring land: puck app periodic DAO send after join, or inside the RPL
  subsystem's join callback?

## R-08N-007 — Leaf does not relay RPL or data traffic (§11.2)

- Classification: divergent (confidence high). Same implementation site as
  R-08N-001.
- Evidence: No stack enforces non-relay for a leaf: Rust forwarding path
  has no role gate (receive.rs:259-291) and leaf-provisioned stacks relay
  DAOs (node.rs:584-630); C `lichen_router_route` forwards for any joined
  node (router.c:207-259); Py `_process_received` FORWARD branch is
  unconditional (node.py:1007-1035).
- Questions: (1) Confirm the enforcement point per stack: a role check in
  the receive/forward loop (Rs receive.rs, C lichen_router_route, Py
  node.py), or DAO-relay suppression plus DIO-silence plus config? (2)
  Does "does not relay RPL" conflict with the Rust design where non-root
  DAO relay is how DAOs reach the root through multi-hop (i.e. is a LICHEN
  leaf necessarily one radio hop from its parent)?

## R-08N-011 — Router sends DIOs, processes DAOs (§11.3)

- Classification: divergent (confidence high).
- Evidence: Rust conformant: non-root DIO propagation
  (build_authenticated_dio non-root branch router.rs:840-864, trickle
  runtime.rs:119-136, DIS-triggered unicast receive.rs:559-582) + DAO
  relay (node.rs:584-630) + root DAO processing (receive.rs:517-547),
  tests tests.rs:1503, 1595, 963. C: DIO transmission is root-only —
  `lichen_rpl_dio_write` callers are the gateway root app (rpl_root.c:195)
  and tests; joined C nodes send no DIOs; no DAO relay exists (DAO
  processing is root-only). Py: `DodagState.build_dio` (dodag.py:362) has
  no caller — the reference node never sends DIOs; `process_dao` is
  library-only.
- Questions: (1) In non-storing MOP=1, does a non-root LICHEN router need
  to send (trickle) DIOs at all, or is root-originated DIO flooding +
  silent DAO relay the intended design (in which case §11.3's "sends
  DIOs" is over-broad and C is conformant)? (2) If non-root DIOs are
  required, C and Py each need a bead — confirm before filing.

## R-08N-014 — BR provides application gateways and optional backhauls (§11.4)

- Classification: divergent (confidence high).
- Evidence: Split coverage: backhaul — Rust TUN with verbatim (no-NAT)
  forwarding (tun.rs:30-194, lichend.rs:914-956, e2e pings end_to_end.rs:283,323)
  and C WiFi-backhaul IPv6 forwarding (forwarding.c:45-91) + tunnel_auth
  in both (tunnel_auth.rs, tunnel_auth.c, vectors tunnel_authorization.json);
  Py has no TUN/upstream path. Application gateway — Py CoAP forward proxy
  only (coap/resources/proxy.py:47-80, SSRF-guarded, test_proxy.py); Rust
  has parser support only (lichen-coap codec.rs:328 is_proxy_uri) with no
  proxy resource; C none. MQTT-SN→MQTT absent everywhere (R-08N-004).
- Questions: (1) Which application gateways are in-scope for the BR for a
  conformance claim — CoAP proxy only, or also MQTT bridge? (2) Should the
  Rust proxy resource be ported from Py (suggested placement
  lichen-gateway CoAP site) or is Py's proxy the reference and Rs/C
  explicitly out of scope? (3) Is Py's lack of a backhaul path acceptable
  for a "reference implementation" (sim-level only)?

## R-08N-015 — BR runs Resource Directory, NTP (§11.4)

- Classification: divergent (confidence high).
- Evidence: RD — Python only: RFC 9176-simplified `/rd` register/refresh/
  delete + `/rd-lookup/res` (coap/resources/resource_directory.py:123-160,
  mounted site.py:249-256, vectors coap_rd.json +
  TestResourceDirectoryVectors test_vector_files_consume.py:569-800);
  Rust and C have no /rd anywhere (rg clean). NTP — no NTP/SNTP/NTS/
  Roughtime protocol code in any stack; the mesh time mechanism is
  DIO-carried time options (Rs time_option.rs:69-120, C messages.c:197-208
  LICHEN_RPL_OPT_DIO_TIME + time_sync.c, Py time_sync.py:409) — a
  different mechanism. The internet-time-source gap (NTS/Roughtime client +
  LCI proxy) is already beaded as `project-LICHEN-worker6-b7z9.20` (spec 09
  14.6 SHOULDs).
- Questions: (1) Is the "NTP" in §11.4 satisfied by the DIO time-option
  dissemination (mesh-internal time), or does it require an actual NTP
  server on the BR (which nothing implements)? If the latter, should .20
  be re-scoped to cover §11.4 explicitly? (2) Resource Directory: is Py's
  simplified RD the reference and Rs/C missing (suggest a bead for porting
  to lichen-gateway), or is RD optional in deployments ("etc." suggests an
  open list)?

## R-08N-016 — BR may aggregate multiple DODAGs (§11.4) — explicit MAY

- Classification: not-implemented (confidence high). MAY — no bead per
  protocol; recorded for completeness.
- Evidence: Every node holds exactly one DODAG state (Rs single `dodag`
  in Router; C single struct lichen_rpl_dodag rpl_root.c:105-117; Py single
  DodagState/DaoManager). The `multi_instance*` modules implement GCP-5
  multi-gateway federation (each gateway roots its own DODAG sharing one
  RPLInstanceID, multi_instance.rs:1-22) — coordination between roots, not
  one BR aggregating several DODAGs.
- Question: Confirm the reading that GCP-5 federation does not satisfy
  "may aggregate multiple DODAGs" (aggregation = one root, multiple
  DODAGIDs) — if Opus reads aggregation as the federation scenario, this
  row is implemented+tested instead.
