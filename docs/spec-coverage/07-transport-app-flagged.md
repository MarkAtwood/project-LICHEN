# Flagged set — spec/07-transport-app.md (sweep 2026-08-31)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or section 06-security/OSCORE-semantics sensitive. Each entry:
requirement, classification, evidence, and the specific question to answer.
No rows in this section touch oscore/EDHOC internals (human-only bar); the
section is not 06-security, so every flag below originates from rule (a) or
(b) of the sweep protocol.

## R-07-001 — Gateways MUST translate mesh-internal ports before external forwarding (§9.1)

- Classification: divergent (confidence high). Gap bead
  `project-LICHEN-worker6-b7z9.43` (P2).
- Evidence: Only 5686→APRS-IS TCP is implemented+tested
  (rust/lichen-gateway/src/aprs_is.rs:228,473,527 + loopback tests:619-1072).
  CoT→XML expansion exists as functions but has no TCP 8087 listener
  (python/src/lichen/gateway/compact_cot.py:432,765; rg 8087 clean).
  5682→CoAP CF112 is plumbing only (constant+codec, no 5682-datagram bridge).
  5685→LoRaWAN has no Cayenne codec in any stack. 5687 has no translation.
  5688 (Crypto Relay) is absent from all constants, dispatch tables, and
  vectors in all three stacks (sweep rows R-07-019/020).
- Questions: (1) Does the MUST bind gateways to translate *all six* ports
  unconditionally, or only for ports the deployment actually carries (i.e.,
  is a gateway that never forwards 5685 traffic conformant without a Cayenne
  codec)? (2) Is port 5688's total absence (not even a reserved constant)
  intended to be tracked as one gap with the translation table, or should the
  whole §10.1.6 crypto-relay feature be a separate epic? (3) Is CoT XML over
  TCP 8087 expected to ship in the C gateway, Rust lichend, or Python
  reference only?

## R-07-002 — Port allocation table incl. 5688 (§9.1, no kw)

- Classification: divergent (confidence high). Keyword-less: noted, not
  beaded; folded into `project-LICHEN-worker6-b7z9.43`.
- Evidence: 8/9 ports defined in all three stacks
  (python/src/lichen/constants.py:24-31; rust/lichen-core/src/constants.rs:31-38;
  lichen/subsys/lichen/udp_port_dispatch/include/lichen/udp_port_dispatch.h:15-22)
  and pinned by test/vectors/port_dispatch.json; 5688 is absent from all
  stacks and from constants.toml. Also: the raw-UDP ports (5681/5682/5685-5687)
  are missing from the canonical constants.toml [ports] table, and
  rust/lichen-core/src/constants.rs:48 carries a stale comment ("rule 7 not in
  constants.toml yet" while constants.toml:36 has mqtt_sn=7).
- Questions: (1) Should 5688 be added as a reserved constant even before any
  relay exists, so dispatch classifies it instead of treating it as unknown?
  (2) Should the raw-UDP ports be hoisted into constants.toml (the declared
  cross-language source of truth) to prevent drift?

## R-07-011 — Sender identity from L2/OSCORE context, not CoT payload (§10.1.1, no kw)

- Classification: implemented+untested (confidence low).
- Evidence: The compact CoT format carries no sender field — pinned by the
  exact layouts in test/vectors/compact_cot.json (+schema); stack-wide
  identity attribution is per key-derived IID (R-04-003/022 evidence).
- Question: Is format-level absence of a sender field + the stack's IID
  attribution sufficient evidence for this row, or does it need an explicit
  test that a 5681 datagram's sender resolves to the OSCORE/L2 identity
  (e.g., a spoofed-source datagram rejected at dispatch)? python/src/lichen/
  port_dispatch.py:146 (dispatch_udp) does verify source-address policy —
  confirm that is the intended enforcement site.

## R-07-016 — APRS-IS ASCII payloads; format chars !/@/:/>/T (§10.1.4, no kw)

- Classification: divergent (confidence high). Keyword-less: noted, not
  beaded.
- Evidence: Rust handles position reports only (cot_to_aprs/aprs_to_cot,
  aprs_is.rs:473,527 — PHG, DDMM.mmN, altitude clamp, inline tests). No
  handling of `:` message, `>` status, `T` telemetry, `@` timestamped
  position (rg clean). Python/C: port dispatch classification only.
- Question: Is position-report-only coverage acceptable for the port's
  documented purpose, or are status/message/telemetry format chars required
  for the APRS feature to be considered implemented?

## R-07-018 — NMEA passthrough on 5687 (§10.1.5, no kw)

- Classification: ambiguous (confidence low).
- Evidence: Dispatch classifies 5687→Nmea in all stacks
  (port_dispatch.rs:165, port_dispatch.py:38, udp_port_dispatch.h:21) but no
  passthrough/forward handler exists downstream anywhere. Python sim
  generates GGA/RMC (sim/gnss.py:100-156 + test_gnss_nmea_feeder.py).
- Question: What does "direct passthrough of standard sentences" require of a
  node — hand the datagram to an application callback (which dispatch does),
  or relay it toward a gateway? Is the existing dispatch-then-drop behavior
  conformant?

## R-07-025 — Gateways SHOULD translate between SenML and IPSO formats (§10.2.2)

- Classification: not-implemented (confidence high). SHOULD — no bead filed
  (omission breaks no shipped documented feature).
- Evidence: No SenML↔IPSO translation code in any stack (rg clean); both
  codecs exist independently (lichen-senml wire.rs; senml/ipso.py).
- Question: Does any current documented gateway feature depend on this
  translation (which would flip it to a beaded SHOULD-gap), or is it
  correctly deferred?

## R-07-026 — CoAP parameters: ACK_TIMEOUT 15s, ARF 2.0, MAX_RETRANSMIT 2, NSTART 1, LEISURE 15s, PROBING_RATE 0.1 (§10.2.3, no kw)

- Classification: divergent (confidence high). Keyword-less: noted, not
  beaded.
- Evidence: Python implements all six exactly (coap/params.py:26-38) with a
  live retransmit engine (transport.py:974-985) and vector
  coap_transport.json loRa_params (test_vector_consumers_lci.py:596-609).
  C sets ACK_TIMEOUT only (apps/puck/prj.conf:48; no Kconfig symbols for the
  other five). Rust has ack_timeout/max_retransmit only inside the Observe
  server (observe.rs:292-293,444-463) — no general CON retransmit engine, so
  Rust CON requests arguably never retransmit at all.
- Questions: (1) Is the absence of a Rust CON-retransmit engine deliberate
  (licend sends NON/Observe traffic) or a gap the spec's table makes visible?
  (2) Should C grow Kconfig symbols for the remaining five parameters, or is
  puck's ACK_TIMEOUT the only C-relevant knob?

## R-07-027 — Prefer NON for telemetry; CON only when critical (§10.2.3, no kw)

- Classification: ambiguous (confidence low).
- Evidence: No automatic NON-selection logic in any stack. Implemented as a
  priority incentive (CON→P2, NON→P3: params.py:163-164,
  transport.py:848-861; vector prefer_non coap_transport.json:121-134). C
  uses NON for observe notifications (coap_location.c:406).
- Question: Is the priority differential an acceptable implementation of
  "prefer NON", or is sender-side automatic NON selection for telemetry
  required?

## R-07-030 — Congestion levels 50/80/95% with per-level actions (§10.2.4, no kw)

- Classification: divergent (confidence high). Keyword-less: noted, not
  beaded.
- Evidence: Rust thresholds 500/800/950 permille with boundary tests
  (duty_cycle.rs:124-147,994-1135); Python congestion levels
  (coap/params.py:140-148 + test_congestion.py); C has no level
  classification — it fail-closed blocks at budget (lora_l2_tx.c:427-436).
- Question: Does the C stack need the four-level classification (it already
  throttles), or is block-at-budget acceptable for a constrained node whose
  only remaining action would be the same block?

## R-07-031 — 5.03 + Max-Age + CBOR {reason: duty_cycle, retry_after, level} (§10.2.4, no kw)

- Classification: divergent (confidence high). Keyword-less: noted, not
  beaded; folded into `project-LICHEN-worker6-b7z9.45`.
- Evidence: Python implements the full emission (params.py:239-292,
  site.py:111-130) with vector load_shedding_503; Rust parses client-side
  (client.rs:74-82); C emits generic 5.03s for unrelated capacity policies
  (coap_status.c:961, coap_location.c:1248, coap_rangetest.c:836-890) but
  never a duty-cycle CBOR body or Max-Age retry hint.
- Question: See R-07-032 — same bead. Additionally: are C's existing generic
  5.03s (no Max-Age) a sender-side hazard, since conformant Python/Rust
  senders will apply the 60 s default backoff to them?

## R-07-032 — Senders receiving 5.03 MUST back off (§10.2.4)

- Classification: divergent (confidence high). Gap bead
  `project-LICHEN-worker6-b7z9.45` (P2).
- Evidence: Python implemented+tested (ip_coap.py:25,80,110,237-245 + tests
  client/test_ip_coap.py:295-408 citing spec 07); Rust implemented+tested
  (client.rs:35-40,159,217-254 + tests:648-720); C coap_client.c has zero
  5.03/backoff/retry handling (rg clean).
- Question: Confirm no other C CoAP client surface (e.g., apps/puck or
  apps/gateway request paths outside subsys coap_client.c) needs the backoff;
  sweep only verified subsys/lichen/coap.

## R-07-034 — Application→priority mapping table (§10.2.4, no kw)

- Classification: divergent (confidence high). Keyword-less: noted, not
  beaded.
- Evidence: Python implements the full 12-row table (params.py:155-170 +
  transport.py:848-861, vector app_to_priority_mapping, TestAppPriority).
  Rust uses priorities but the per-port/subtype table was not found
  (lichend.rs:545-1059, tui/radio.rs:80-95). C defaults all app data to
  TX_PRIORITY_BULK (lora_l2_tx.c:399-407) — meaning C sends tactical chat and
  CoAP CON at P4, contradicting the table.
- Question: Is the C bulk-default a deliberate simplification or a gap? If
  gap: should the mapping live in udp_port_dispatch (which already classifies
  ports) so lora_l2_tx can consume it?

## R-07-036 / R-07-037 — Observe MUST bounds (≤16/resource, ≤64 global) + LRU eviction (§10.3)

- Classification: divergent / not-implemented (confidence high). Gap bead
  `project-LICHEN-worker6-b7z9.44` (P2).
- Evidence: No stack implements 16/64 or LRU. Rust: fail-closed RegistryFull
  with caller-chosen const-generic capacity, no production instantiation
  (observe.rs:289-341; tests at 2 observers). Python: aiocoap observer lists
  unbounded. C: per-resource pools 4/4/3, explicitly never-evict
  (coap_msg.c:37-39, coap_status.h:37-38, coap_location.h:29,
  coap_rangetest.c:838-855), no global counter.
- Questions: (1) C's never-evict looks deliberate — should the spec be
  amended to reject-new (current behavior is arguably safer against
  subscription thrash on constrained nodes), or must C implement
  evict-oldest? (2) For Python, is a site-level cap wrapper the right
  placement, or should each ObservableResource own its bound? (3) Does
  "64 globally" mean per-node-process, or per-DODAG/per-interface?

## R-07-038 — MQTT-SN message types / codec (§10.4, no kw)

- Classification: divergent (confidence high). Keyword-less: noted, not
  beaded.
- Evidence: Python has the full codec (mqttsn/messages.py:33-47,137-344,
  codec.py) with 13 vectors (mqtt_sn.json) incl. QoS -1, truncated, reserved
  type; Rust and C classify the port and compress it via SCHC Rule 7 but do
  not parse MQTT-SN.
- Question: Do the Rust/C stacks need an MQTT-SN codec, or is Python the
  reference implementation for payload formats (consistent with how SenML/CoT
  are distributed across stacks)?

## R-07-040 — Gateway translates MQTT-SN ↔ MQTT 3.1.1/5.0 (§10.4.1, no kw)

- Classification: not-implemented (confidence high). Keyword-less: noted, not
  beaded. Resolves the R-08N-004 deferral (spec/08-nodes sweep).
- Evidence: No MQTT broker client or translator in any stack (rg
  1883|broker|paho clean).
- Question: This is the largest single feature gap in the section (whole
  gateway role absent, cross-ref R-08N-004). The sweep preamble rules
  keyword-less rows out of gap beads — should the human override that and
  file an epic for the MQTT-SN gateway anyway, given two prior sweeps
  deferred to this one?

## R-07-041 — CoAP Block-wise NOT RECOMMENDED (§10.5)

- Classification: divergent (confidence high). SHOULD-NOT tension — no bead;
  needs a human/spec decision.
- Evidence: Block-wise exists and is actively used: Rust block.rs (+ tests),
  Python aiocoap passthrough (transport.py:1130-1131), C gateway app uses
  Zephyr-native Block2 (apps/gateway/src/main.c:326-384) consumed by puck
  (main.c:445); vectors coap_block.json exist and explicitly say they pin the
  option syntax "still used by OTA and gateway paths". The standalone C
  engine (coap_blockwise.c) is unwired (bead `worker6-kbgx`).
- Question: Spec-vs-implementation conflict: either the spec sentence should
  be softened (block-wise permitted where SCHC reassembly is unavailable, e.g.
  the C gateway path) or the gateway/puck Block2 usage should be scheduled
  for removal. Which way? (Related: OSCORE block-wise is load-bearing per
  `worker6-cvko` — removing block-wise has security-test fallout.)

## R-07-043 — Unknown-limit chunks MUST fit 1281-byte receiver capacity (§10.5)

- Classification: ambiguous (confidence low).
- Evidence: No application chunking exists (R-07-044), so the conditional
  MUST has no trigger site — vacuously satisfied. The 1281 constant itself is
  implemented+tested in all stacks (R-07-042 sites; coap_transport.json:311
  pins mandatory_receiver 1281).
- Question: Does vacuous compliance count for a conditional MUST whose
  precondition (application chunking) is entirely absent, or should the
  missing /firmware/upload protocol be treated as making the MUST
  unimplementable (and thus beaded)?

## R-07-045 — Border router runs CoAP Resource Directory (§10.6, no kw)

- Classification: divergent (confidence high). Keyword-less: noted, not
  beaded (adjacent to `worker6-l1qw.18`).
- Evidence: Python only (resource_directory.py:124-358, simplified RFC 9176,
  coap_rd.json, 73+ tests); Rust and C have no /rd at all.
- Question: Spec says the *border router* runs RD. Python's RD mounts on the
  generic CoAP site (any node), and no Rust/C BR runs it. Is RD required on
  BRs specifically (→ should ride with the l1qw.18 WKC/Block2 gateway
  work), or is the Python implementation sufficient as reference?

## Adjacent keyword-less not-implemented rows (context for the above; not separately flagged)

- R-07-015 (Cayenne LPP codec absent — blocks R-07-001's 5685 row),
- R-07-019/020 (crypto-relay wire format and gateway operation absent —
  same site as R-07-001's 5688 row),
- R-07-044 (/firmware/upload chunking absent — precondition of R-07-043).

## Cross-sweep notes

- R-01-012's DTLS-for-MQTT-SN deferral resolves here: §9.1 reserves 5684 and
  states OSCORE-not-DTLS; code comments already match (constants.rs:34). No
  action.
- Beads `project-LICHEN-wutk.7` / `wutk.8` ("KISS/SLIP transport vs
  spec/07-transport-app.md") reference this spec file for LCI transports;
  this section contains no SLIP/KISS text — those beads appear to target the
  LCI spec (spec/11) and were left untouched.
- SCHC Rule 7 open beads `worker6-83wu` / `worker6-pgsl` affect R-07-039's
  "implemented+tested" status if the fallback policy changes MQTT-SN
  sendability.
