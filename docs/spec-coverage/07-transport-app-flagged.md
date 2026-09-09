## spec/07-transport-app.md — flagged set for Opus verification (sweep 2026-09-09)

20 requirements flagged: divergent (16), ambiguous (1), low-confidence
(024, 033, 038 — 033 also implemented+untested). Not a 06-security /
oscore-EDHOC section, so criterion (c) does not apply. Rows are R-07-NNN
per `docs/spec-coverage/07-transport-app.md`; spec line refs are to
`spec/07-transport-app.md`.

---

### R-07-001 — Gateway MUST translate mesh-internal ports (§9.1, :51-52)
- Classification: divergent (1 of 6 translations implemented: 5686→APRS-IS TCP in Rust).
- Evidence: rust/lichen-gateway/src/aprs_is.rs:228,258-319 (tested :619-1072); no TCP 8087 listener anywhere; no Cayenne codec; no 5688; NMEA sim-only. Beaded as b7z9.43.
- Question for Opus: Is the C/Zephyr gateway in scope for the translation MUST at all (b7z9.43 suggests "only if the C gateway ships app translation")? Should the spec scope the MUST to specific node classes (border router vs leaf), since a leaf gateway cannot exist in RPL non-storing topology?

### R-07-003 — CoT subtype byte table incl. 0x10 marker / 0x20 alert (§10.1.1)
- Classification: divergent — C has no marker/alert codec at all; Rust Marker/Alert are payload-less stubs; Python full.
- Evidence: lichen/subsys/lichen/compact_cot/ (PLI+chat only); rust/lichen-core/src/compact_cot.rs:57; python/src/lichen/compact_cot.py:32.
- Question for Opus: Is C's PLI+chat-only scope an intentional size constraint (STM32WL RAM) that should be reflected in a spec conformance class, or a gap? Rust alert stubs carry zero payload — the spec's alert subtype presumably needs at least a text field; confirm intended wire shape.

### R-07-006 — Receivers MUST reject malformed PLI (§10.1.1, :168-169)
- Classification: divergent (primary decoders conform+tested; two helper receivers do not).
- Evidence: python/src/lichen/gateway/compact_cot.py:336-358 tolerates trailing bytes (warnings.warn); rust/lichen-gateway/src/aprs_is.rs:93 rejects only len<17 / non-PLI subtype, no range validation. Filed as new gap bead this sweep.
- Question for Opus: Does the MUST cover internal translation helpers (aprs_is.rs) or only the datagram entry-point decoders? If yes, confirm the fix is to route both helpers through lichen-core's validating decoder rather than duplicating validation.

### R-07-009 — Sender identity from L2/OSCORE context, not payload (§10.1.1, :207)
- Classification: divergent, low confidence.
- Evidence: wire format has no sender field (all stacks) — structural half holds; but expand_cot_to_xml (python/src/lichen/gateway/compact_cot.py:432) derives a content-hash UUID when sender_uid is absent and nothing passes L2/OSCORE identity; no port-5681 receiver exists anywhere.
- Question for Opus: With no 5681 datagram server in any stack, is this requirement even reachable? Should the spec note that sender-identity binding applies at the (unbuilt) gateway ingestion point, and should the UUID fallback be prohibited?

### R-07-010 — Gateways expand compact CoT to full XML (§10.1.1, :209)
- Classification: divergent (Python-only).
- Evidence: python/src/lichen/gateway/compact_cot.py:432-966 complete+tested; Rust has no XML dependency; C none.
- Question for Opus: Confirm Rust/C gateway translation scope decision (same root cause as R-07-001; do not file twice — pick the owning bead).

### R-07-014 — APRS-IS bridge on 5686 (§10.1.4)
- Classification: divergent (TCP path done in Rust; AX.25 reconstruction absent; `T` telemetry format char unimplemented).
- Evidence: rust/lichen-gateway/src/aprs_is.rs:228-527 + tests.
- Question for Opus: Is AX.25 RF reconstruction a real deployment requirement (spec says "when bridging to RF APRS") or should the spec downgrade it to optional? Same for the `T` telemetry format char.

### R-07-015 — NMEA passthrough on 5687 (§10.1.5)
- Classification: divergent (dispatch entry only; no consumer/producer; sim generation only).
- Evidence: port tables all 3 stacks; python/src/lichen/sim/gnss.py:100-156.
- Question for Opus: Is port 5687 dead weight (spec lists no translation obligation beyond "may convert")? Either implement passthrough in the gateway or mark the port reserved-until-implemented.

### R-07-016..020 — Crypto relay 5688 (§10.1.6)
- Classification: not-implemented (whole subsection: CBOR format, CAIP-2, response, limits, gateway RPC op).
- Evidence: port 5688 absent from all constants/dispatch (rg clean); cross-noted in b7z9.43(f).
- Question for Opus: Is 5688 in scope for any current milestone, or should the spec mark the subsection "reserved, unimplemented"? Filing 5 separate beads for one absent feature seemed like bead-spam; confirm one epic-level bead (b7z9.43) is the right vehicle.

### R-07-024 — IPSO discovery /.well-known/core?rt=ipso (§10.2.2)
- Classification: implemented+tested for discovery infrastructure, low confidence on the `rt=ipso` attribute specifically.
- Evidence: well-known-core handlers exist (rust dispatch.rs:301,349 + test; py site.py:203; C CONFIG_COAP_SERVER_WELL_KNOWN_CORE) but no stack registers any IPSO resource (see R-07-023), so `?rt=ipso` filtering is never exercised.
- Question for Opus: Should IPSO URIs be served by the node's CoAP server at all (R-07-023 shows codec-only today), or is IPSO Direct client-side encoding only? Spec reads as server-side ("CoAP resources MAY use OMA LwM2M/IPSO paths").

### R-07-026 — CoAP transmission parameters for LoRa (§10.2.3)
- Classification: divergent.
- Evidence: Python pins all 6 constants + vectors but the live aiocoap transport uses RFC 7252 defaults (transport.py:977-1044); Rust has no constants at all (ad-hoc ctor args in observe paths); C has only ACK_TIMEOUT=15s (Zephyr MAX_RETRANSMIT=4 default still in effect).
- Question for Opus: The retry-storm/duty-cycle rationale makes this behaviorally load-bearing even though the table carries no RFC 2119 keyword. Should this be filed as a MUST-gap bead (spec implies normative "LICHEN Value" column), and which stack owns the reference implementation (Python constants exist but are unwired)?

### R-07-027 — Prefer NON for telemetry; CON only for critical (§10.2.3, :513-523)
- Classification: ambiguous.
- Evidence: no per-message CON/NON policy code found; delivery-service selection absent (R-07-034/b7z9.122), so there is nothing to evaluate the preference against.
- Question for Opus: Is this row redundant with the delivery-services table (:581-598) once R-07-034's send-side selection lands, or does it impose an additional constraint on current NON/CON usage?

### R-07-028 — Duty cycle MUST: accounting groups + per-frequency occupancy (§10.2.4, :527-528)
- Classification: divergent.
- Evidence: all 3 stacks = single rolling window per node; dwell is per-TX ceiling (Rs US915_FCC_MAX_DWELL_MS 400), not per-frequency occupancy; no accounting-group multiplexing. Tracking kernel itself is vector-pinned (Semtech airtime oracle). Filed as new gap bead this sweep.
- Question for Opus: Does "applicable regulatory accounting group" require multi-group support today (e.g., EU sub-band hopping where per-sub-band budgets differ), or is single-group + per-TX dwell adequate for the current regional plans (EU868 1%, US915 dwell-only)? This decides whether the fix is a data-structure change or a spec clarification.

### R-07-031 — Congestion tiers + 5.03 load-shedding emission (§10.2.4, :548-577)
- Classification: divergent (3-way).
- Evidence: Py complete+tested (500/800/950); Rs thresholds/gating but no server-side duty-cycle 5.03 builder; C builder duty_response.c:117-155 with DIVERGENT thresholds 700/850/950 (spec :550-555 = 500/800/950) and no production caller. Filed as new gap bead this sweep (threshold divergence); b7z9.45 tracks the C emission/backoff gap.
- Question for Opus: Confirm the C 700/850/950 constants are a bug (not a deliberate C-profile), and whether the fix belongs in duty_response.c constants or the spec's tier table.

### R-07-032 — Senders MUST back off on 5.03 (§10.2.4, :573)
- Classification: divergent (C status uncertain — evidence conflict).
- Evidence: Py+Rs implemented+tested. C: backoff.c (DEFAULT 60s/MAX 3600s) + coap_client.c:297-315,472-477 NOW EXIST — this contradicts bead b7z9.45's claim of "C coap_client.c has ZERO 5.03/backoff handling"; recent bead 6lhf ("Committed host test + cross-impl vectors for the 5.03 backoff payload parser", open) suggests this landed recently.
- Question for Opus: Verify current C sender-backoff coverage against b7z9.45 and close/update that bead; confirm the cross-implementation 5.03 payload-parser vectors (6lhf) actually gate the C path.

### R-07-033 — Failure signaling only via already-defined mechanisms (§10.2.4, :575-577)
- Classification: implemented+untested (negative constraint, conformant by absence), low confidence.
- Evidence: no forwarder synthesizes CoAP responses in any stack; no MAC ACK/NACK added.
- Question for Opus: Confirm no planned CCoP/CCP mechanism reintroduces forwarder-synthesized responses, and whether a negative test (forwarder must not emit 5.03) is worth a vector.

### R-07-034 — Datagram vs message delivery service selection via DTN S-flag (§10.2.4, :581-598)
- Classification: divergent (RX complete, TX absent).
- Evidence: dtn_sflag_hbh.json consumed by all 3 stacks (Py routing/dtn_option.py, Rs routing/dtn_option.rs + stack.rs:1000-1046, C routing/router.c:416-441 + routing/dtn.c); send-side selection absent — b7z9.122.
- Question for Opus: None beyond b7z9.122's scope; included here because the spec-07 half of the split (per-message application selection, §10.2.4 table) should be verified as covered by that bead's fix plan.

### R-07-036 / R-07-037 — Observe MUST bounds 16/64 + LRU eviction (§10.3, :695-697)
- Classification: divergent / not-implemented.
- Evidence: no 16/64 enforcement anywhere; C pools of 3-4 never-evict with explicit 5.03-on-full; Rs fail-closed RegistryFull; Py unbounded. Beaded as b7z9.44, which already flags the never-evict-vs-LRU conflict as needing a human decision.
- Question for Opus: Confirm the b7z9.44 human decision (implement evict-oldest per spec vs amend spec to fail-closed pools). Note C's 5.03-on-full is arguably *stricter* than the spec's LRU requirement.

### R-07-038 — MAY coalesce unsent Observe updates (§10.3, :667-670)
- Classification: implemented+untested, low confidence.
- Evidence: C coalesces to latest on /status and /sensors/location (coap_status.c:1374-1428, retry :885-920; coap_location.c:386-424); Rs rejects-with-Backpressure instead (conformant for a MAY); no vector pins coalescing.
- Question for Opus: Should a vector pin the coalescing contract (latest-value only, no distinct-record merge) given R-07-039's MUST NOT sits directly adjacent and is only structurally guaranteed in C?

### R-07-042 — MQTT-SN gateway architecture (§10.4)
- Classification: divergent (transport layer complete, application bridge absent).
- Evidence: port+SCHC Rule 7 all 3 stacks (vector-pinned); codec Py-only; no MQTT-SN↔MQTT broker bridge anywhere (same finding as R-08N-004, 08-nodes sweep).
- Question for Opus: Confirm the broker bridge is owned by the 08-nodes/gateway sweep (R-08N-004) so the two sweeps don't file competing beads; the port_dispatch.json vector pins only 5683-family + 10883 — the spec's "reserved 5684" row is pinned as reserved_dtls, good.

### R-07-043 — CoAP Block-wise NOT RECOMMENDED (§10.5, :735-741)
- Classification: divergent.
- Evidence: block-wise IS implemented in all 3 stacks and coap_block.json explicitly says it is still used by OTA and gateway paths; SCHC fragmentation is also fully implemented (R-07-044).
- Question for Opus: Spec vs implementation tension: either spec 10.5 should acknowledge block-wise's OTA/gateway role (like the guard-ppm align-spec-to-reality precedent), or OTA paths should migrate to SCHC fragmentation/app chunking. Which way does Mark want it?

### R-07-046 — Resource Directory on border router (§10.6)
- Classification: divergent (Python-only; Rs/C absent).
- Evidence: resource_directory.py + coap_rd.json (15 vectors, Py consumer); rg clean in rust/ and lichen/.
- Question for Opus: Cross-listed from 08-nodes R-08N-015 — confirm RD in Rs/C is tracked by an existing gateway-epic bead (b7z9.113 covers GCP discovery runtime; RD specifically may be unowned). If unowned, file one bead rather than two.
