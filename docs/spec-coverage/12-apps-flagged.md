# spec/12-apps.md — flagged set for Opus verification (sweep 2026-09-09)

Flags: (a) low confidence, (b) ambiguous or divergent classification, (c) oscore/EDHOC semantics.
Gap beads already filed for the top clusters: project-LICHEN-worker6-b7z9.119 … .128 (see matrix).

---

## R-12-001 — MUST include `ts` from GNSS wall-clock (18.1.1)
- Classification: divergent (low confidence)
- Evidence: no sender consults a time provider (messaging.py:377 validates ts only if present); C stamps
  uptime seconds, not Unix epoch (coap_msg.c:261); Rust documents omit-or-0 (msg.rs:100-102).
- Question: Does the MUST apply to the send path only at the CoAP-resource layer, or is a firmware
  time-provider gate required? Is C's uptime-based `timestamp` field acceptable as an internal form, or
  must the wire form carry Unix epoch? Should a `wall_clock_valid` gate be added (09-packets-timing §14.6)?

## R-12-003 — TTL expiry = ts + ttl vs GNSS wall-clock (18.1.1)
- Classification: divergent (low confidence)
- Evidence: Python inbox never expires messages; msg_store.py:193 computes expiry against an injected
  monotonic clock (:91); Unix-wall-clock expiry exists only in the routing DTN layer (dtn_option.py:69-79).
- Question: Which layer owns message TTL expiry (inbox resource vs store vs routing DTN), and must
  msg_store's injected clock be switched to GNSS wall-clock with the same fail-open rule as dtn_option?

## R-12-005 — Broadcast = POST to coap://[ff02::1]/msg/inbox (18.1.2)
- Classification: ambiguous (low confidence)
- Evidence: resource accepts broadcast-targeted posts (vector messaging.json inbox_post_broadcast) but no
  ff02::1 delivery path exists in any stack (doc mentions only).
- Question: Is broadcast delivery expected at the messaging-resource layer (loopback + forwarding) or is
  this purely transport multicast that the resource need not implement? Does the vector overpin acceptance?

## R-12-008/009/012/014 — custody send path, receipt window, custody-chain retry (18.1.2/18.1.4)
- Classification: not-implemented / ambiguous (low confidence)
- Evidence: no C flag, no CON selection, no /msg/custody handshake, no receipt-window timer, receipts never
  sent, custody chain unrealized (beads b7z9.122, b7z9.123).
- Question: Is /msg/store + rt="msg.store" the intended realization of §18.1.4 custody (with the spec's
  /msg/custody path stale), or must /msg/custody be implemented? Should spec 18.1.2 be amended to match,
  or code to spec? Note the custody-best-effort decision bars reinterpreting custody as guaranteed delivery.

## R-12-024 — Custody REQUIRED for border routers (18.1.4)
- Classification: divergent (low confidence)
- Evidence: no app-layer custody in C; C routing-layer DTN store uses §9.8 values (32 msgs/64 KB/1536 B/
  24 h-7 d, routing/dtn.h:32-49), not the §18.1.4 table.
- Question: Does the C routing-layer DTN store satisfy "REQUIRED for border routers", or is a §18.1.4-
  conforming app-layer store required on the BR? Which limits table governs when 05 §9.8 and 18.1.4 differ?

## R-12-028/031 — back-pressure body + push delivery (18.1.4)
- Classification: divergent
- Evidence: msg_store.py:175-197 (bare 5.03, no Max-Age/{reason,available,retry_after}; POST → 2.04 not
  2.01; pull-drain, no wait-for-ACK/retain/delete-on-success).
- Question: Are the response codes mandatory with the exact example body, or is the body illustrative?
  Is pull-drain an acceptable delivery model, or is the push loop (wait-for-ACK) a MUST?

## R-12-035 — MAY replace unsent position update with newer state (18.2.1)
- Classification: ambiguous (low confidence)
- Evidence: C test_backpressure_retries_are_bounded covers retry, not replacement; no replace-newer-state
  code found in any stack.
- Question: Does any queue layer implement replace-if-unsent for position, or is this a scheduler-level
  allowance that no stack exercises yet?

## R-12-040 — position privacy CoAP enforcement (18.2.4)
- Classification: divergent
- Evidence: senml.py:109-116 calls check_read() with no args (authenticated members rejected) and discards
  the code (bare 4.03; spec requires 4.01 + {error:"oscore_required", mode}); only call site; no middleware.
- Question: Confirm the intended wiring — should check_read receive the request's OSCORE context and
  requester IID, and should the CoAP layer emit 4.01 vs 4.03 exactly as the policy returns? Is the
  position_privacy_auth.json matrix (which lacks the `off` mode and pins no error bodies) sufficient as oracle?

## R-12-041 — group beacon encryption with OSCORE group key (18.2.4) — OSCORE semantics
- Classification: implemented+untested at site level (low confidence)
- Evidence: group_beacon.py seal/open with AAD=mcast, receiver drops non-members; 9 unit tests; NOT mounted
  by build_site; GroupBeaconEmitter policy-gated.
- Question: Should GroupBeaconResource/Emitter be mounted in build_site, and does the AAD choice (mcast
  address) match the group-OSCORE external AAD rules elsewhere in the spec? (OSCORE group semantics —
  flag only, no fix planned here.)

## R-12-047 — SOS origin transcript origin address vs AddrForKey (18.4.1)
- Classification: divergent w.r.t. settled decision upstream-yggdrasil-addressing
- Evidence: all three stacks synthesize the transcript origin IPv6 as 0200:0000:...:<IID>
  (emergency.py:247, coap_server.c:498-499, sos_origin.rs) while spec 12-apps.md:733-735 requires the
  originator's 16-octet primary 02xx address (AddrForKey) preserved end to end. All three agree with each
  other — which is NOT the oracle (decision: upstream byte-equality vectors are).
- Question: Is the synthesized 0200:0000:…:<IID> a legacy fixture expectation to be regenerated, or is the
  "primary 02xx address" in this section intentionally a different object? This touches a settled decision —
  needs explicit adjudication before any code change. Related: sos_signature.json is descriptive-only
  (placeholder keys); only Rust pins a real digest (sos_origin.rs:160-173) — oracle weakness.

## R-12-048/049 — SOS silent-drop divergence + Origin Sequence gate (18.4.1)
- Classification: divergent
- Evidence: C silent drop (-ENOENT, coap_server.c:467-502) vs Python 4.01 (emergency.py:235-251) vs
  sos_signature.json:30 (error_response:false); C origin-seq gate exists but is not called from sos_post
  (coap_server.c:449-528 vs sos_resource.c:92-96); Rust has no gate and no RX path. C rate limiter is
  single-source global state (coap_server.c:447), diverging from per-source MUST.
- Question: Does "silently dropped" bind the CoAP resource layer (Python must stop returning 4.01), and is
  responding 4.29 to an over-limit SOS poster (Python) compatible with "dropped and logged but not relayed"?
  Confirm C should wire the existing seq gate into sos_post and convert the limiter to per-origin.

## R-12-051 — rate-limit key MUST be 16-byte IPv6 / MUST NOT extract IID (18.4.1)
- Classification: divergent
- Evidence: C single global limiter (not per-source); Python keys per-source by hex string (key form not
  pinned by vectors — sos_rate_limiting.json consumed by C and Rust only).
- Question: Should sos_rate_limiting.json be extended to pin the 16-byte key and per-origin independence so
  the C single-source state becomes a conformance failure rather than a comment?

## R-12-057 — dispatch byte 0x16 (18.4.3) — see bead b7z9.120
- Classification: divergent
- Evidence: Rust lichen-core/src/l2_payload.rs:83 test asserts 0x16 → UnknownDispatch, in direct conflict
  with spec 02-physical-link.md:237-244 and C/Python classifiers; no sender emits 0x16 anywhere.
- Question: Confirm Rust must add the SOS dispatch variant (spec + C + Python agree), and identify the
  correct emission point (does the CoAP POST /sos handler construct the 0x16 frame, or does a link-layer
  hook?).

## R-12-059 — SOS button grammar conflict (18.4.4)
- Classification: divergent — **spec-internal conflict**
- Evidence: spec 18.4.4 says hold 3 s / triple-press / hold 5 s = cancel; C implements spec/19-device-ux.md
  (≥2 s hold, 5 s = factory reset, no triple-press; ux_button_core.c).
- Question: Which spec governs (12-apps §18.4.4 vs 19-device-ux §4/§8)? This needs human adjudication of
  the spec conflict before code converges.

## R-12-060 — GET /sos shape (18.4.5)
- Classification: divergent
- Evidence: Python returns {"active": bool, "from", "t"} (emergency.py:174-175); C stub {"s": true}
  (coap_server.c:530-542); spec requires {"active": [<alert objects>]}; Python /sos/log exists+tested but
  never registered in any server setup (sos_log.py).
- Question: Is the Python `active`-as-bool shape an accepted legacy form (with vectors?) or a divergence to
  fix? Should sos_log.py be mounted in build_site?

## R-12-065 — SOS MUST NOT preempt committed RX / exceed airtime (18.4.6)
- Classification: ambiguous (low confidence)
- Evidence: no SOS-specific guard in any stack; only general duty-cycle/CSMA gates
  (rust/lichen-core/src/duty_cycle.rs, lichen/tests/airtime).
- Question: Do the general TX-eligibility gates satisfy this MUST by construction, or is an SOS-specific
  assertion/test required (e.g., that TX_PRIORITY_SOS never overrides a committed RX window)?

## R-12-070 — multicast roll call ff02::mesh (18.6.2) — see bead b7z9.128
- Classification: divergent
- Evidence: unicast-only record model in all three stacks (emergency.py:414-467; C lifecycle tests same).
- Question: Is `ff02::mesh` a defined multicast address anywhere (04-network.md?), or should the spec name
  ff02::1/ff03::fc? No address constant exists in code.

## R-12-073 — missed check-ins trigger alerts (18.6.4)
- Classification: not-implemented
- Evidence: C tracks due state (checkin.c:1908 lichen_checkin_due) but no alert emission in any stack.
- Question: Does "trigger alerts (see 18.4)" mean emitting an §18.4.2 alert (SOS-priority path) or a local
  notification? Scope determines whether this rides the SOS rate limiter.

## R-12-080 — group multicast derivation (18.8.3)
- Classification: implemented+tested but low confidence
- Evidence: groups_collection.py:184-199 group_multicast_from_id (RFC 3306 ff35:0040) using "owner's native
  /64 prefix"; spec says upper 64 bits of the owner's primary AddrForKey /128.
- Question: Verify Python's `_owner_mcast_prefix` actually uses the upstream AddrForKey-derived /128 (not a
  legacy native-profile prefix) and that the byte layout matches 18.8.3's example
  (ff35:0040:0200:1234:5678:9abc:0001::0001 — note the example's plen/placement looks odd for RFC 3306;
  confirm intended encoding).

## R-12-086 — group self-leave semantics (18.8.2)
- Classification: divergent
- Evidence: DELETE /groups/{gid} is owner-only authoritative delete (groups_collection.py:707-731, members
  get 4.03); spec says member voluntarily leaves via DELETE on own node.
- Question: Should the spec be read as "DELETE on any node = owner delete; self-leave is a different local
  operation", or must members be able to self-leave via DELETE? Implementation comment claims roles table
  supports owner-only — possible spec ambiguity rather than a bug.

## R-12-094 — tokens issuance endpoint unreachable (18.8.6) — see bead? (overflow, not filed)
- Classification: divergent
- Evidence: _handle_tokens_post implemented+unit-tested (delegation_tokens_resource.py) but GroupsItemResource.
  render_post routes only key/admins (groups_collection.py:733-739); no other registration.
- Question: Confirm routing is the only missing piece (no ACL reason), and whether the invite-path 4.03 body
  matches the spec diagnostic {"error":"delegation_invalid","reason":…} exactly.

## R-12-096 — group messaging/position via group mcast (18.8.4)
- Classification: divergent (low confidence)
- Evidence: GET /groups implemented; group /msg/inbox POST vector exists (groups_messaging.json) but
  multicast delivery transport unimplemented; GroupBeaconResource unmounted.
- Question: Is group-mcast delivery in scope for the node CoAP layer, or delivered via the multicast
  forwarding path (04-network) with the resource merely accepting the POST?

## R-12-097/106/112 — C deaddrop/confessions response-shape divergences (18.9/18.10)
- Classification: divergent (C only)
- Evidence: coap_dtn.c returns 2.04 (no Location-Path/Max-Age) for both POSTs (:299-301, :543); GET supports
  ?node= only, no Observe; confessions GET is SenML-only, lacks the §18.10.7 metadata map; no dedicated C
  tests for coap_dtn.c (only overlay-deaddrop-proof.conf).
- Question: Is the C divergent shape an accepted embedded profile (vectors don't cover C) or a conformance
  gap requiring C vector tests? Either way the silent absence of C vector consumption is a coverage hole.

## R-12-098 — deaddrop SCHC MUST (18.9) — see bead b7z9.119
- Classification: not-implemented
- Evidence: no /deaddrop or CF-112 SCHC rules in appendix-schc.md, constants.toml, rust rules, python rules;
  no compressed-packet vectors.
- Question: Confirm whether §18.9's "MUST use the project's SCHC rule set" is satisfiable via the generic
  global_oscore rules (constants.toml rule 5/6) — if so the spec clause may be declarative rather than
  requiring dedicated /deaddrop rules; adjudicate before filing implementation work.

## R-12-100 — Retry-After encoding + conflicting rate-limit vector (18.9)
- Classification: divergent + fixture conflict
- Evidence: Retry-After always encoded as CBOR body (+ Max-Age in Python), never CoAP option 213;
  test/vectors/deaddrop.json rate_limit_rejection (:67-77) expects 5.03 where spec mandates 4.29; Rust test
  rate_limit_rejection_matches_vector (deaddrop_vectors.rs:339) pins the wrong code; C bare 4.29.
- Question: Adjudicate the fixture (spec says 4.29 + Retry-After — fixture should be regenerated) and whether
  "Retry-After" means the CoAP option (13) or the CBOR body field. Do NOT weaken the test to the fixture.

## R-12-107 — confessions/deaddrop rate keying (18.9/18.10.3) — see bead b7z9.124
- Classification: divergent (MUST NOT violation)
- Evidence: C keys on 1 byte (coap_dtn.c:193-205, :497); Python keys confessions on low 64 bits
  (confessions.py:118, test_native_0200_source_iid_keys_rate); Rust caller-supplied (confessions.rs:785);
  pairwise-pair/group-(ctx,SenderID) keying unimplemented.
- Question: Confirm the intended key hierarchy and whether the 128-bit IPv6-source requirement applies when
  the address is not authenticated (unprotected posts) — spec says yes; Python's 64-bit keying is codified by
  a test that would need updating with the fix (not by weakening).

## R-12-111 — confessions group-OSCORE sender unlinkability (18.10.5) — OSCORE semantics, RECOMMENDED
- Classification: unimplemented (RECOMMENDED mode)
- Evidence: no group-context detection or (group, SenderID) keying anywhere; Rust test
  oscore_group_confession_sender_unlinked tests the vector's data model only.
- Question (human-only, no fix planned): confirm the RECOMMENDED group mode remains out of scope until group
  OSCORE contexts land; the rate-limit exemption for group posts (18.10.3) depends on it.

## R-12-114 — resource summary parity (18.11/18.12)
- Classification: implemented+tested (low confidence on Rust node)
- Evidence: rust lichen-node dispatch.rs:346-359 hosts only /sensors, /config, /deaddrop, /confessions —
  /msg/*, /diag/* absent from the Rust node dispatcher (client-side models exist).
- Question: Is the Rust node dispatcher intended to reach §18.11 parity, or is Rust client-library-only a
  settled scoping (like C-only /config/checkin accepted by the prior verify pass)?

---

## Fixture/oracle weaknesses (report, do not weaken)
1. `test/vectors/sos_signature.json` — descriptive-only, placeholder keys ("valid_pubkey_for_iid"), no real
   signature bytes; only Rust pins a real transcript digest (sos_origin.rs:160-173). Should be regenerated
   with real pinned vectors per the Schnorr48 draft's Appendix-A discipline.
2. `test/vectors/deaddrop.json#rate_limit_rejection` — expects 5.03; spec 18.9 mandates 4.29 + Retry-After.
3. `test/vectors/position_privacy_auth.json` — missing `off` mode and error-body pinning.
4. `test/vectors/density_scaling.json#position_beacon_rate` — encodes the §18.2.1 MUST with zero consumers.
