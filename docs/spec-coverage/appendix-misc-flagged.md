# spec/appendix-misc.md — flagged set for Opus verification (sweep 2026-09-09)

Section has no RFC 2119 keywords; all requirements are implied by examples.
No rows were low-confidence or ambiguous, and this is not section 06-security —
items below are flagged because classification was divergent (R-APXM-001),
because the Appendix D footnote touches EDHOC semantics (criterion c), and
because R-APXM-006's absence interacts with an align-spec-to-reality pattern
Opus has adjudicated before.

## R-APXM-001 — RD registration payload format (divergent)

- Requirement (C.1): `POST coap://[6lbr]/rd?ep=node-001&lt=86400` with
  `Content-Format: application/link-format` and a link-format payload body.
- Classification: **divergent**.
- Evidence: Python RD decodes the registration body as CBOR only
  (`_decode_single_cbor`, python/src/lichen/coap/resources/resource_directory.py:280;
  docstring :127-128); there is no link-format decode path for registration.
  Lookup (C.2) returns link-format only when the client sends Accept: 40
  (:385-388), default CBOR 60. Rust and C have no `/rd` or `/rd-lookup/res`
  symbols at all (rg clean). Tests are Python-only: python/tests/coap/
  test_resource_directory.py, test/vectors/coap_rd.json. Identical divergence
  classified in R-07-046 and R-08N-015 but never beaded; bead filed this sweep.
- Question for Opus: is the appendix's `application/link-format` registration
  binding normative (making the Python CBOR-only decoder an implementation bug
  to fix, and widening the gap for Rust/C), or should spec 07 §10.6 /
  appendix-misc C.1 be amended to the CBOR profile Python actually implements
  (align-spec-to-reality precedent: GUARD_PPM, spec-15.2-key-storage)? Note
  RFC 9176 §5 default is `application/link-format` (CF 40); CBOR link-format
  is the registered extension — a spec amendment would need to state the
  LICHEN profile explicitly. Also decide whether RD must exist in the Rust
  gateway and C gateway binaries for the 6LBR role to conform.

## R-APXM-006 — MQTT-SN→MQTT broker gateway bridge (not-implemented)

- Requirement (E flow 3): `Leaf 3 -> MQTT Broker: MQTT-SN PUBLISH (via gateway
  at border router)`.
- Classification: **not-implemented** (high confidence, included here because
  three sweeps deferred it without tracking).
- Evidence: MQTT-SN codec, port 10883 dispatch and SCHC Rule 7 exist in all
  three stacks, but no code connects to an MQTT broker in any of them (no
  `broker`/`1883`/`paho`/MQTT-client hits in rust/, lichen/, python/src/;
  Python codec has gateway-role message types with no broker behind them).
  Bead filed this sweep (parent project-LICHEN-worker6-b7z9).
- Question for Opus: implement the bridge (which stack first — Rust gateway
  `lichend` is the natural owner per 08-nodes R-08N-004) or amend the spec
  example/07 §10.4 to mark the broker bridge as an optional/unscheduled
  feature? The Py codec's gateway-role message types (ADVERTISE/GWINFO) have
  no server wiring behind them either — confirm that reading.

## Appendix D footnote (criterion c — EDHOC semantics)

- Text: `**Can add EDHOC for session keys` (Forward Secrecy row).
- Classification: informational claim, flagged per protocol.
- Evidence: no EDHOC session-key establishment exists in any stack; OSCORE
  contexts are provisioned, not EDHOC-derived (06-security sweep covers the
  normative EDHOC text; its matrices are authoritative).
- Question for Opus: is the footnote's "can add EDHOC" still an accurate
  forward-looking claim given current EDHOC status, or should the footnote be
  qualified until an EDHOC integration exists? No bead filed — oscore/EDHOC
  semantics are human-only.
