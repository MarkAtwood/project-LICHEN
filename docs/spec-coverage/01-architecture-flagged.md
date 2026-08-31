# Flagged set — spec/01-architecture.md (sweep 2026-08-31)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or section 06-security/OSCORE-semantics sensitive. Each entry:
requirement, classification, evidence, and the specific question to answer.
No rows in this section touch oscore/EDHOC internals (human-only bar) — the
section is architectural; OSCORE appears only as a layer assignment (R-01-012).

## R-01-003 — Efficient: SCHC compresses headers to 6-15 bytes (§1.2.2, no kw)

- Classification: divergent (confidence high).
- Evidence: Measured compressed IPv6/UDP headers across the shared vectors are
  21-33 bytes, never ≤15: test/vectors/schc_compression.json (27 cases; the
  minimum is a 48-byte packet compressing to 21 bytes), schc_adaptation.json
  compressed_size rule2=23 / rule3=40 / rule4=37. AGENTS.md itself records
  "48 bytes to 18-33 bytes". No rule in C (rules 0-7, schc.c:6), Rust
  (lichen-schc), or Python reaches 6-15 bytes.
- Questions: (1) Is "6-15 bytes" a stale or erroneous spec number to be
  amended (erratum) to the measured 18-33, or is there an intended rule
  profile (e.g., best-case static-header rules) that should achieve 6-15 and
  is simply not implemented? (2) Should the owning requirement live in
  spec/03-adaptation.md (sweep pending) rather than the architecture goals?

## R-01-005 + R-01-011 — Interoperable: standard CoAP/MQTT-SN apps work unmodified (§1.2.4); Application layer: CoAP, MQTT-SN, Raw UDP, ICMPv6 (§2, no kw)

- Classification: divergent (confidence high), grouped — one gap site
  (MQTT-SN).
- Evidence: CoAP, Raw UDP (udp_port_dispatch + port_dispatch.json vectors),
  and ICMPv6 (R-04-016) are implemented+tested. MQTT-SN exists only as wire
  codec + port dispatch + SCHC Rule 7 (Py mqttsn/codec.py+messages.py; Rs
  port_dispatch.rs MqttSn, codec.rs:1041-1133; C tests/schc_mqtt_sn). No
  MQTT-SN gateway/broker endpoint exists in any stack (rg 1883|broker clean),
  so a standard MQTT-SN client has no counterpart; cross-ref R-08N-004
  (Gateway role MQTT-SN→MQTT translator not-implemented).
- Questions: (1) Does the design goal "standard applications work unmodified"
  require the MQTT-SN gateway translator, or is CoAP interop the operative
  goal with MQTT-SN aspirational? (2) The 07-transport sweep (pending) owns
  the normative MQTT-SN text — should the gap bead be filed there as a MUST
  if 07 carries keywords, keeping this row a pointer?

## R-01-008 — Non-goal: no backward compatibility with Meshtastic or MeshCore (§1.3, no kw)

- Classification: implemented+untested (confidence low — judgment call).
- Evidence: The LICHEN wire protocol is deliberately incompatible: sync word
  0x34 "Distinct from Meshtastic (0x2B)" (Py constants.py:11; Rs
  constants.rs:4; C radio default pinned lichen/tests/coap_config/main.c:589,
  708) plus a custom frame format with mandatory Schnorr-48 link signatures
  (lichen_link_tx.c:165). HOWEVER, the tree ships Meshtastic/MeshCore *bridge
  adapters*: rust/lichen-meshtastic (LICHEN-IPv6 ↔ Meshtastic MeshPacket
  translation over IP_TUNNEL_APP portnum 33, lib.rs), C
  lichen/subsys/lichen/{meshtastic,meshcore} with 9 test suites
  (lichen/tests/meshtastic_{adapter,ble,codec,gateway_adapter,...}),
  python/src/lichen/interface/meshtastic/adapter.py (LICHEN node emulating a
  Meshtastic device over BLE GATT).
- Questions: (1) Do the translation bridge adapters violate the non-goal, or
  is the non-goal strictly about the LICHEN wire protocol being
  incompatible (my reading: adapters are application-level gateways and do
  not violate it)? (2) If the adapters are sanctioned, should the non-goal
  text be amended to say "no wire backward compatibility (bridge adapters
  excepted)" so future sweeps don't re-flag this? (3) Is the intentional
  non-interoperability (0x34 ≠ 0x2B) worth a negative test?

## R-01-012 — Security layer: OSCORE (RFC 8613) for CoAP; DTLS 1.3 for MQTT-SN (§2, no kw)

- Classification: divergent (confidence high).
- Evidence: OSCORE implemented+tested in all stacks (lichen-oscore crate; C
  subsys/lichen/oscore + tests oscore, oscore_persist; Py coap secure
  channel; vectors oscore_schc_roundtrip.json). DTLS is entirely absent: the
  only trace is rust/lichen-core/src/constants.rs:34 `PORT_COAP_DTLS = 5684`
  commented "Reserved, not used (OSCORE instead)" and the corresponding C
  udp_port_dispatch reserved entry; rg dtls finds no DTLS code.
- Questions: (1) Is "DTLS 1.3 for MQTT-SN" a spec erratum (the operative
  project decision is OSCORE-everywhere, per the code comment and AGENTS.md
  "OSCORE for CoAP — end-to-end encryption, not just link-layer"), or a real
  planned feature for MQTT-SN deployments? (2) If erratum: amend §2 and the
  §1.1 security row together. (3) If real: 07-transport sweep should own the
  gap bead once MQTT-SN gateway work (R-08N-004) lands, since DTLS without
  an MQTT-SN endpoint is untestable.

## R-01-015 — Routing: RPL DODAG; local 02xx preference before Yggdrasil gateway forward (§2, no kw)

- Classification: implemented+tested (confidence low — Rust-only evidence).
- Evidence: Rust implements exactly the stated preference: DAO-learned
  is_local_mesh check before upstream forwarding (gateway.rs:1539-1558),
  forward_mesh_to_upstream lichend.rs:914-951, test
  dao_route_makes_ygg_address_local end_to_end.rs:2403-2435. C gateway
  forwarding.c shows no local-preference gate on the searches run (rg
  local|0x02|prefix clean); Python is simulator-level with no TUN path.
- Questions: (1) Is the C/Zephyr gateway expected to implement the 02xx-local
  preference (i.e., is C absence a gap), or is the Rust gateway the sole
  BR/backhaul implementation (same scoping question as R-04-010)? (2) Does
  forwarding.c handle backbone egress at all, and if so by what rule — the
  file exists (cross-ref R-08N-003 forwarding.c:45-91) but no
  local/0200::/8-specific logic was found on this pass.

## Additional observation (not a row flag) — §2 MAC row vs spec 02a

R-01-018 classifies implemented+tested with high confidence (CSMA/CA
satisfies "TSCH or CSMA/CA"), so it is not formally flagged. But the §2
diagram names only "TSCH (RFC 7554) or CSMA/CA" while the implementation (and
spec/02a-coordinated-capacity.md) centers on TDMA slotframes
(lichen/subsys/lichen/link/tdma.c, CONFIG_LICHEN_TDMA, tdma_tx_allowed in the
TX path). The architecture diagram appears stale relative to 02a. Suggest the
02a sweep or a spec erratum update the §2 MAC row to "TDMA (02a) or
CSMA/CA"; TSCH itself is absent from all stacks.
