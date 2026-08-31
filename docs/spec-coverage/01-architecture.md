## spec/01-architecture.md — coverage (sweep 2026-08-31)

19 requirements extracted (0 RFC 2119 keyword rows — the section is
definitional/architectural: §1.1 layer-standards table, §1.2 design goals,
§1.3 non-goals, §2 protocol-stack diagram; all 19 rows are keyword-less
normative). Same situation as spec/08-nodes: no MUSTs → gap beads filed: **0**
(keyword-less divergences noted in matrix per preamble, not beaded). Gap-bead
overflow: 0 (0 MUST-gaps; cap 10). Cross-section ownership: the SCHC size
number (R-01-003) belongs to the 03-adaptation sweep; MQTT-SN/DTLS normative
text (R-01-005/011/012) to 07-transport; frame/PHY detail (R-01-017/019) to
02-physical-link. Note: Meshtastic/MeshCore *bridge adapters* exist
(rust/lichen-meshtastic, lichen/subsys/lichen/{meshtastic,meshcore},
python interface/meshtastic) — application-level translation, not wire
backward compatibility; see flagged set.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-01-001 | Every protocol layer uses an existing IETF standard (SCHC 8724, IPv6 8200, RPL 6550, OSCORE 8613 + custom LLSec, UDP 768, CoAP 7252; MQTT-SN OASIS) (§1.1) | implemented+tested | Umbrella row — per-layer implementations all exist and are vector-tested: Rs crates lichen-{schc,ipv6,rpl,oscore,coap,link}; C lichen/subsys/lichen/{schc,routing,oscore,coap,link}; Py lichen/{schc,ipv6,rpl,coap,link}. Layer detail rows R-01-011..019 and the per-section sweeps | high |
| R-01-002 | Real IPv6: globally routable addresses, not proprietary node IDs (§1.2.1) | implemented+tested | Key-derived 0200::/8 + fe80::/10 IIDs in all stacks with independent-oracle vectors — cross-ref R-04-003/004 (yggdrasil-derivation.json, ipv6-addresses.json; Rs addr.rs:109-117, Py identity.py:206-234, C identity_addr.c:49-68). Proprietary node-num IDs exist only inside the Meshtastic bridge adapters, not the LICHEN protocol | high |
| R-01-003 | Efficient: SCHC compresses headers to 6-15 bytes (§1.2.2) | divergent | Measured compressed IPv6/UDP headers are 21-33 B, never ≤15 B: test/vectors/schc_compression.json (27 cases; minimum 48 B packet → 21 B compressed); schc_adaptation.json compressed_size rule2=23, rule3=40, rule4=37 B. AGENTS.md records 18-33 B. No rule in any stack reaches 6-15 B. Keyword-less: noted, not beaded — flagged; 03-adaptation sweep should own the number | high |
| R-01-004 | Authenticated: every packet cryptographically signed (§1.2.3) | implemented+tested | C TX always signs (S+SI bits unconditional lichen_link_tx.c:165; sign+append :208-233; relay_raw :302,336-361) and RX rejects unsigned at the authenticated boundary (lichen_link_rx.c:72). Rs: error doc "all LICHEN frames must be signed" lichen-link/src/link_layer.rs:34. Py: sign-on-TX link_layer.py:11,43. Tests: lichen/tests/frame, link_crypto, replay; vectors schnorr48.json | high |
| R-01-005 | Interoperable: standard CoAP/MQTT-SN applications work unmodified (§1.2.4) | divergent | CoAP: full servers+clients in all stacks (C coap_server.c:52; Py coap/udp_server.py:27-50; Rs lichen-coap — see 11-lci sweep). MQTT-SN: codec + port dispatch only (Py mqttsn/codec.py+messages.py; Rs port_dispatch.rs MqttSn + SCHC Rule 7 codec.rs:1041-1133; C tests/schc_mqtt_sn) — no MQTT-SN gateway/broker endpoint (rg 1883\|broker clean), so a standard MQTT-SN client has no counterpart; cross-ref R-08N-004 | high |
| R-01-006 | Mesh: RPL multi-hop routing without central coordination (§1.2.5) | implemented+tested | Rs five_node_dodag_forms mesh_formation.rs:74 + transit forwarding receive.rs:259-291; C routing_dispatch tests main.c:206-308; Py test_node.py:2123-2180. Cross-refs R-08N-002/005/008/010/012. (C non-root routers send no DIOs / Py never sends DIOs — R-08N-011 — but the multi-hop data plane is demonstrated in e2e) | high |
| R-01-007 | Gateway-friendly: border routers connect mesh to internet (§1.2.6) | implemented+tested | Rs TUN gateway: forward_mesh_to_upstream lichend.rs:914-956 + cross-mesh e2e pings end_to_end.rs:283,323; C forwarding.c:45-91 backhaul; Py simulator-level only. Cross-ref R-04-010 | high |
| R-01-008 | Non-goal: no backward compatibility with Meshtastic or MeshCore (§1.3) | implemented+untested | Wire protocol deliberately incompatible: LORA_SYNC_WORD 0x34 "Distinct from Meshtastic (0x2B)" (Py constants.py:11; Rs constants.rs:4; C radio default pinned lichen/tests/coap_config/src/main.c:589,708) + custom frame format with Schnorr-48 link signatures. Bridge adapters exist (rust/lichen-meshtastic IP_TUNNEL_APP portnum 33; C subsys/lichen/{meshtastic,meshcore} + lichen/tests/meshtastic_*, meshcore_*; Py interface/meshtastic/adapter.py) — translation gateways, not wire compat. No test asserts non-interoperability | low — flagged: adapters vs non-goal |
| R-01-009 | Non-goal: no support for non-IP protocols (§1.3) | implemented+untested | Conformant by absence: single IPv6 dispatch path in all stacks (LICHEN_L2_DISPATCH_SCHC lichen_link_tx.c:150; no non-IP payload path found, rg clean). No negative test | high |
| R-01-010 | Non-goal: no complex QoS or traffic engineering (§1.3) | implemented+untested | Conformant by absence: no QoS/TE machinery (rg clean). TDMA/CCP (link/tdma.c, ccp) are MAC capacity coordination per spec 02a, not QoS | high |
| R-01-011 | Application layer: CoAP, MQTT-SN, Raw UDP, ICMPv6 (§2) | divergent | CoAP implemented+tested (R-11-010..015). Raw UDP: udp_port_dispatch subsystem + lichen/tests/udp_port_dispatch + Rs port_dispatch_vectors.rs + Py test_port_dispatch.py + vectors port_dispatch.json. ICMPv6 implemented+tested (R-04-016). MQTT-SN codec-only (same site as R-01-005) | high |
| R-01-012 | Security layer: OSCORE (RFC 8613) for CoAP; DTLS 1.3 for MQTT-SN (§2) | divergent | OSCORE implemented+tested in all stacks (lichen-oscore crate; C subsys/lichen/oscore + tests oscore, oscore_persist; Py coap secure channel; vectors oscore_schc_roundtrip.json; cross-ref R-11-047). DTLS absent: Rs PORT_COAP_DTLS comment "Reserved, not used (OSCORE instead)" constants.rs:34; rg dtls clean everywhere. Keyword-less: not beaded; flagged (07-transport owns) | high |
| R-01-013 | Transport: UDP (RFC 768) compressed via SCHC (§2) | implemented+tested | C schc.c:6 "rules 0-7" IPv6/UDP + tests schc_rule1..6_{compress,decompress}; Rs lichen-schc tests rule5/rule6_{compression,decompression}.rs + adaptation_vectors.rs; Py tests/schc; vectors schc_compression.json | high |
| R-01-014 | Network: IPv6 (RFC 8200) compressed via SCHC; link-local fe80::/10 + key-derived native 0200::/8 (§2) | implemented+tested | Same SCHC sites as R-01-013 (every rule is IPv6-based); both address families implemented+vector-tested — cross-ref R-04-003/004 and R-11-007 | high |
| R-01-015 | Routing: RPL DODAG; local 02xx preference before Yggdrasil gateway forward (§2) | implemented+tested | Rs: is_local_mesh DAO-gated check before upstream forward gateway.rs:1539-1558, forward_mesh_to_upstream lichend.rs:914-951, test dao_route_makes_ygg_address_local end_to_end.rs:2403-2435; DODAG formation cross-ref R-08N-012. C gateway forwarding.c: no local-preference gate found (rg clean) — Rust-only evidence | low — flagged |
| R-01-016 | Adaptation: SCHC (RFC 8724) compression and fragmentation (§2) | implemented+tested | C tests schc_fragment_generation, schc_ack_processing, schc_reassembly; Rs fragment.rs + tests/{fragmentation,fragmentation_vectors,reassembly_state_machine}.rs; Py schc/reassembly.py + session_manager.py + tests/schc; vectors schc_fragmentation.json, schc_tile_sizing.json | high |
| R-01-017 | Link security: Ed25519 signatures (truncated) + replay protection (§2) | implemented+tested | 48-B Schnorr48: vectors schnorr48.json; C link/schnorr48.c + tests schnorr48, frame; Rs lichen-link schnorr.rs; Py crypto/schnorr48.py. Replay: C link/replay.c + tests replay, replay_persist; Rs seqnum.rs:65-68; Py link/replay.py (handoff-floor wiring gap tracked as R-08-033/034) | high |
| R-01-018 | MAC: TSCH (RFC 7554) or CSMA/CA (§2) | implemented+tested | CSMA/CA implemented+tested: C link/csma.c + tests csma, csma_constants; Py timing/csma.py + tests/timing; Rs csma_constants_vectors.rs + tx_queue.rs; CCA gate in TX path lichen_link_tx.c:184-194. TSCH absent (rg clean) — the "or" is satisfied. TDMA (spec 02a) also implemented (link/tdma.c) but absent from this §2 diagram — spec-coherence note in flagged file | high |
| R-01-019 | Physical: LoRa CSS (Semtech SX126x/SX127x) (§2) | implemented+untested | Rs lichen-embassy/src/esp32s3.rs:13-27 Sx1262Radio wrapping the lora-phy SX126x driver + stm32wl.rs; C radio models SX126X/SX127X/LR1110 with BUILD_ASSERTs hal_caps.c:79-104 + drivers/lora/lr1110 + lora_sim.c + lora_renode.c; Py board_intake.py:49-52 maps SX1262/SX1272/SX1276/SX1278. No host-exercisable radio tests (hardware validation is bench-level) | high |

### Histogram (rows)

- implemented+tested: 11 (R-01-001, 002, 004, 006, 007, 013, 014, 015, 016, 017, 018)
- implemented+untested: 4 (R-01-008, 009, 010, 019)
- divergent: 4 (R-01-003, 005, 011, 012)
- not-implemented: 0
- ambiguous: 0

### Gap beads filed (0; cap 10; overflow 0)

No MUST rows exist in this section (0 RFC 2119 keywords), so no gap beads are
due per the matrix preamble. The keyword-less divergences are noted above, not
beaded: R-01-003 (SCHC 6-15 B claim vs measured 21-33 B — 03-adaptation sweep
should own), R-01-005/011 (MQTT-SN codec-only — 07-transport sweep should own,
consistent with R-08N-004), R-01-012 (DTLS 1.3 for MQTT-SN absent; code
comment says OSCORE-everywhere is the operative decision — 07-transport
sweep should own). Adjacent evidence notes: no pre-existing beads are
duplicated by this sweep.
