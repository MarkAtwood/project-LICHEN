## spec/08-nodes.md — coverage (sweep 2026-08-31)

16 requirements extracted (0 RFC 2119 keyword rows — the section is
definitional: 15 keyword-less behavioral rows + 1 explicit MAY). IDs are
`R-08N-NNN` because `R-08-NNN` is already consumed by the
spec/08-gateway-coordination sweep above; spec headings are internally
numbered §11.x. Gap beads filed under epic `project-LICHEN-worker6-b7z9`,
labels `rpl`/`gateway` + `spec-gap`: **0** (no MUST rows; keyword-less
divergences noted in matrix per preamble, not beaded). Gap-bead overflow: 0
(0 MUST-gaps; cap 10). The NTP half of R-08N-015 is already beaded as
`project-LICHEN-worker6-b7z9.20` (spec 09 14.6 NTS/Roughtime).

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-08N-001 | Leaf role: Host IPv6, RPL Leaf, does not forward (§11.1) | divergent | Rs: `RplRole::Leaf` exists but is a DAO-TX gate only — leaf transit forwarding ungated receive.rs:259-291, leaf relays child DAOs node.rs:584-630, leaf sends DIOs router.rs:840-864 (`lichen-node/src/rpl_stack/`). C: leaf is a CoAP /config string only (`LICHEN_CONFIG_ROLE_LEAF` coap_config.h:41-43), zero RPL consumers (rg verified). Py: no leaf concept (DodagRole UNJOINED/JOINED/ROOT dodag.py:125-130) | high |
| R-08N-002 | Router role: full RPL participation, maintains neighbor/routing state, forwards (§11.1, §11.3) | implemented+tested | Rs: NeighborTable router.rs:514-558, transit forward receive.rs:259-291, RH3 relay receive.rs:323-371 (tests routing/tests.rs:87 router_joins_on_dio, :1318 eviction); C: parents[] rpl_dodag.h:118, `lichen_router_route` router.c:207-259 (tests routing_dispatch/main.c:153-384); Py: GradientTable router.py:520-568, FORWARD branch node.py:1007-1035 (test_node.py:2129 hop-limit). Downward routing state is root-only per non-storing MOP=1 (Rs router.rs:898-906) | high |
| R-08N-003 | Border Router: RPL Root, identity-preserving backhaul (§11.1) | implemented+tested | Rs: `provision_root` gateway.rs:985-990, DODAGID=own addr router.rs:220-263, mesh→upstream writes decompressed original IPv6 to TUN verbatim lichend.rs:947-951 (no NAT code, rg clean); e2e end_to_end.rs:283,323 pings both directions. C: `lichen_rpl_dodag_init_root` dodag.c:258-276, backhaul forwarding forwarding.c:45-91, tunnel_auth tests. Py: root classes dodag.py:306-323; no TUN/backhaul (sim-level only) | high |
| R-08N-004 | Gateway role: Host, RPL None, L7 protocol translator MQTT-SN→MQTT (§11.1) | not-implemented | No MQTT broker bridge in any stack: Rs port dispatch+codec only (port_dispatch.rs:30-44, SCHC Rule 7 codec.rs:1041-1133); Py wire codec only (mqttsn/messages.py); C SCHC tests only (lichen/tests/schc_mqtt_sn). No hits for broker/MQTT client libs, port 1883; only gateway binaries are RPL-root BRs (`lichend`, C gateway app) | high |
| R-08N-005 | Leaf joins through one preferred RPL parent (§11.2) | implemented+tested | Rs: `select_parent` MRHOF single parent dodag.rs:699-769 (`three_rpl_stacks_send_leaf_dao_via_preferred_parent` tests.rs:1595 asserts preferred_parent); C: `lichen_rpl_dodag_select_parent` dodag.c:273-373 (rpl_dodag tests :697-818); Py: dodag.py:685-722 (test_dodag.py:76-99) | high |
| R-08N-006 | Leaf sends DAO for its native /128 (§11.2) | divergent | Rs: full path `send_dao` transmit.rs:117-154, signed DAO via preferred parent router.rs:788-817; vectors rpl_route_state.json canonical leaf DAO (Rs rpl_route_state_vectors.rs:306, C rpl_routing/main.c:271-282). C: builder library only (`build_dao` self-target /128 rpl_dao_build.c:188-247, LICHEN_RPL_LEAF_DAO_LEN rpl_routing.h:557) + TX-manager tests (rpl_routing/main.c:247-376) but no app caller — no shipped C node ever sends a DAO. Py: `DaoManager.build_dao` dao_manager.py:442-458 zero callers (rg verified) | high |
| R-08N-007 | Leaf does not relay RPL or data traffic (§11.2) | divergent | No forwarding gate anywhere: Rs receive.rs:259-291 forwards regardless of role (no Leaf check), leaf DAO relay node.rs:584-630; C router.c:207-259 forwards for anyone (config leaf string unwired); Py node.py:1007-1035 unconditional FORWARD. Same site as R-08N-001 | high |
| R-08N-008 | Leaf sends all traffic via default parent (§11.2) | implemented+tested | Rs: route_for fallback to preferred_parent mod.rs:202-208 (from_parent guard prevents loop); used by send_ipv6 transmit.rs:173-178. C: `route_external` requires is_joined, next_hop=preferred_parent router.c:179-205. Py: `_route_external` router.py:570-601. Tests: Py test_router.py:242 test_external_with_parent_forwards, :226 no-parent-drops; Rs routing/tests.rs:87 | high |
| R-08N-009 | Router maintains neighbor table and routing state (§11.3) | implemented+tested | Same sites as R-08N-002; ETX-driven: Rs `update_with_coords_and_eviction` router.rs:548-555 (test :108 measured_etx), C dodag.c:122-168, Py GradientTable | high |
| R-08N-010 | Router forwards packets for children (§11.3) | implemented+tested | Rs receive.rs:259-291 + relay_forwards_original_source_and_signed_body tests.rs:1503, rfc6554_route_crosses_two_relays :420; C routing_dispatch tests :206-308; Py test_node.py:2129-2180 | high |
| R-08N-011 | Router sends DIOs, processes DAOs (§11.3) | divergent | Rs: non-root DIOs propagate (build_authenticated_dio non-root branch router.rs:840-864, trickle runtime.rs:119-136, DIS-unicast receive.rs:559-582) + DAO relay node.rs:584-630 — conformant, tested. C: DIO TX root-only (`lichen_rpl_dio_write` callers = gateway rpl_root.c:195 + tests only); no DAO relay, DAO processing root-only. Py: `build_dio` dodag.py:362 has no caller (node never sends DIOs); `process_dao` library-only (zero node-loop callers) | high |
| R-08N-012 | Border Router is DODAG root (§11.4) | implemented+tested | Rs: as_root dodag.rs:290-326, gateway provisions root gateway.rs:985-990 (tests five_node_dodag_forms mesh_formation.rs:74, gateway_dio_carries_root_metadata end_to_end.rs:387); C: dodag.c:258-276 + rpl_root.c:119-251 (rpl_dodag tests :513-577); Py: dodag.py:306-323 (test_root_construction :52, test_root_ignores_dio :59) | high |
| R-08N-013 | BR installs native /128 host routes from DAOs (§11.4) | implemented+tested | Rs: `rebuilt_routes` host-route loop routing.rs:1767-1816, /128 target validation :644 (tests downward_routes_assembled_from_daos mesh_formation.rs:131, dao_prefix_authorization suite); C: rebuild inserts host routes rpl_dao_process.c:709-711, prefix_len=128 routing_table.c:97-99 (rpl_dao_auth tests :197-541); Py: dao_paths.py:162 host route insert (test_dao.py:221-458) | high |
| R-08N-014 | BR provides application gateways and optional backhauls (§11.4) | divergent | Backhaul: Rs TUN + verbatim forwarding (tun.rs:30-194, lichend.rs:914-956, e2e tests) + C WiFi backhaul/forwarding (forwarding.c:45-91) + tunnel_auth both; Py none. Application gateway: Py CoAP forward proxy only (proxy.py:47-80, test_proxy.py); Rs/C none (Rs proxy parser-only codec.rs:328). MQTT-SN→MQTT absent everywhere (see R-08N-004) | high |
| R-08N-015 | BR runs Resource Directory, NTP (§11.4) | divergent | RD: Py only — RFC 9176-simplified `/rd` + `/rd-lookup/res` resource_directory.py:123-160, site.py:249-256, vectors coap_rd.json + TestResourceDirectoryVectors (test_vector_files_consume.py:569-800); Rs: no /rd anywhere (rg clean); C: no /rd. NTP: absent in all stacks (DIO-carried mesh time instead: Rs time_option.rs:69-120, C time_sync.c:43-215, Py time_sync.py); NTS/Roughtime gap already beaded `project-LICHEN-worker6-b7z9.20` | high |
| R-08N-016 | BR may aggregate multiple DODAGs (§11.4) — explicit MAY | not-implemented | Single DODAG state per node in all stacks (Rs Router one `dodag` router.rs; C root struct one dodag rpl_root.c:105-117; Py single DodagState). `multi_instance*` is GCP-5 multi-root federation (each gateway roots its OWN DODAG, shared RPLInstanceID), not one BR aggregating several — multi_instance.rs:1-22 | high |

### Histogram (rows)

- implemented+tested: 8 (R-08N-002, 003, 005, 008, 009, 010, 012, 013)
- implemented+untested: 0
- divergent: 6 (R-08N-001, 006, 007, 011, 014, 015)
- not-implemented: 2 (R-08N-004, R-08N-016 — the latter an explicit MAY, absence conformant)
- ambiguous: 0

### Gap beads filed (0; cap 10; overflow 0)

No MUST rows exist in this section, so no gap beads are due per the matrix
preamble. Keyword-less divergences (R-08N-001/007 leaf non-forwarding
unenforced, R-08N-006 node-level DAO sending unwired in C/Py, R-08N-011 C/Py
routers send no DIOs / process no DAOs, R-08N-014 app-gateway asymmetry,
R-08N-015 RD absent in Rs/C + NTP absent) are noted in the matrix, not
beaded; see flagged set for Opus verification. R-08N-004 (Gateway
MQTT-SN→MQTT translator, whole-role absence) is the largest gap — the
07-transport/18-applications sweeps own the normative MQTT-SN text and may
bead it; the NTP half of R-08N-015 is pre-beaded as
`project-LICHEN-worker6-b7z9.20`.
