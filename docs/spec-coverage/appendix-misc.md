# spec/appendix-misc.md — coverage sweep

## spec/appendix-misc.md — coverage (sweep 2026-09-09)

Scope note: this appendix contains **no RFC 2119 keywords**. Every row below is
an implied-by-example requirement (Appendix C wire examples, Appendix E traffic
flows). The normative owners of the same subject matter are spec 07 §10.6 and
appendix-senml F.15 (RD) and spec 07 §10.4 / 08-nodes §11.1 (MQTT-SN gateway);
cross-references given per row. Appendix D is a comparison table with no
normative content.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|--------------------|--------|----------|------------|
| R-APXM-001 | C.1: `POST coap://[6lbr]/rd?ep=node-001&lt=86400` with `Content-Format: application/link-format` payload | divergent | Py-only RD: `python/src/lichen/coap/resources/resource_directory.py:123`, `render_post` :252-300 (ep mandatory :274-275, lt default 86400 bounds :260-270, 2.01 Created + Location-Path :298-299) — but registration body is decoded as **CBOR** (`_decode_single_cbor` :280; docstring :127-128), NOT `application/link-format` as the example specifies. Tests: `TestRdPost` (python/tests/coap/test_resource_directory.py:53-158); vectors `test/vectors/coap_rd.json` (15 cases, TestResourceDirectoryVectors test_vector_files_consume.py:569-800). Rust: no `/rd` (rg clean); C: no `/rd`. Cross-ref: R-07-046, R-08N-015 (same classification, un-beaded) | high |
| R-APXM-002 | C.2: `GET coap://[6lbr]/rd-lookup/res?rt=temperature` returns matching links | implemented+tested | Py: `_RdLookupResource` at `/rd-lookup/res` resource_directory.py:357-392, filters rt/ep/href/if with RFC 6690 star matching (:79-109); opt-in mount `build_site(resource_directory=True)` site.py:51,165. Tests: `TestRdLookup.test_lookup_by_rt_returns_matching_links` (test_resource_directory.py:459), `test_lookup_rt_prefix_star` :517, `test_rd_lookup_not_exposed_by_default` :753; vectors coap_rd.json (`test_rd_lookup_res_by_rt`, test_vector_files_consume.py:725). Rust/C absent (folded into R-APXM-001 bead) | high |
| R-APXM-003 | Appendix D: comparison table (topology, hops, overhead, auth/encryption, FS) | n/a (informational) | No normative content. Claims consistent with spec 03 (18-33 byte compressed baseline) and 06 (OSCORE, Ed25519). Footnote `**Can add EDHOC for session keys` flagged for Opus (see flagged file) | high |
| R-APXM-004 | E flow 1: `Leaf 1 -> Border Router: CoAP response with temperature (upward via RPL)` | implemented+tested | Rust: upward default route to preferred parent `rust/lichen-node/src/rpl_stack/mod.rs:315-324` + transit forwarding receive.rs:278-298; Py: `next_hop_upward` python/src/lichen/rpl/routing.py:295-297 + router.py:568-599; C: `route_external` lichen/subsys/lichen/routing/router.c:179-205. Tests: `three_rpl_stacks_send_leaf_dao_via_preferred_parent` (rpl_stack/tests.rs:1658), `test_next_hop_upward_is_preferred_parent` (python/tests/rpl/test_routing.py:181), `test_external_with_parent_forwards` (python/tests/routing/test_router.py:261) | high |
| R-APXM-005 | E flow 2: `Root -> Leaf 4: CoAP request (downward via source routing)` | implemented+tested | Rust: root DAO route table `rust/lichen-rpl/src/routing.rs:417`, SRH codec `rust/lichen-rpl/src/srh.rs:31-89`, root emission `rust/lichen-gateway/src/gateway.rs:1826-1936`; Py: `insert_source_route` python/src/lichen/rpl/routing.py:300-360 + node.py:1093-1172; C: SRH codec/advance `lichen/subsys/lichen/rpl/rpl_srh.c:23,124` + consumption router.c:458-510 — **C root-side insertion unwired** (already beaded: worker6-pqxd, -j8b7, -nd1h; see 05-routing-flagged). Tests: `root_originated_downward_srh` (gateway.rs:2928), `canonical_root_insertion_vectors_match` (srh_root_insertion_vectors.rs:33, drives test/vectors/srh_root_insertion.json), `test_source_route_end_to_end_traversal` (python/tests/rpl/test_routing.py:210), lichen/tests/rpl_srh/main.c | high |
| R-APXM-006 | E flow 3: `Leaf 3 -> MQTT Broker: MQTT-SN PUBLISH (via gateway at border router)` | not-implemented | No MQTT-SN→MQTT broker bridge in any stack (rg `broker|1883|paho` clean across rust/, lichen/, python/src/). Present: Py MQTT-SN 1.2 codec (mqttsn/messages.py, gateway-role ADVERTISE/SEARCHGW/GWINFO types :397-425), port dispatch + SCHC Rule 7 in all 3 stacks (rust/lichen-core/src/constants.rs:38, port_dispatch.rs:234; C schc_compress.c:382; tests lichen/tests/schc_mqtt_sn, vectors mqtt_sn.json). No broker connection behind the codec anywhere. Cross-ref: R-07-042 (divergent), R-08N-004 (not-implemented) — both sweeps deferred beading to the owner; this sweep filed the bead | high |
| R-APXM-007 | E diagram: every node (BR, routers, leaves) carries a routable `native /128` | implemented+tested | Node /128 = upstream Yggdrasil `AddrForKey(Ed25519)` in all three stacks: `rust/lichen-core/src/addr.rs:113-152`, `python/src/lichen/ipv6/addr.py:207-245`, `lichen/subsys/lichen/link/identity_addr.c:55-117`. Oracle: `test/vectors/yggdrasil_address.json` (upstream anchor verbatim from yggdrasil-go@422836ee); byte-equality tests: `upstream_anchor_byte_equality` (lichen-core/tests/yggdrasil_addr_vectors.rs:138), `test_upstream_anchor_byte_exact_through_production` (python/tests/crypto/test_yggdrasil_address_vectors.py:134), pubkey_to_iid/main.c:197-199. Consistent with settled decision `upstream-yggdrasil-addressing` (spec/decisions.jsonl) — "native /128" reads as the node routable /128, no conflict | high |

### Histogram (rows)

- implemented+tested: 3 (R-APXM-002, 004, 007)
- implemented+untested: 0
- divergent: 1 (R-APXM-001)
- not-implemented: 1 (R-APXM-006)
- ambiguous: 0
- informational: 1 (R-APXM-003)

### Gap beads filed (2; cap 10; overflow 0)

1. R-APXM-006 — MQTT-SN→MQTT broker gateway bridge at border router absent in
   all stacks (`project-LICHEN-worker6-b7z9.211`, labels spec-gap/gateway/mqttsn).
   Filed here because R-07-042, R-08N-004 and 12-apps each deferred it and no
   bead existed.
2. R-APXM-001 — RD registration payload divergent (Py CBOR vs
   application/link-format example / RFC 9176 default) + RD absent in Rust/C
   (`project-LICHEN-worker6-b7z9.212`, labels spec-gap/coap). R-07-046/
   R-08N-015 classified it twice, never beaded.

### Notes

- Step 0: no decision in `spec/decisions.jsonl` lists `appendix-misc.md`; no
  verify checks applied. The example's "native /128" wording is consistent with
  the `upstream-yggdrasil-addressing` decision (not re-adjudicated here).
- SHOULD-level gap: RD lookup (R-APXM-002) is Python-only and opt-in
  (`resource_directory=True` off by default) — omission breaks the documented
  6LBR feature in Rust/C, folded into the R-APXM-001 bead rather than a
  separate one.
- MAYs: none in section; none filed.
