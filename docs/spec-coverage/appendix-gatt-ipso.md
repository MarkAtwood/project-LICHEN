<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

## spec/appendix-gatt-ipso.md — coverage (sweep 2026-09-09)

Scope note: Appendix K ("BLE GATT to IPSO/SenML Mapping") is a translation
table appendix. K.1 (overview diagram), K.6/K.7 (worked SenML/IPSO-Direct
examples) and the mapping tables K.2/K.3 contain **zero** RFC 2119 keywords
except one sentence: K.2 "A device exposing a GATT Service SHOULD be
represented as one or more IPSO Object instances" — the tables are the payload
of that SHOULD and are folded into R-GATT-001 rather than given per-row entries
(one implementation site: a GATT→IPSO gateway translator, which does not
exist). K.4 is a keyword-less reservation declaration (R-GATT-002); K.8 is a
keyword-less negative mapping statement (R-GATT-009); K.9.1 and K.9.5 are
keyword-less imperatives (R-GATT-004, R-GATT-008). The only MUSTs are K.5
(R-GATT-003) and K.9.2 (R-GATT-005); K.9.3 is a MAY (R-GATT-006) and K.9.4 a
SHOULD (R-GATT-007). Note line 291 self-describes the appendix as
"informational" — the normative-force question is flagged for Opus. Req IDs
use `R-GATT-NNN` (GATT = appendix-gatt-ipso).

Step 0: `spec/decisions.jsonl` contains no decision whose `specs` array lists
`appendix-gatt-ipso.md` — no verify greps to run, no spec regression to fix.

Headline: the BLE GATT relay feature this appendix specifies is **absent from
all three stacks**. Every BLE code path found is transport, not sensor mapping:
Meshtastic GATT service emulation (rust/lichen-meshtastic/src/gatt.rs:1-20,
custom ToRadio/FromRadio/FromNum UUIDs), KISS-over-BLE GATT
(rust/lichen-kiss/src/ble.rs, python/src/lichen/interface/kiss/gatt.py,
interface/meshtastic/gatt.py), LCI SLIP-over-GATT
(python/src/lichen/gateway/ble_lci.py:1-10, client/ble.py), IPSP IPv6-over-BLE
(lichen/subsys/lichen/transport/ble_ipsp_transport.c), C gateway BLE
(lichen/apps/gateway/src/ble_meshtastic.c, ble_meshcore.c, ble_uart.c). The
conformance vectors `test/vectors/ble_gatt_reassembly.json` self-reference
spec/kiss-framing.md (transport framing/reassembly), not this appendix.
Absence greps (rust/, lichen/, python/src/, firmware/, c/): GATT sensor
characteristic UUIDs `2a37|2a6e|180d|1809|2a19|180f|181a|2a6f` → zero real
hits (only hex-literal coincidences in oscore/trust/schnorr test keys); IPSO
extension IDs `\b2625[0-9]\b` → zero; conversion constants
`133\.322|0\.453592|0\.3048|0\.44704|mmHg` → zero (only unrelated compact_cot
centidegrees); CoRE link-format `anchor=` attribute and `rt="ipso"` → zero
(only trust-anchor false positives); `lwm2m` (case-insensitive) → only
docstrings in the two IPSO modules.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-GATT-001 | A device exposing a GATT Service SHOULD be represented as one or more IPSO Object instances (K.2; K.3 characteristic tables are the mapping payload) | not-implemented | No GATT sensor-characteristic UUID appears in any stack (absence greps above). Closest partial support is IPSO vocabulary for 7 of the ~30 mapped objects — `ObjectId` enum {3303, 3304, 3313, 3315, 3323, 3334, 3336} rust/lichen-senml/src/ipso.rs:15-23,51-94 and mirror python/src/lichen/senml/ipso.py:26-35,63-105 (re-export python/src/lichen/senml/__init__.py:5-21); tested: python/tests/senml/test_ipso.py:30-105 (8 tests incl. test_known_ids_match_oma_registry, test_shared_positive_vectors, test_resource_specific_units) and rust/lichen-senml/tests/ipso_vectors.rs:55,88, both against test/vectors/ipso_smart_objects.json. Heart Rate 3346, Load 3322, Concentration 3325, Power 3328, Positioner 3337, Magnetometer 3314, Digital Input 3200, LwM2M Device 3 and every service-level mapping (K.2 table) are absent; the Rust IPSO module has no production caller (only its own test imports it) | high |
| R-GATT-002 | IPSO object IDs 26250-26299 are reserved for LICHEN BLE extensions not covered by the OMA registry (K.4; keyword-less reservation + 10-object table) | not-implemented | rg `\b2625[0-9]\b` across rust/, lichen/, python/src/, firmware/, c/, test/ → zero hits: no code defines, registers, or squats on the extension range. No GATT relay exists to consume the vocabulary (see R-GATT-001). Classification-bucket question flagged (flagged file #1): a reservation with no implementing feature is arguably vacuous rather than "not-implemented" | high |
| R-GATT-003 | Gateways MUST convert to SenML canonical units before transmission (K.5, with 10-row conversion table) | not-implemented | No conversion code in any SenML stack: rg `133\.322|0\.453592|0\.3048|0\.44704|mmHg|centidegree` → only compact_cot course_centidegrees (unrelated, CoT PLI); python/src/lichen/senml/ and rust/lichen-senml/src/ contain no conversion module (rg `convert|conversion` → only IEEE-754 comment wire.rs:832); C lichen/subsys/lichen/senml/ likewise. Units are emitted as opaque strings (ipso.py:219, wire.rs Record.unit); no GATT gateway exists to host the conversion | high |
| R-GATT-004 | Multiple instances of the same characteristic: assign sequential IPSO instance IDs (3303/0, 3303/1) (K.9.1; imperative, no RFC 2119 keyword) | not-implemented | Policy site (GATT notification → instance assignment) absent with the relay (R-GATT-001). The record layer does accept caller-chosen instance IDs — IpsoPath(object_id, instance_id, …) python/src/lichen/senml/ipso.py:126-163,187-220, Path::resource rust/lichen-senml/src/ipso.rs:138-152 — and vectors pin non-zero instances (test/vectors/ipso_smart_objects.json "ipso-humidity-instance-two" 3304/2/5700, instance 4/7 cases); but nothing assigns them sequentially per BLE device | high |
| R-GATT-005 | Gateway MUST add bt (base time) at reception; if the device advertises Current Time Service (0x1805), prefer device time (K.9.2; second clause keyword-less, treated as SHOULD-strength) | not-implemented | Gateway-side obligation unimplementable: no BLE GATT notification receiver exists (R-GATT-001). The bt wire field itself is implemented+tested in all three stacks: rust/lichen-senml/src/wire.rs:35,166,302,440 (base_time, tests :934-1102); python/src/lichen/senml/codec.py label map (bt=-3) with test_full_fields_vector.py against test/vectors/senml_full_fields.json; C lichen/subsys/lichen/senml/include/lichen/senml.h:128-146,239-259 (base_time in pack+record encoders, lichen/tests/senml/). Current Time Service client: absent (absence greps). Note: appendix F.12 (relative_time.py:4-8) conditions bt on wall_clock_valid — consistent with "gateway adds bt" only at relay/gateway nodes, not constrained nodes | high |
| R-GATT-006 | Gateway MAY aggregate multiple GATT notifications into one SenML pack with relative timestamps (t field) (K.9.3, MAY) | not-implemented | MAY — never bead-filed. Pack machinery that the aggregation would use is implemented+tested: multi-record pack encode/decode with t offset — rust wire.rs pack tests (incl. base_time/t offsets), python lichen/senml/codec.py pack()/unpack() + relative_time.py:16-33 stamp_record (bt+t vs relative-t fallback, tested test_relative_time.py:2 tests), C senml.h:146,170 (time_offset from base_time); batched packs also used by rust/lichen-gateway/src/resources.rs:971-983 (encode_nodes_senml) and python SenMLSensorsResource (python/src/lichen/coap/resources/senml.py:12-37, /sensors observable). No GATT notification source exists to aggregate | high |
| R-GATT-007 | Gateway SHOULD cache last-known values and include staleness indicator in SenML (ut field for update time) (K.9.4) | not-implemented | ut wire field implemented+tested (machinery half): rust/lichen-senml/src/wire.rs:48,179,351,489 (update_time, tested via full-fields vectors), python/src/lichen/senml/codec.py:45,63 (label 7 = "ut"), C senml.h:245,259 (has_update_time). Cache-last-known-values half absent with the relay (no BLE value store in any stack). SHOULD-gap folded into umbrella bead project-LICHEN-worker6-b7z9.201 — the omission leaves the documented BLE-relay feature without its staleness story | high |
| R-GATT-008 | Gateway advertises relayed BLE devices in CoRE Link Format with anchor pointing to BLE MAC (`</3303/0>;rt="ipso";anchor="ble:aabbccddeeff"`) (K.9.5; imperative, no RFC 2119 keyword) | not-implemented | No link-format `anchor=` attribute support in any CoAP server/RD code: rg `anchor` in rust/lichen-coap/src, rust/lichen-gateway/src, python/src/lichen/coap/, lichen/subsys/lichen/coap/ → only trust-anchor false positives; `rt="ipso"` and `ble:` URI scheme → zero hits anywhere. /.well-known/core responders advertise LICHEN's own resources only (e.g. python/src/lichen/coap/resources/site.py) | high |
| R-GATT-009 | Device metadata (manufacturer, model, serial, firmware version) maps to LwM2M Device Object (ID 3), not IPSO sensor objects (K.8; keyword-less declaration; unmapped-characteristics table is the negative payload) | not-implemented | No LwM2M Device object (ID 3) in any stack: case-insensitive `lwm2m` matches only docstrings of the two IPSO modules. Nothing maps device metadata to object 3 — and trivially nothing violates the "not IPSO sensor objects" prohibition. Classification-bucket question flagged (flagged file #2) | high |

### Notes
- The appendix's two worked examples (K.6 heart-rate SenML pack + IPSO Direct
  PUT /3346/0/5700 CF=60; K.7 weather-station batch pack) are non-normative and
  carry no rows. Their machinery status: SenML pack wire format (bn/bt/n/u/v/t)
  implemented+tested in all three stacks (test/vectors/senml_labels.json,
  senml_full_fields.json; consumers python/tests/senml/test_label_vectors.py,
  test_full_fields_vector.py, rust/lichen-senml/tests/label_vectors.rs,
  full_fields_vectors.rs); IPSO path naming for arbitrary numeric paths works
  (Path::parse accepts any 2-3 component path, so "3346/0/5700" parses) but no
  CoAP server mounts IPSO-style /NNNN/0/NNNN resources, so the K.6 PUT
  alternative has no handler.
- The `test/vectors/ipso_smart_objects.json` description does not cite
  appendix-gatt-ipso.md; it is an OMA-registry naming vector set shared with
  the SenML work (appendix F). It covers only the 7-object subset.
- K.2's odd-looking rows (Speed and Cadence sharing UUID 0x2A53/0x2A5B, Blood
  Pressure "mmHg; convert to Pa") are consistent with the BT assigned-number
  reality (one measurement characteristic carrying several fields) and with the
  K.5 conversion table — no spec-internal contradiction worth flagging.
- Gap beads filed: **3** (2 MUST gaps: R-GATT-003, R-GATT-005; 1 umbrella
  feature gap covering the SHOULD/keyword-less rows R-GATT-001/002/004/007/008).
  Well under the 10-bead cap; no overflow. MAY (R-GATT-006) not filed.
  Flagged: **3** (appendix-gatt-ipso-flagged.md).
