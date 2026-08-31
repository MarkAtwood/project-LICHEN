# Spec Coverage Matrix

Per-section requirements-extraction sweeps against the LICHEN implementations
(C/Zephyr `lichen/`, Rust `rust/`, Python `python/src/`). Evidence format:
`C:`/`Rs:`/`Py:` = stack, `file:line`, test names, vector files.

Status vocabulary: implemented+tested | implemented+untested | divergent |
not-implemented | ambiguous. Confidence: high / low (low = wants second
opinion). Divergent and not-implemented MUSTs get gap beads (cap 10/section);
keyword-less normative rows are noted, not beaded; MAYs/SHOULDs never beaded
unless a documented feature breaks.

## spec/08-gateway-coordination.md — coverage (sweep 2026-08-31)

36 requirements extracted (24 MUST-bearing rows, 1 SHOULD, 1 OPTIONAL/RECOMMENDED,
10 keyword-less normative). Gap beads filed under epic `project-LICHEN-worker6-l1qw`,
labels `gcp` + `spec-gap`. Gap-bead overflow: 0 (all MUST-gaps covered; same-site
MUSTs share beads).

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-08-001 | Implementations MUST support both federation modes (GCP-1; GCP-10) | divergent | C: Kconfigs `LICHEN_GW_FEDERATION_*`+`LICHEN_GW_PSK` referenced by no code (lichen/apps/gateway/Kconfig:237-263); open primitives untested (lichen/subsys/lichen/gcp/gcp_trust.c:114-163). Rs: both engines+tests (trust.rs:1288-1381, gcp_psk_oscore_vectors.rs) but daemon refuses mode=open (lichend.rs:512); dual-mode none (config.rs:119-129 single enum). Py: trust oracle tested (crypto/trust.py, tests/crypto/test_trust.py) | low — gap bead `project-LICHEN-worker6-l1qw.15` |
| R-08-002 | Closed Federation (PSK) MUST be supported (GCP-3.1) | implemented+tested | Rs: PskFederation trust.rs:1288-1381 + tests/gcp_psk_oscore_vectors.rs (11 tests, `test/vectors/gcp_psk_oscore.json`); C: PSK/group OSCORE ctx coap_keys_oscore.c:77-118 untested; Py: `closed_federation_psk_derivation` vectors orphaned | high |
| R-08-003 | Open Federation (signatures) MUST be supported (GCP-3.2) | implemented+tested | Rs: verify_gateway_message/TOFU trust.rs:605-630,919-960 + unit tests :1829-2000 (gcp3_trust_models.json); C: gcp_trust.c:114-163 untested; Py: test_trust.py drives rotation subset | low — open mode not config-reachable (lichend.rs:512); C untested |
| R-08-004 | (no kw) Backbone discovery: multicast CoAP GET ff02::1 → /.well-known/lichen-gw/info; periodic + on-change Observe (GCP-4.1) | divergent | Rs: encoders + /info payload discovery.rs:37-159, resources.rs:546-721 + unit tests :366-431; nothing sends the GET or publishes Observe (no refs outside discovery.rs). C: none. Py: codec only (discovery.py:250-318); `gateway_discovery.json` orphaned | high |
| R-08-005 | (no kw) LoRa fallback: gateway announce frames include GATEWAY flag in link layer (GCP-4.2) | divergent | C: `LICHEN_GATEWAY_FLAG 0x80` routing/announce.h:41, announce.c:568-626 — untested, and it is the routing-payload type byte, not an LLSec flag. Rs/Py: standalone `LoraGatewayAnnounce` (discovery.rs:167-310; discovery.py:321-414) unused by real announce frames (rust/lichen-core/src/announce.rs:197 has no flag) | high |
| R-08-006 | (no kw) All cooperating gateways use same RPLInstanceID; each is DODAG root; unified DODAG (GCP-5) | implemented+tested | Rs: multi_instance.rs:320-958 + tests/multi_instance_vectors.rs (13, `rpl_multi_instance.json`) + ~45 unit tests; Py: multi_instance.py:137-657 + tests/rpl/test_multi_instance.py:817+; C: rpl_multi_instance.c:22-351 no dedicated test; caveat: none wired into a running gateway (lichen-core constants.rs:56 single fixed instance) | high |
| R-08-007 | (no kw) Superframe sync: GPS epoch; non-GPS elect time master (lowest IID); others sync via backbone CoAP; duration configurable (GCP-6.1) | divergent | GPS epoch + election tested: Py discovery.py:437-455 + test_gcp6_vectors.py:56-77, test_discovery.py:314-342; C coap_slot_coord.c:196-202, rpl_multi_instance.c:170-176; Rs multi_instance.rs:405. Backbone CoAP sync absent in all stacks; superframe 60 s configurable (C coap_slot_coord.h:50-52) | high |
| R-08-008 | Both slot allocation options MUST be supported: interleaved + contiguous (GCP-6.2) | implemented+tested | C: coap_slot_coord.c:226-277, register_gateway(ordinal) :640-648, mode>1 rejected :1213-1222 (tests main.c:947-962, 1014); Rs: slot.rs:116-227 + tests :1392-1446; Py: slot_claim.py:318-420 + test_gcp6_vectors.py:100-115 (`gcp6_slot_coordination.json` consumed) | high |
| R-08-009 | Overlapping slot claim: lowest IID MUST win (GCP-6.3) | implemented+tested | C: coap_slot_coord.c:299-323 + test_conflict_resolution main.c:704-761; Rs: slot.rs:340-344,872-902 + receiver tiebreak resources.rs:1984-2030 (tests :1486, 2489); Py: slot_claim.py:256-315 + test_gcp_iid_comparison_vectors.py (`gcp_iid_comparison.json`) | high |
| R-08-010 | Loser MUST select next available slot and re-claim (GCP-6.3) | divergent | Rs: receiver-side reallocation resources.rs:2031-2078 + tests :2530-2567, find_next_available slot.rs:917-956; C helper find_available coap_slot_coord.c:602-638 zero callers; no stack emits a re-claim — gap bead `project-LICHEN-worker6-l1qw.17` | high |
| R-08-011 | Loser MUST broadcast updated schedule via CoAP to peers and LoRa announces (GCP-6.3) | not-implemented | No broadcast/schedule-fanout in C, Rs, or Py (rg empty); updated schedule exists only as Rust POST response body resources.rs:2098-2117 — gap bead `project-LICHEN-worker6-l1qw.17` | high |
| R-08-012 | MUST verify Schnorr signature on any slot claim; invalid/missing signatures MUST be silently discarded (GCP-6.3, GCP-6.5) | divergent | C conforms+tested: verify coap_slot_coord.c:362-416, silent discard return 0/no response :1488-1508, rate-limited WARN :341-350 (test_mutation_breaks_verify main.c:492, test_unknown_signer :544). Rs: verifies but returns 4.01 (resources.rs:1938-1964; test asserts 0x81 :2462). Py: verify primitive only (slot_claim.py:217-253), no handler — gap bead `project-LICHEN-worker6-l1qw.16` | low — OSCORE-layer silent consumption in Rs dispatch may or may not satisfy the MUST |
| R-08-013 | Overlap one-valid/one-invalid: valid claim MUST be accepted, invalid ignored (GCP-6.3) | implemented+tested | C: resolve_conflict valid-beats-invalid :307-316 + test_conflict_resolution; Rs: type-enforced — only VerifiedSlotClaim reaches resolve_conflict (slot.rs:419,500-549; test :1510, 1486); Py: slot_claim.py:299-303 + test_slot_claim.py | high |
| R-08-014 | GET responses /slots, /channels, /nodes MUST be ≤32 entries; larger sets require Block2 (GCP-6.4) | not-implemented | C: no cap, Block2 engine unwired (coap_blockwise.c:302-418), /nodes absent (resources coap_slot_coord.c:1656-1701); Rs: all 3 handlers, no cap/no Block2 (resources.rs:1872-1906, 2121-2185); Py: no GET resources — gap bead `project-LICHEN-worker6-l1qw.18` | high |
| R-08-015 | (no kw) All CoAP messages use OSCORE (PSK or signature context per mode) (GCP-6.4) | divergent | C: POST gated :1459-1474, GET handlers answer plaintext (existing bead `project-LICHEN-worker6-pttk`); Rs: enforced at dispatch gateway.rs:1337-1425 + end_to_end.rs:698; Py: handoff resource gating only (coap/resources/handoff.py:79-82 + test_handoff_resource.py:159-206) | high |
| R-08-016 | Claim whose protected header algorithm is not −65537 MUST be rejected (GCP-6.5) | divergent | C: byte-exact memcmp coap_slot_coord.c:1272-1277, −65536 decoy test main.c:769-813; Rs: slot-claim path has no COSE header at all (check exists only in tunnel_auth.rs:11-17,560-565, wrong resource); Py: check only on handoff (handoff.py:961-964) — gap bead `project-LICHEN-worker6-l1qw.16` | high |
| R-08-017 | MUST NOT add gateway_count / slot_start to slot-claim payload (GCP-6.5) | divergent | C: keys exactly 1..7 coap_slot_coord.c:63-71, encoder :846-874 + tests :887-915; Rs: gateway_count IS payload key 5 (resources.rs:73-80); Py: legacy claim includes gateway_count (slot_claim.py:129-142); `gcp6_slot_coordination.json` payload itself carries gateway_count (legacy vector) — gap bead `project-LICHEN-worker6-l1qw.16` | high |
| R-08-018 | Claims sent over LoRa SHOULD cap at ~40 slots; larger allocations use backbone (GCP-6.5) | not-implemented | No ~40-slot cap in C, Rs, or Py; C test_max_slots_claim asserts 60-slot claim fits 255 B at host level (main.c:1014). No bead (SHOULD, breaks no documented feature) | high |
| R-08-019 | (no kw) Validation/response codes: expiry>now, ≤300 s+5 s else 4.03; replay/invalid-slot 4.03; success 2.04; unresolved conflict 4.09 with winning claim (GCP-6.5 steps 7-11) | divergent | C: 4.03/2.04/4.09-with-stored-claim :1509-1552 + tests :584-761, but cap is exactly 300 s, no +5 s tolerance (:438-442, test_expiry_too_far :616-650). Rs: 2.04 :1195-1201; conflict = 2.05+CBOR :2008-2029 (test :2510-2526); no 4.03/4.09/expiry. Py: none. Vectors pin stale 2.01/4.29 — gap bead `project-LICHEN-worker6-l1qw.19` | high |
| R-08-020 | claim_seq counter MUST persist across gateway reboots (GCP-6.5) | divergent | Receiver: C slot_claim_settings.c:205-267 + test_reboot_persistence:156; Rs slot.rs:480,514-519 + replay_highwater_survives_restart:1763. Sender: absent in all stacks (C sign_claim coap_slot_coord.c:895 zero production callers); Py: absent — gap bead `project-LICHEN-worker6-l1qw.20` | high |
| R-08-021 | claim_seq MUST be NVS-stored and incremented atomically before each claim (GCP-6.5) | not-implemented | Same site as R-08-020 (sender machinery absent everywhere; Rs tuple semantics differ from monotonic claim_seq) — gap bead `project-LICHEN-worker6-l1qw.20` | high |
| R-08-022 | Receiver MUST persist per-gateway highest accepted claim_seq high-water in NVS (GCP-6.5) | implemented+tested | C: settings root lichen/slot_claim, commit-before-return slot_claim_settings.c:19,164-267 + slot_claim_settings suite (10 tests); Rs: sealed state + generation floor resources.rs:1908-1933, 1661-1714 + tests :2606-2711; Py: absent | high |
| R-08-023 | Claim with claim_seq ≤ cached high-water MUST be rejected (GCP-6.5) | implemented+tested | C: :444-453, 470-486 + test_gates:600-613, test_seq_recheck_under_lock:652; Rs: slot.rs:514-519 + :1709, 1763 (tuple compare — semantic caveat, see R-08-021); Py: absent | high |
| R-08-024 | New high-water MUST be persisted BEFORE claim applied to slot table (GCP-6.5) | implemented+tested | C: :528-535 + test_roundtrip_and_persist_order:124, test_persist_failure:681; Rs: commit_slot_state persist-first resources.rs:1908-1931 + slot_state_write_failure_does_not_consume_verified_claim:2664; Py: absent | high |
| R-08-025 | claim_seq high-water cache MUST be bounded to ≤64 entries (GCP-6.5) | divergent | C: 8 entries (coap_slot_coord.h:35-37), drop + fail-closed commits (slot_claim_settings.c:143-148, 239-245; test asserts 8 :189-229); Rs: StateFull at 256 prod (slot.rs:521-525, lichend.rs:2000), 64 in tests; Py: absent — gap bead `project-LICHEN-worker6-l1qw.21` | high |
| R-08-026 | On overflow MUST evict least-recently-updated entry (LRU) (GCP-6.5) | not-implemented | No LRU/timestamp in C cache or Rs verifier (both fail-closed instead; arguably safer — see bead) — gap bead `project-LICHEN-worker6-l1qw.21` | high |
| R-08-027 | Signature verification MUST complete before conflict resolution (GCP-6.5) | implemented+tested | C: verify :387-416 precedes conflict loop :488-526, `#error` guard :414-416 + tests; Rs: strict order in handle_post_slots resources.rs:1938-2030 + tests :2462, 2664; Py: n/a (no handler) | high |
| R-08-028 | MUST rate-limit slot claims ≤10/min/peer IID and ≤60/min global (GCP-6.5) | not-implemented | No limiter in any stack (dead enums: C coap_handoff.h:82, Rs handoff.rs:99, Py handoff.py:72); vector pins divergent 4.29 — gap bead `project-LICHEN-worker6-l1qw.22` | high |
| R-08-029 | Claims exceeding rate limits MUST be silently dropped (GCP-6.5) | not-implemented | Same site as R-08-028 — gap bead `project-LICHEN-worker6-l1qw.22` | high |
| R-08-030 | (no kw) Handoff flow: node DAO to new GW; POST /handoff old GW; release + confirm; confirm to node; routes updated (GCP-7) | divergent | Steps 1-3,5 tested: Rs handoff.rs:949-1092 + end_to_end.rs:1075,1121; Py test_handoff.py:325-378; C coap_handoff.c:996-1063 untested. Step 4 (B confirms handoff to node via CoAP) absent in all stacks | high |
| R-08-031 | (no kw) Handoff request validation: kid known peer, old_gw==own IID, node owned, expiry>now, seq>last per node, else 4.03 (GCP-7.1) | divergent | Rs: different protocol (CBOR node/ts/rssi handoff.rs:121-134; OSCORE+registry checks, 4.01 gating resources.rs:2130-2171; no old_gw/expiry/seq). C: decode requires only node+timestamp coap_handoff.c:878-933; 4.00 not 4.03 (:1056-1058). Py: COSE envelope classes exist untested (handoff.py:760-1182); `gcp_handoff_cose_sign1.json` orphaned. Existing bead `project-LICHEN-worker6-3o0p.5` | high |
| R-08-032 | (no kw) Handoff confirm validation: kid == expected old GW, new_gw==own IID, seq matches request; init window; register node (GCP-7.1) | divergent | C: no confirm message type (accept_response coap_handoff.c:378-435); Rs: response parsing accept_handoff handoff.rs:1030-1092 (no kid/seq echo); Py: HandoffConfirmCoseSign1 :1030-1135 untested. Existing bead `project-LICHEN-worker6-3o0p.5` | high |
| R-08-033 | New gateway MUST initialize replay window floor at (link_epoch, link_seq) (GCP-7.1) | not-implemented | C: transfers OSCORE state only coap_handoff.c:694-698; link replay (lichen/tests/replay, replay_persist) never init from handoff; Rs: OSCORE only handoff.rs:154-167; Py: seq increments only handoff.py:672-689 — gap bead `project-LICHEN-worker6-l1qw.23` | high |
| R-08-034 | New gateway MUST accept only frames with epoch > link_epoch, or epoch == link_epoch AND seq > link_seq (GCP-7.1) | not-implemented | Same site as R-08-033; underlying rule implemented+tested in link layer (lichen/tests/replay; rust/lichen-link/src/seqnum.rs:65-68; python link/replay.py) but unwired to handoff — gap bead `project-LICHEN-worker6-l1qw.23` | high |
| R-08-035 | (no kw) Single gateway sends/expects no coordination messages; new gateways detect absent legacy peers, run independently (GCP-8) | divergent | C: build-time opt-in Kconfig default n (coap/Kconfig:346-361) + STANDALONE role rpl_multi_instance.c:190-192; Rs: Disabled default config.rs:121-124, context-gated dispatch gateway.rs:1347-1355; absent-peer/legacy detection absent in all stacks | high |
| R-08-036 | The protocol is OPTIONAL but RECOMMENDED for deployments with 2+ gateways (GCP-1) | ambiguous | Deployment-level applicability statement (RFC 2119 OPTIONAL/RECOMMENDED); no implementation mapping is expected. Excluded from gap filing (not a MUST) | n/a |

### Histogram (rows)

- implemented+tested: 10 (R-08-002, 003, 006, 008, 009, 013, 022, 023, 024, 027)
- implemented+untested: 0
- divergent: 16 (R-08-001, 004, 005, 007, 010, 012, 015, 016, 017, 019, 020, 025, 030, 031, 032, 035)
- not-implemented: 9 (R-08-011, 014, 018, 021, 026, 028, 029, 033, 034)
- ambiguous: 1 (R-08-036)

### Gap beads filed (9; cap 10; overflow 0)

| Bead | Requirements | Priority |
|------|--------------|----------|
| `project-LICHEN-worker6-l1qw.15` | R-08-001 federation-mode selection | P2 |
| `project-LICHEN-worker6-l1qw.16` | R-08-012, R-08-016, R-08-017 COSE slot-claim format + silent discard | P1 |
| `project-LICHEN-worker6-l1qw.17` | R-08-010, R-08-011 loser re-claim + broadcast | P2 |
| `project-LICHEN-worker6-l1qw.18` | R-08-014 32-entry cap + Block2 + /nodes | P2 |
| `project-LICHEN-worker6-l1qw.19` | R-08-019 response-code semantics | P2 |
| `project-LICHEN-worker6-l1qw.20` | R-08-020, R-08-021 sender claim_seq persistence | P1 |
| `project-LICHEN-worker6-l1qw.21` | R-08-025, R-08-026 64-entry LRU cache | P2 |
| `project-LICHEN-worker6-l1qw.22` | R-08-028, R-08-029 rate limiting | P2 |
| `project-LICHEN-worker6-l1qw.23` | R-08-033, R-08-034 handoff replay-window init | P1 |

Pre-existing beads covering adjacent findings (referenced, not duplicated):
`worker6-pttk` (GET OSCORE downgrade), `worker6-qpco.5/.6/.7` (Python COSE
classes), `worker6-nwjl`/`worker6-nwjl.6` (claim signature coverage + parity),
`worker6-72p4`/`worker6-j6o2`/`worker6-70p7` (claim-duration enforcement),
`worker6-vpee` (resp_buf 5.00 bug), `worker6-3yhv` (conflict-path compile),
`worker6-0k8i` (seq-store NV growth), `worker6-3o0p.5` (handoff COSE parity),
`worker6-s1x0` (slot-coord test coverage), `worker6-2dgs` (endpoint authz
gating), `worker6-5brg` (spec erratum: decoy bytes in GCP-7.1 example).

## spec/04-network.md — coverage (sweep 2026-08-31)

22 requirements extracted (6 MUST-bearing rows, 1 MUST-qualified derivation
row [R-04-004, the MUST binds via R-04-003's "MUST match test vectors"], 15
keyword-less normative rows). Gap beads filed under epic
`project-LICHEN-worker6-b7z9`, labels `ipv6` + `spec-gap`. Gap-bead overflow: 0
(1 MUST-gap; cap 10).

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-04-001 | Isolated meshes (no border router) MUST work; no central address authority (§6.1) | implemented+tested | Per-node derivation needs no prefix advertisement: Rs addr.rs:109-117, Py identity.py:206-234, C identity_addr.c:49-68 + vectors/tests (R-04-003); announce relay Rs announce.rs:343-347,946-966 / Py processor.py:218-232; LOADng lichen-core/src/loadng.rs; RPL root selection multi_instance.rs:993-1017. Component-level offline tests; no single isolated-mesh e2e test | high |
| R-04-002 | Multiple border routers MUST be tolerated (§6.1) | implemented+tested | Rs: multi_instance.rs:964-1017 select_root + vectors; per-BR DAO-learned local routes gateway.rs:1582-1588; ygg_reachable gating lichend.rs:439-442. Anycast/failover delegated to external yggdrasil daemon (config.rs:197-203, no failover code). Caveat: multi_instance not wired into a running gateway (same as R-08-006) | low — flagged |
| R-04-003 | IID + primary 02xx address derived from Ed25519 pubkey via unified function; MUST match test vectors exactly (§6.2) | implemented+tested | Rs addr.rs:86-92,109-117; Py identity.py:138-151,206-234; C identity_addr.c:28-68, ipv6_addr.c:166-180. Vectors: yggdrasil-derivation.json (7), ipv6-addresses.json (11, independent oracle generate_ipv6_addresses.py). Tests: Rs tests/ipv6_address_vectors.rs + yggdrasil_addr_vectors.rs; Py test_vectors.py:2378-2385 + tests/ipv6/test_key_address_cross_impl_vectors.py:142-144 (literal 0c02a50225b4baaa); C tests/pubkey_to_iid/main.c:160-174 + tests/link_crypto/src/main.c:497-557 | high |
| R-04-004 | Derivation: IID=SHA-512(pk)[0:8] w/ U/L cleared (0xFD); primary=[0x02]+SHA-512(pk)[0:7]+IID (§6.2 pseudocode) | implemented+tested | Same sites as R-04-003: mask Rs addr.rs:90 / Py identity.py:150 / C identity_addr.c:43; prefix `addr[0]=0x02` asserted Rs tests/ipv6_address_vectors.rs:73,155,169. Note: /8-vs-/7 Yggdrasil erratum pending in beads (lqzm/yjg6/0t11 vs uvij, conflicting directions); landed code is exact 0200::/8 == this spec text | high |
| R-04-005 | Temporary (RFC 4941) + opaque (RFC 7217) IIDs MUST NOT be used (§6.2) | implemented+untested | No RFC4941/7217 code or privacy-extension path in any stack (rg clean; only spec prose mentions 04:73, 06:1286-1287). Compliant by absence; no negative test asserts IID stability across restarts | high |
| R-04-006 | Lower 64 bits of primary address == IID (MUST, §12.1) | implemented+tested | Vector yggdrasil-derivation.json:46-65 (binding_invariant ygg_lower64_equals_iid); Rs tests/ipv6_address_vectors.rs:68-72 + gateway/trust.rs:2022-2034; Py tests/ipv6/test_key_address_cross_impl_vectors.py:64; C tests/pubkey_to_iid/main.c:171 | high |
| R-04-007 | BR MUST NOT forward mesh multicasts to internet; multicast dropped both directions unless explicit peering config (§6.3.4) | divergent | C: implemented+tested — router.c:576-589 backbone-ingress drop + multicast_peering flag router.h:146, test routing_dispatch/main.c:277-284. Py: router.py:493-499 both directions + TestBRMulticastFilter 8 tests (test_router.py:469-597). Rs: NO filter — upstream_to_mesh gateway.rs:1539-1558 checks only ULA; multicast dst falls through to transmit_ipv6_wire :1556 (internet→mesh forwarded); forward_mesh_to_upstream lichend.rs:914-951 TUN-writes multicast (mesh→internet); stack.rs:587-595,795-806 accepts multicast dst — gap bead `project-LICHEN-worker6-b7z9.39` | high |
| R-04-008 | (no kw) Link-local after lichen_link_init(); primary self-derived, always available (§6.1) | implemented+tested | C link_ctx.c:147 lichen_link_init(ctx,eui64) fail-closed (-EIO CSPRNG path tested tests/link_ctx/main.c:40); link-local derived after link init lichen_l2_init.c:771-776; primary net_if_ipv6_addr_add :792 only after key load :783-793; init failure bricks iface until reboot :747-751,136-139; LCI static fe80::1/2 slip_transport.c:118. Rs/Py identity-carried (link_layer.rs:549, node.py:403-407). Suites: link_ctx, link_crypto, l2_key_selection | high |
| R-04-009 | (no kw) Root election lowest-EUI-64 deterministic; >50% vote demotion w/ Schnorr-signed DEMOTION_REQUEST; root no longer advertises ULA (§6.1) | divergent | Election is multi-criteria w/ lowest-EUI-64 as final tiebreak (multi_instance.rs:964-981 Ord + select_root :993-1017, signature filter fail-closed) per spec 2a.5.2 — not the bare lowest-EUI-64 of 04:32. DEMOTION_REQUEST + >50% vote: absent in all stacks (only local demote() primitive dodag.rs:373-380, dodag.py:331-342; planned per docs/spec-chapter-breakdowns.md:379-385). Root ULA advertisement: absent (conformant); residual ULA classification/accept code Rs hybrid.rs:231-234, node.rs:196,526,609-616,750-757 + Py headers.py:259-264 (gateway upstream rejects ULA gateway.rs:1549-1551) | high |
| R-04-010 | (no kw) Off-mesh 02xx forwards to BR Yggdrasil TUN; local stays on LoRa; multi-BR redundancy via Yggdrasil (§6.1) | implemented+tested | Rs gateway only: forward_mesh_to_upstream lichend.rs:914-956, is_local_mesh DAO-gated gateway.rs:1582-1588, tests yggdrasil_cross_mesh_routing :2371-2393 + dao_route_makes_ygg_address_local :2403-2435; node default route toward BR/root hybrid.rs:268-306. C: no TUN/off-mesh forwarding code found. Py: sim-level only (no OS TUN) | low — flagged |
| R-04-011 | (no kw) Multicast scopes + standard groups ff02::1/1a/2, ff03::1, ff03::fc (§6.3.1) | divergent | ff02::1 + ff02::1a defined AND used in all stacks (Rs multicast.rs:8-13 + rpl_stack/util.rs:29-30; C dad.c:20 + rpl_root.c:27-28; Py icmpv6.py:26 + addr.py:26 + authenticated_dio.py:360-361). ff02::2 defined-unused (Rs lichen-ipv6 lib.rs:195), absent in C, example-only Py. ff03::1 tests-only (Py test_router.py:517), no prod use Rs/C. ff03::fc defined-unused everywhere (Rs multicast.rs:15-17, Py addr.py:27). Scope byte tests: Rs multicast_constants.rs:15-44, Py test_multicast_constants.py:17-30 | high |
| R-04-012 | (no kw) Hop-limited broadcast: decrement, relay if >0, consume at 0; no routing table consulted (§6.3.2) | implemented+tested | C router.c:576-604 multicast relay branch (next_hop = mcast addr itself; forwarded_hop_limit :502-507; scope guards) + tests routing_dispatch/main.c:245-284; Rs with_decremented_hop_limit lichen-ipv6 lib.rs:398-404 (test :1613-1635) + announce relay hop_limit_prevents_relay announce.rs:946-966 + gateway encapsulation decrement gateway.rs:1662-1678 (test :2538); Py node.py:979-1013 + test_node.py:2123-2180 (parametrized incl. ff02::1). Caveats: Rs general ff03 flooding absent (unicast via RPL lookup receive.rs:271-289); Py router.py:501-511 has no multicast scope branch | high |
| R-04-013 | (no kw) Per-sender hop-aware broadcast budgets 200/100/30/10 per hour; SOS 3 (§6.3.3) | divergent | Py only: broadcast_limit.py:24-27,33-47,137-145 + vectors broadcast_rate_limiting.json + tests link/test_broadcast_limit_vectors.py — NOT wired into node relay path (zero callers in python/src). C/Rs: absent. SOS relay budget 3 absent from limiter everywhere (only SOS originator limit exists: emergency.py:30-33 + sos_rate_limiting.json, spec 18.3) | high — flagged |
| R-04-014 | (no kw) Yellow-zone probabilistic relay: ≥50% budget → 50% drop (§6.3.3) | divergent | Py classify_broadcast :50-71 + 50% drop resolution :117-118 + test_yellow_zone_probabilistic; same unwired (Py) / absent (C, Rs) status as R-04-013 | high — flagged |
| R-04-015 | (no kw) Relay state expires after 2h idle; memory bounded ~2KB @100 senders (§6.3.3) | divergent | Py SENDER_STATE_IDLE_S=2*3600 :30,105-107 + test_sender_state_expires_after_idle (7201s); unwired/absent as R-04-013; ~2KB bound: no cap/eviction mechanism in any stack | high — flagged |
| R-04-016 | (no kw) ICMPv6 Echo Request/Reply (RFC 4443) (§6.4) | implemented+tested | C icmpv6.c:657-727 handle (checksum verify, suppression :707-712) + ~30 ztests tests/icmpv6 + ping_l2 L2-path e2e; Rs node.rs:188-224 auto-reply wired stack.rs:626-641 + tests/icmpv6_echo_vectors.rs (ipv6-icmpv6.json) + gateway e2e end_to_end.rs:481,508,531; Py icmpv6.py:426+ implemented+tested (test_icmpv6.py:219-325) but not called from node receive loop (node.py dispatches only RPL type 155 :1099-1101) | high |
| R-04-017 | (no kw) ICMPv6 Destination Unreachable / Packet Too Big (§6.4) | implemented+tested | Builders+parsers all stacks w/ shared vectors: C icmpv6.c:577-639 + tests main.c:441,468,510,673; Rs lichen-ipv6 lib.rs:608-763 + unit tests :1485-1536; Py icmpv6.py:387-413 + test_icmpv6.py:194-211 + test_ipv6_routing_relay_vectors.py:237,271. No stack emits them from the forwarding datapath (PTB arguably N/A: SCHC fragmentation presents 1280 MTU to ULPs) | low — flagged |
| R-04-018 | (no kw) RPL control messages carried via ICMPv6 (§6.4) | implemented+tested | Type 155 in all stacks: Rs rpl_stack/util.rs:56-79 (NH=ICMPv6, RPL_ICMPV6_TYPE constants.rs:58, hop 255; SCHC codec.rs:743,1358,1423,1908,2345; relay decrements once tests.rs:1588-1590); C rpl_root.c:156-230 (net_pkt injection, dst ff02::1a); Py messages.py:27 + admission authenticated_dio.py:360-365 (dst ff02::1a + hop 255 enforced) | high |
| R-04-019 | (no kw) Short addr = crc32_ieee(EUI-64, key 0x4c494348454e) truncated to 16 bits; DAD retry seed mixing (§12.3) | implemented+tested | All stacks byte-identical (init 0x4348454e = low 32 bits of "LICHEN"): C ipv6_addr.c:45-86 (LICHEN_CRC32_INITIAL ipv6_addr.h:111); Rs short_addr.rs:23,61-94; Py short_addr.py:46-139. Vectors short_addr_dad.json (6) + dad_hash_clarification.json (authoritative_algorithm=crc32_ieee). Tests: Rs short_addr_vectors.rs (5 tests incl. ISO-HDLC check value 0xcbf43926), Py test_vectors.py:4029-4045, C tests/short_addr_iid/src/main.c | high |
| R-04-020 | (no kw) Assignment methods: derived / self-assigned random + DAD / root pool (optional); collision → regenerate+retry (§12.3) | divergent | Method 1 + seed mixing: all stacks (R-04-019). Method 2 random pick: not found in any stack (Py docstring mention only short_addr.py:672-695). Method 3 root pool: Rs std Coordinator address_assignment.rs:837-1212 + short_addr_assignment.json + tests address_assignment_vectors.rs:120,186; Py CoordinatorAddressTable short_addr.py:428-519 + test_address_assignment.py; C client-side only (rpl_short_assignment.c), no C root allocator. DAD exchange: Py DadProbeSequence :293-401 + test_short_addr_dad.py; C dad.c probe/conflict state machine :245-316 unwired (no callers outside tests); Rs RFC4861 semantics lichen-ipv6 lib.rs:1136-1152 + coordinator candidate fallback address_assignment.rs:1068-1090 | high — flagged |
| R-04-021 | (no kw) 16-bit mode selected via link-layer Addr Mode value 1 (§12.3) | implemented+tested | C link.h:138-143 LICHEN_ADDR_SHORT=1 + frame.c:14,21,62,140-144; Rs frame.rs:9-18 AddrMode::Short=1 + from_u8/addr_len :22-38; Py frame.py:34-53 AddrMode.SHORT + addressing.py:98-168. Tests: C tests/frame (vector-driven; invalid mode 4 :435), Rs frame.rs:382-416,497-517 + link_frame.json :823-899 + schnorr.rs:435,733; Py tests/link/test_addressing.py | high |
| R-04-022 | (no kw) Short addresses mesh-local; full key-derived IID remains stable identity for security (§12.3) | implemented+tested | RFC4944 short_addr↔IID mapping: Rs short_addr.rs:39-54, Py addressing.py:98-168, C short_addr_iid suite; reserved set Rs short_addr.rs:14-31 + C lichen_dad_short_addr_is_reserved (dad.h:60-64); security pinning by key-derived IID: C coap_keys_store.c:90,245,394, Rs trust.rs TOFU | high |

### Histogram (rows)

- implemented+tested: 14 (R-04-001, 002, 003, 004, 006, 008, 010, 012, 016, 017, 018, 019, 021, 022)
- implemented+untested: 1 (R-04-005, MUST NOT — compliant by absence)
- divergent: 7 (R-04-007, 009, 011, 013, 014, 015, 020)
- not-implemented: 0
- ambiguous: 0

### Gap beads filed (1; cap 10; overflow 0)

| Bead | Requirements | Priority |
|------|--------------|----------|
| `project-LICHEN-worker6-b7z9.39` | R-04-007 Rust BR multicast filter (both directions) | P1 |

Pre-existing beads covering adjacent findings (referenced, not duplicated):
`worker6-lqzm` / `worker6-yjg6` / `worker6-0t11` / `worker6-uvij`
(0200::/8-vs-/7 erratum, conflicting directions — human call), `worker6-3ffq`
(EUI-64→IID XOR doc comment), `worker6-2qty` (04 table formatting).
Keyword-less divergences (R-04-009 DEMOTION_REQUEST, R-04-013/014/015
broadcast rate limiting, R-04-020 method 2) are noted in the matrix, not
beaded, per matrix preamble; see flagged set for Opus verification.

## spec/11-lci.md — coverage (sweep 2026-08-31)

54 requirements extracted (18 MUST-bearing rows, 5 SHOULD rows, 2 explicit-MAY
rows, 29 keyword-less normative rows). The 17.6.1 transport-encryption table is
descriptive (no keyword, no behavior) and is folded into R-11-031/R-11-049
rather than given its own row. 17.5.8/17.5.9 defer to 12-apps 18.9/18.10;
C divergences there are already tracked by `project-LICHEN-worker6-l1qw.29/.30`
and are cross-referenced, not re-beaded. Architecture note: the LCI *server*
lives in C/Zephyr + Python reference; Rust ships the client SDK, wire-contract
oracles, and SLIP but serves no LCI resources. Gap beads filed under epic
`project-LICHEN-worker6-b7z9`, labels `lci` + `spec-gap`. Gap-bead overflow: 0
(5 MUST-gaps → 3 beads; same-site MUSTs share beads).

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-11-001 | MUST NOT use legacy 0xC1 framing, integer type codes/config keys, raw_tx/raw_rx, /messages as LCI (17.1.1, 17.5) | implemented+tested | Py: zero 0xC1/int-type code (rg clean); /messages only opt-in `LegacyMessagesAliasResource` rt="legacy.messages" (coap/resources/messaging.py:603-618, site.py:228-234); contract tests test_lci_contract_docs.py:38-110. Rs: zero legacy symbols; doc note lichen-client/src/paths.rs:8-9. C: legacy native (LN_FRAME_SYNC_BYTE 0xC1 lichen/lib/native/native.c:417; LN_TYPE_RAW_TX/RX native.h:34-49) still compiled+wired on 4 puck boards (CONFIG_LICHEN_NATIVE=y t1000_e_nrf52840.conf:42; apps/puck/src/main.c:431), banner-marked not-LCI (native.c:5-17) | low — is a co-resident legacy server on production firmware inside the MUST's scope? flagged |
| R-11-002 | SLIP framing: 0xC0 END, escapes DB DC / DB DD (17.3.1) | implemented+tested | C: slip_transport.c:287 encode, constants slip_transport.h:33-36 + lichen/tests/slip_transport (20 tests); Py: slip/codec.py:29-92 + test_vector_consumers_lci.py:169-280 (slip_framing.json); Rs: lichen-kiss/src/slip.rs:14-148 + tests/slip_vectors.rs + gateway framer lichen-gateway/src/slip.rs:31-108 | high |
| R-11-003 | SHOULD support BLE Option A (SLIP over NUS BLE UART); Option B OPTIONAL (17.3.2) | implemented+tested | C: gateway GATT-UART→SLIP (apps/gateway/src/ble_uart.c:363,113 + ble_lci_netif.c); Option B IPSP also present (ble_ipsp_transport.c). Py: NUS UUID 6e400001-b5a3-f393-e0a9-e50e24dcca9e exact (client/ble.py:63-67) + gateway/ble_lci.py:39-251 + tests/gateway/test_ble_lci.py. Rs: absent (KISS-BLE UUID differs lichen-kiss/src/ble.rs:17-24) — SHOULD, Py+C cover the documented client path; no bead | high |
| R-11-004 | (no kw) BT Classic SPP: SLIP over RFCOMM, same as serial (17.3.3) | not-implemented | No RFCOMM/SPP code in C, Rs, Py (rg clean). Keyword-less: noted, not beaded | high |
| R-11-005 | (no kw) RTOS IPC: lci_send/lci_recv discrete IPv6 packets, no framing (17.3.4) | implemented+tested | C: app_interface/ipc.c:193-217 lichen_app_interface_ipc_{send_to_network,recv_for_network,send_to_app,recv_for_app} (names differ from spec symbols) + lichen/tests/app_interface (FIFO/short-buffer/timeout tests). Py/Rs: n/a (host stacks) | high |
| R-11-006 | (no kw) Node acts as router; client traffic to mesh addresses forwarded over LoRa; ::/0 → node (17.2, 17.4) | divergent | C gateway only: forwarding.c:67 lichen_forwarding_handle + CONFIG_NET_ROUTE (apps/gateway/prj.conf:17); node/puck has no default-router injection (rg clean). Rs: no local-client ingress at all — serial peer carries mesh frames (lichend.rs:823-928). Py: client-side routing model only (client/addressing.py:36,86-96) | high — keyword-less: noted, not beaded; flagged |
| R-11-007 | (no kw) Node IID always key-derived SHA-512(pk)[0:8] U/L-cleared (17.4) | divergent | Derivation correct in all stacks (C app_identity.c:46-62, l2/ipv6_addr.c:166-180; Py crypto/identity.py:138-151; Rs via yggdrasil vectors) BUT C LCI interface address is literal fe80::1 (SLIP_LCI_NODE_IID slip_transport.h:43, slip_transport.c:118-121, Kconfig "Node address: fe80::1") and BLE LCI fixed link addr (ble_lci_netif.c:38-48); spec 11:172-174 calls fe80::1 "illustrative shorthand" | high — keyword-less: noted, not beaded; flagged |
| R-11-008 | (no kw) Wire EUI-64 = IID with U/L toggled exactly once; never the IID source (17.4) | implemented+tested | C: lichen_eui64_to_iid l2/ipv6_addr.c:142-164 (XOR 0x02) + tests/link_crypto:526-527, tests/pubkey_to_iid; Py: ipv6/addr.py:77-94 iid_to_eui64 + client/addressing.py:137-144 | high |
| R-11-009 | MAY client use static fe80::2 or MAC-derived address; not a LICHEN identity (17.4) | implemented+tested | Py: client/addressing.py:32-35,106-134 static_assignment/client_link_local + tests/client/test_addressing.py. MAY — never beaded | high |
| R-11-010 | (no kw) CoAP server on UDP port 5683 (17.5) | implemented+tested | C: coap/coap_server.c:52 s_coap_port=5683 + udp_port_dispatch.h:17 + tests (udp_port_dispatch, coap_client); Py: coap/udp_server.py:27-50 bind_coap_udp(port=5683) + tests/coap/test_udp_server.py; Rs: lichen-core/src/constants.rs:33 PORT_COAP=5683 (no Rust server binds it) | high |
| R-11-011 | (no kw) /.well-known/core lists the contract resource set (17.5.1) | divergent | C: CONFIG_COAP_SERVER_WELL_KNOWN_CORE gateway-only (apps/gateway/prj.conf:23; coap_server.c:447-450), lists registered resources incl. status/config/keys/msg/deaddrop/confessions; puck lacks the option. Py: default site advertises 7 resources (coap/resources/site.py:187-202); /keys /diag /msg /deaddrop /confessions opt-in only; pinned by core_link_format.json. Rs: dispatch.rs:301-303 lists 4 paths only | high — keyword-less: noted, not beaded; flagged |
| R-11-012 | GET/PUT /config CBOR {name,role}; PUT → 2.04 Changed (17.5.2) | implemented+tested | C: coap/coap_config.c:718-841 (2.04 :839) + tests/coap_config, gateway_config; Py: node_resources.py:86-133 (2.04 :115-132; PUT 4.01 unless allow_writes) + test_lci_config_vectors.py (lci_config.json); Rs client: client/config.rs:403-417 + vector test :513-517; Rs server stub dispatch.rs:311-320 returns {"interval":60} | high |
| R-11-013 | GET/PUT /config/radio (freq_mhz,bw_khz,sf,cr,tx_power_dbm,sync_word); PUT → 2.04 (17.5.2) | implemented+tested | C: coap_config.c:843-964 (2.04 :961-963; range validation :446-543; sync_word "0x34") + tests/coap_config:552+; Py: node_resources.py:135-179 + test_lci_radio_config_vectors.py; Rs client: radio_config.rs:290-304 + vector tests :343,:410 (lci_radio_config.json) | high |
| R-11-014 | GET /config/identity read-only (eui64, pubkey, pubkey_fingerprint, addrs) (17.5.2) | implemented+tested | C: coap_config.c:966-995 GET-only resource :1014-1018 + lci_identity.json; Py: node_resources.py:182-193 + test_lci_identity_vectors.py (incl. 4.05 on mutation); Rs client: identity.rs:116 + vectors :141 | high |
| R-11-015 | (no kw) GET /status observable; uptime/battery/mem/time/dodag/radio/ccp; push on significant change (17.5.3) | implemented+tested | C: coap/coap_status.c:538-678 encoder incl. ccp; Observe engine :1322-1428, .notify :1304-1308 + tests/coap_status_get (5 observe tests); vectors lci_status.json, coap_observe_sequence.json. Py: StatusResource ObservableResource node_resources.py:15-36 + test_status_observe.py + TestLciStatusVectors. Rs: client decode only (client/status.rs:26-68); no Rust server resource | high |
| R-11-016 | (no kw) time object: wall_clock_valid false → unix_time omitted/zero; source_class gnss/network/local-client/manual/internal-rtc; age_s (17.5.3) | divergent | C: unix_time omitted when invalid ✓ (coap_status.c:580-608) but source_class strings capitalized "GNSS"/"Network"/"Local-client"/"Manual/static"/"Internal RTC" (link/time_sync.c:206-224) vs spec lowercase tokens; Py: timing/status_time.py:17-47 lowercase ✓ + tests/timing/test_status_time.py. Cross-stack value mismatch | high — keyword-less: noted, not beaded; flagged |
| R-11-017 | (no kw) GET /status/neighbors observable (addr, rssi, snr, etx, last_seen, trust) (17.5.3) | implemented+tested | C: coap_status.c:680-743 + resource :1310-1314 + neighbors_notify :1119-1179 + tests/coap_status_get; neighbors_cbor.json. Py: NeighborsResource :39-71 + test_vector_consumers_lci.py:518-563 (bare-list vs envelope divergence, client accepts both). Rs client: status.rs:104-146 + vectors :343 | high |
| R-11-018 | (no kw) GET /status/routes (prefix/via/metric/lifetime_s + default_route) (17.5.3) | implemented+tested | C: coap_status.c:745-823 + routes_notify :1181-1244; Py: RoutesResource :74-83 + TestRoutingTableVectors (lci_routing_table.json); Rs client: status.rs:148-176 + vectors :380 | high |
| R-11-019 | Clients MUST treat 4.04/5.01 on /diag as unsupported diagnostics, no legacy fallback (17.5.4) | implemented+tested | Py client: client/lci.py:41 RAW_DIAGNOSTIC_UNSUPPORTED_CODES {"4.04","5.01"} → RawDiagnosticState.UNSUPPORTED (:811-856) + tests/client/test_lci.py:502,568,596,642; docstring :463 "without falling back to legacy APIs". C/Rs: no raw-diag client surface (C server omits /diag — MAY-sanctioned; unknown path 4.04) | high |
| R-11-020 | (no kw) GET /diag summary {available, raw{rx,rx_events,tx,max_frame_len}} (17.5.4) | implemented+tested | Py: coap/resources/raw_rx.py:18-28,101-112 diag_summary + tests/coap/test_raw_rx_resource.py::test_get_diag_summary. C/Rs: absent (MAY-sanctioned; Rs never consumes lci_raw_diag.json) | high |
| R-11-021 | (no kw) GET/PUT /diag/raw/rx arming {enabled,ttl_s,include_payload}/{remaining_s,max_ttl_s} (17.5.4) | implemented+tested | Py: RawRxResource raw_rx.py:31-75 + RawDiagTTL coap/raw_diag.py (MAX_TTL_S=300) + tests test_raw_rx_resource.py + test_raw_diag_ttl_vectors.py (raw_diag_ttl.json) + client arm_raw_rx lci.py:473-502 | high |
| R-11-022 | (no kw) GET /diag/raw/rx/events Observe {frame, rssi_dbm, snr_db, uptime_ms, freq_hz, crc_ok} (17.5.4) | implemented+tested | Py: RawRxEventsResource raw_rx.py:78-98 (ObservableResource) + test_raw_rx_events_observe + TestRawDiagVectors (lci_raw_diag.json, test_lci_status_side_vectors.py:164-272) + client observe_raw_rx_events lci.py:504-513 | high |
| R-11-023 | Raw RX MUST be disabled by default (17.5.4) | implemented+tested | Py: RawDiagTTL.enabled False until armed (coap/raw_diag.py:30-59) + test_raw_diag_ttl_vectors.py TestDefaults + test_get_raw_rx_disabled_matches_spec_example. C/Rs: no raw RX (MAY-sanctioned omission) | high |
| R-11-024 | Raw RX MUST use a finite arming lifetime (17.5.4) | implemented+tested | Py: RawDiagTTL MAX_TTL_S=300, ttl required on arm, clamp, monotonic countdown, auto-disable (raw_diag.py:55-85) + TestArming/TestCountdown vectors | high |
| R-11-025 | Raw RX MUST NOT divert frames from the normal IPv6 stack (17.5.4) | ambiguous | No stack implements real-radio raw RX: Py sim only republishes host-pushed events (raw_rx.py:78-98), C/Rs have no raw RX — vacuously satisfied everywhere; spec text pinned only by test_lci_contract_docs.py:26. No behavioral tap-vs-consume test exists | low — flagged: does vacuous satisfaction count? |
| R-11-026 | (no kw) POST /diag/raw/tx {frame, wait} → 2.04 (17.5.4) | implemented+tested | Py: RawTxResource raw_tx.py:41-58 (frame ≤255, wait bool) + tests/coap/test_raw_tx_resource.py::test_post_raw_tx_accepts_spec_frame + client send_raw_tx + TestRawDiagVectors tx re-encode | high |
| R-11-027 | Implementations MUST rate-limit raw TX (17.5.4) | implemented+untested | Py: MIN_INTERVAL_S=1.0 → 4.00 (raw_tx.py:17-18,57-58); no test exercises the limiter (accept path only). C/Rs: no raw TX | high |
| R-11-028 | MUST reject frames/overrides violating configured PHY/regulatory constraints (17.5.4) | not-implemented | Py: frame-length cap only (raw_tx.py:51), no radio-override validation surface, no regulatory check. C/Rs: raw TX absent; Rs region TX-power caps are unwired primitives (lichen-hal/src/lib.rs:223-262) — gap bead filed | high |
| R-11-029 | SHOULD omit raw TX entirely in production firmware (17.5.4) | not-implemented | Vacuously compliant: no production firmware (C/Rs) ships raw TX; Py reference resource exists but is not production firmware and is not mounted by default. SHOULD — no bead | high |
| R-11-030 | Raw diagnostics MUST require local administrative authorization (17.5.4) | not-implemented | Py server resources carry no gate (raw_rx.py:45 render_put, raw_tx.py:41 render_post — zero auth checks); authorization is client-side only (client/lci.py:240-270), bypassable. C: lichen_coap_is_local_admin primitive exists (coap/coap_keys.c:51-98) but no diag resources. Rs: AccessLevel primitive unwired (lichen-core/src/access_level.rs:39) — gap bead filed | high |
| R-11-031 | BLE transports MUST require LE Secure Connections for raw-diag resources (17.5.4) | implemented+tested | Py client: client/packet_coap.py:296-370 check_security_for_path requires LESC for /diag/raw/*, JUST_WORKS rejected + tests test_packet_coap.py:924-1250, test_lci.py:714-856. C: transport-wide BT_SECURITY_L4 when CONFIG_LICHEN_BLE_TRANSPORT_DIAG_REQUIRE_SECURE=y (transport/Kconfig:148-156; ble_ipsp_transport.c:654) — whole-link L4, no diag resources to bind per-resource | low — flagged: transport-wide L4 vs per-resource binding |
| R-11-032 | Deployments exposing raw diag beyond a local trusted link MUST protect with OSCORE or equivalent (17.5.4) | ambiguous | No beyond-local guard anywhere: Py raw-diag resources are mountable on any UDP site with no OSCORE gate (client-side LESC only); C/Rs no raw diag (vacuous). No build/config signal prevents beyond-local mounting in Py | low — flagged; folded into gap bead with R-11-030 |
| R-11-033 | Firmware SHOULD require a build-time diagnostic enablement flag (17.5.4) | not-implemented | No Kconfig/cargo-feature/python flag for raw diag in any stack (rg: only the BLE-secure Kconfig). SHOULD — breaks no documented feature; noted, not beaded | high |
| R-11-034 | MAY require local physical confirmation before arming raw RX / accepting raw TX (17.5.4) | not-implemented | No physical-confirmation mechanism in any stack. MAY — never beaded | high |
| R-11-035 | (no kw) /keys CRUD: GET list, GET single, PUT (pubkey, trust) → 2.04, DELETE → 2.02 (17.5.5) | implemented+tested | C: coap/coap_keys.c keys_list :528-532, keys_single GET/PUT/DEL :538-544, PUT 2.04 :396-397, DELETE 2.02 :518-519 + tests/coap_keys, coap_keys_lifecycle; vectors keystore_cbor.json, keystore_iid.json. Py: KeyStoreResource keys.py:147-222 full CRUD + pubkey↔IID binding :121-144 + tests/coap/test_keys_resource.py — but NOT mounted in any site (site.py:258-259 mounts legacy GET-only KeyResource); no LciClient /keys methods. Rs client: keystore.rs:211-277 + paths.rs:54-60 | high |
| R-11-036 | (no kw) Direct IPv6+CoAP mesh reachability is authoritative; /mesh is not an LCI proxy resource (17.5.6) | implemented+tested | Py: LciClient.share_waypoint direct to coap://[peer]/waypoints (lci.py:370-413,1009-1025) + test_lci_contract_docs.py:95-110 pins the /mesh exclusion; Rs: clients target node resources directly, no /mesh anywhere; C: gateway forwarding (see R-11-006) | high |
| R-11-037 | Clients MUST NOT require /proxy for normal LCI operation (17.5.6) | implemented+tested | Py: zero /proxy references in LciClient (rg clean); Rs: lichen-client/cli/tui never use /proxy (rg clean); contract test test_lci_contract_docs.py:95-110 asserts the MUST text | high |
| R-11-038 | (no kw) Optional RFC 7252 /proxy: Proxy-Uri names the mesh target; gateway strips proxy options before forwarding (17.5.6) | implemented+tested | Py: ProxyResource coap/resources/proxy.py:47-105 (rt="proxy", _is_mesh_uri SSRF guard :23-44, Proxy-Uri stripped :88-90) + tests/coap/test_proxy.py; mounted only with mesh_client (site.py:203-204). Rs: Proxy-Uri parsing only (lichen-coap option.rs:24, codec.rs:327-329), no proxy resource. C: absent. Optional resource — Py coverage suffices | high |
| R-11-039 | (no kw) /msg/inbox|sent|ack optional messaging; POST → 2.01 + Location-Path; inbox observable (17.5.7) | implemented+tested | C: coap/coap_msg.c:2029-2058 + tests coap_msg_inbox (6), coap_msg_sent (8), coap_msg_ack (10); vectors coap_messages.json, messaging.json. Py: messaging.py POST 2.01+Location-Path, Observe + test_messages_resource.py, test_lci_auth.py. Rs client: msg.rs:555-864 + messaging_vectors.rs, receipt_vectors.rs. Caveat: duplicate /msg/inbox registration in C (coap_server.c:435 vs coap_msg.c:2029) | high |
| R-11-040 | Legacy /messages MUST NOT be advertised as a native messaging resource (17.5.7) | implemented+tested | Py: LegacyMessagesAliasResource advertises rt="legacy.messages" title="legacy demo alias" (messaging.py:603-618), mounted only when messaging enabled (site.py:228-234); default site excludes it; test_lci_contract_docs.py:50-72 pins the spec sentence | low — flagged: is rt="legacy.messages" in WKC "advertising as native"? (judgment: no) |
| R-11-041 | Deaddrop: All writes (POST) MUST use OSCORE; unauthenticated POSTs return 4.01 (17.5.8) | divergent | Py: 4.01 {"error":"oscore_required"} without post-unprotect identity (deaddrop.py:586-594; spoofed-option fail-closed :114-149) + TestOscorePostGate. Rs: Unauthorized gate order deaddrop.rs:1077-1150 + deaddrop_vectors.rs. C: OSCORE gate (coap_dtn.c:146-152) BUT local-admin cleartext fallthrough (oscore/coap_oscore.c:482-487) lets SLIP/loopback admin POST unprotected — documented "OSCORE or local admin" (coap/include/lichen/coap_dtn.h:9) | low — divergence may be intentional per 17.6.3; gap bead filed; related l1qw.30 |
| R-11-042 | Deaddrop: GETs MAY be public; sensitive drops SHOULD require OSCORE match (17.5.8) | divergent | Py: _drop_visible fail-closed for private/group (deaddrop.py:420-433), details 404/403 :694-700 + TestPrivacy. Rs: visible_to fail-closed (deaddrop.rs:1152-1160) + private_and_group_acl_fail_closed :889. C: no read privacy ACL (coap_dtn.c:211-241) — covered by existing bead `project-LICHEN-worker6-l1qw.30` | high — MAY/SHOULD row; C gap tracked via l1qw.30, no new bead |
| R-11-043 | (no kw) Deaddrop rate limits enforced per OSCORE context or source IID (17.5.8 → 18.9) | implemented+tested | Py: DEADDROP_POSTS_PER_HOUR=6 per context + 4.29 retry_after (deaddrop.py:29,367-384,608-614) + TestLimits. Rs: per-context_id check_rate_limit (deaddrop.rs:1104) + rate_limit_rejection_matches_vector :339. C: cooldown-only, divergent budgets — l1qw.30 | high |
| R-11-044 | Confessions: POST SHOULD use SenML+CBOR ct=112; OSCORE OPTIONAL; GETs public (17.5.9) | implemented+tested | Py: confessions.py render_post validates SenML pack structure (ct not explicitly checked, :592-603), OSCORE optional :221-222, GET public :538-582 + test_confessions_resource.py. Rs: CONTENT_FORMAT_SENML_CBOR=112 (confessions.rs:101) + confessions_vectors.rs. C: confessions_get public (coap_dtn.c:243-267), 112 via senml.h:56; C *requires* OSCORE on POST where spec makes it optional (l1qw.30) | high |
| R-11-045 | (no kw) Confessions rate limits tightest in LICHEN: 1 POST/30s, 12/hour per source IID (17.5.9 → 18.10) | divergent | Py: CONFESSION_COOLDOWN_S=30 + CONFESSION_HOURLY_MAX=12 per-IID (confessions.py:30-31,315-342) + tests (4_29, 12th/13th post, per-node independence). Rs: same constants (confessions.rs:57-71) + rate_limit_30s_window :167, 12th_post :191. C: single window default 60s (LICHEN_COAP_DEADDROP_RATE_LIMIT_MS 60000, coap/Kconfig:320-328; coap_dtn.c:300-313), no hourly cap, keyed on last IID byte only — l1qw.30 | high — C divergence tracked via l1qw.30 |
| R-11-046 | Confessions MUST NOT persist to flash; RAM-only; cleared on reboot (17.5.9) | implemented+tested | Py: in-memory only, "Never written to flash/NVS/filesystem" (confessions.py:260-266), clear() models reboot :405-410 + test_no_log_storage_is_ram_only, test_reboot_clears_ram. Rs: ConfessionStore RAM-only (confessions.rs:6-8,542-547) + no_log_guarantee_checks :599, reboot_clear_crash :348. C: confessions store nothing at all (coap_dtn.c:314-316) — trivially compliant, untested | high |
| R-11-047 | (no kw) OSCORE for sensitive local-link operations; same mechanism as mesh traffic (17.6.2) | implemented+tested | C: same coap_oscore.c path serves local links; context lookup by peer (coap_oscore.c:450); tests oscore, oscore_persist, coap_oscore_fallback. Py: coap/secure/channel.py SecureDatagramChannel + per-resource OSCORE gates + test_vector_consumers_lci.py:700. Rs: SecureStack/secure_dispatch (lichen-node/src/secure_dispatch.rs:31-56). Context bootstrap/"pairing" is manual everywhere (lichen-oscore/src/provisioning.rs:27) | high |
| R-11-048 | SHOULD support restricting local client access (17.6.3) | implemented+tested | C: lichen_coap_is_local_admin two-arm model (loopback/SLIP-scope admin + OSCORE) + tests/coap_lci_auth (11 tests) + coap_lci_auth.json. Py: per-resource gates + coap/access.py oracle + test_access_levels_vectors.py (access_levels.json). Rs: AccessLevel primitive + inline tests, unwired | low — flagged: 3-level model exists as oracle/primitive, not wired into dispatch anywhere |
| R-11-049 | (no kw) Access levels read-only/standard/admin; non-admin excludes /diag/raw/*; level determined by transport (USB=admin, BLE=standard) (17.6.3) | divergent | Py: access.py models exactly this (levels :27-41, transport map :44-50, /diag/raw/ admin-only :73-79) + access_levels.json vectors — but the live aiocoap site never consults it (per-resource gates instead). C: 2-tier only (local-admin vs OSCORE; no read-only/standard split), transport-determined via SLIP-scope check (coap_keys.c:73-95). Rs: primitive only (access_level.rs:15-47), zero callers | low — flagged: which stack is the reference for the 3-tier contract? |
| R-11-050 | Constrained node MUST implement SLIP framing (serial) (17.7) | implemented+tested | C subsystem LICHEN_SLIP_TRANSPORT (transport/Kconfig:9-27) + USB CDC ACM; tests/slip_transport (20 tests); enabled on rak4631_nrf52840.conf:18-19. FLAG: primary target t1000_e enables CONFIG_LICHEN_NATIVE=y (t1000_e_nrf52840.conf:42) not SLIP; same for t_echo/r1_neo/thinknode | low — flagged; bead filed (product enablement) |
| R-11-051 | Constrained node MUST implement /.well-known/core (17.7) | implemented+tested | C: CONFIG_COAP_SERVER_WELL_KNOWN_CORE gateway-only (apps/gateway/prj.conf:23); absent from apps/puck/prj.conf. Py: default-site WKC pinned by core_link_format.json. Rs: dispatch.rs:301,349 | low — flagged; bead filed |
| R-11-052 | Constrained node MUST implement /config (read-only acceptable) (17.7) | divergent | C subsystem+tests exist (coap_config.c; tests/coap_config, gateway_config) but puck initializes the standalone server with NULL handlers (apps/puck/src/main.c:522 lichen_coap_server_init(NULL)) → /config answers 4.04 on the constrained product; gateway serves it fully | high — bead filed |
| R-11-053 | Constrained node MUST implement /status (17.7) | divergent | Same site as R-11-052: puck NULL handlers (apps/puck/src/main.c:522); subsystem tested (tests/coap_status_get; lci_status.json); gateway serves /status + Observe | high — bead filed |
| R-11-054 | Capable node SHOULD implement all transports, all resources, Observe on status resources, OSCORE for local link (17.7) | ambiguous | Partial per stack: C gateway ≈ (WKC, config, status+Observe, keys, msg, deaddrop, confessions, SLIP+BLE+IPSP, OSCORE) but no /diag/raw, no /proxy; Py has the resources but opt-in mounting; Rust serves nothing. SHOULD — no bead | high |

### Histogram (rows)

- implemented+tested: 34 (R-11-001, 002, 003, 005, 008, 009, 010, 012, 013, 014, 015, 017, 018, 019, 020, 021, 022, 023, 024, 026, 031, 035, 036, 037, 038, 039, 040, 043, 044, 046, 047, 048, 050, 051)
- implemented+untested: 1 (R-11-027)
- divergent: 10 (R-11-006, 007, 011, 016, 041, 042, 045, 049, 052, 053)
- not-implemented: 6 (R-11-004, 028, 029, 030, 033, 034)
- ambiguous: 3 (R-11-025, 032, 054)

### Gap beads filed (3; cap 10; overflow 0; 5 MUST-gaps → 3 beads)

| Bead | Requirements | Priority |
|------|--------------|----------|
| `project-LICHEN-worker6-b7z9.40` | R-11-028, R-11-030 (+R-11-032) raw-diag server-side MUSTs: no PHY/regulatory rejection, no admin/OSCORE gate | P2 |
| `project-LICHEN-worker6-b7z9.41` | R-11-050..R-11-053 puck constrained-node LCI enablement (NULL handlers, WKC off, SLIP off) | P1 |
| `project-LICHEN-worker6-b7z9.42` | R-11-041 C deaddrop local-admin cleartext POST vs OSCORE-only MUST | P2 |

Pre-existing beads covering adjacent findings (referenced, not duplicated):
`worker6-l1qw.29` (deaddrop SCHC rules), `worker6-l1qw.30` (C deaddrop/
confessions 18.9/18.10 budgets, codes, ACL, confessions stub). Keyword-less
divergences (R-11-004 SPP, R-11-006 routing, R-11-007 fe80::1, R-11-011 WKC
listing, R-11-016 time source_class strings, R-11-049 access tiers) are noted
in the matrix, not beaded, per matrix preamble; see flagged set for Opus
verification.

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

## spec/10-implementation.md — coverage (sweep 2026-08-31)

8 requirements extracted (1 MUST, 1 explicit MAY, 6 keyword-less normative).
§16.1 (repository tree), §16.3 (stack tables), §16.5 (dependency tables), and
§16.6 (I-D list) are informative with no behavioral requirements — not
extracted. The section's normative core is §16.7 (DAO Origin Persistence).
Gap beads filed under epic `project-LICHEN-worker6-b7z9`: **0** (the only MUST
is implemented+tested; keyword-less divergences noted in matrix per preamble,
not beaded). Gap-bead overflow: 0 (0 MUST-gaps; cap 10). The C stack persists
no DAO state at all (no TX record, no RX floor) — the largest real gap in this
section, surfaced via the keyword-less rows R-10-001..004.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-10-001 | (no kw) TX persists public-key identity + last reserved Origin Sequence + complete last signed DAO bytes, crash-safe (§16.7) | divergent | Rs: `DaoTxState{public_key, last_reserved, last_signed_dao}` persistence.rs:122-131, `reserve_next` :252, `finalize_signed` :284 (unit tests :764+). Py: `TxState(sequence, dao_bytes)` dao_persistence.py:74-78 + `store_tx_state` :123, TwoSlotFilePersistence crash-safe :256-302 — but the record itself carries no pubkey field (manager single-identity; see flagged set). C: no DAO TX persistence — RAM-only manager rpl_routing.h:541-555; TX is builder-only, no caller sends (matches R-08N-006 finding) | high |
| R-10-002 | (no kw) On reboot the TX API exposes the exact retained bytes for retransmission; never reconstructs or re-signs (§16.7) | divergent | Rs: `DaoTxState::open` persistence.rs:187, `last_signed_dao()` :248. Py: `_restore_tx_state` dao_manager.py:315-332 (missing/corrupt = hard failure) + `test_get_last_dao_bytes_returns_persisted_bytes` test_dao_persistence.py:933. C: absent (no TX record exists) | high |
| R-10-003 | (no kw) RX persists only pubkey + accepted high-water sequence + digest; not the complete DAO or route table (§16.7) | divergent | Rs: `OriginReplayStore` get/set_floor(pubkey, seq, dao_digest) dao_origin.rs:136-140; `DaoRxState` + `encode_high_water` persistence.rs:367, :643 (round-trip tests :765, :786). Py: `RxFloor(sequence, digest)` dao_persistence.py:82-86, `store_rx_floor(pubkey,…)` :148. C: `root_state` RAM-only rpl_routing.h:508-513, no NVS/settings binding (rg clean rpl_root.c); link-layer floors replay_persist.h:56-61 are 16-bit LLSec state, not DAO origin state | high |
| R-10-004 | (no kw) Fresh receive: persist the RX floor before exposing the route or returning success (§16.7) | divergent | Rs: `unavailable_replay_storage_leaves_dao_state_unchanged` dao_origin_vectors.rs:265-300 (forced persist failure → `Persistence` outcome, route None, storage snapshot unchanged). Py: documented order "7. replay-floor persistence for a fresh DAO → 8. atomic in-memory route mutation" dao_manager.py:660-671 + `test_fresh_dao_higher_sequence_commits_floor` test_dao_origin.py:1263. C: ordering documented only rpl_dao_process.c:243-244 — no persistence backing to order | high |
| R-10-005 | (no kw) Equal-sequence/equal-digest retransmission does not rewrite persistence; idempotent re-parse + exact self-Target revalidation (§16.7) | implemented+tested | Py: `test_idempotent_retransmission_does_not_rewrite_floor` test_dao_origin.py:1212. Rs: retransmission flag dao_origin.rs (`is_retransmission`, "False for idempotent retransmissions") + `version_floor_rejects_stale_root_authorization_and_replays_are_idempotent` lichen-node/src/routing/tests.rs. C: "Equal-seq exact digest = idempotent retransmission … MUST NOT rewrite floor. Matches Rust" rpl_dao_process.c:244-246 | high |
| R-10-006 | MUST snapshot complete route + replay-floor + storage state around rejected DAOs to test no partial mutation (§16.7) | implemented+tested | Rs: `unavailable_replay_storage_leaves_dao_state_unchanged` dao_origin_vectors.rs:265 (storage_snapshot compare :280-297), `fixed_dao_origin_vectors_match_rpl_node_handler` :144 (52 vectors from test/vectors/dao_origin_signature.json, floor-mutation asserts), `delegated_prefix_is_allowed_and_denial_leaves_no_state_mutation` dao_prefix_authorization.rs:327, `foreign_slash64_and_default_route_fail_closed_without_mutation` :723. Py: `test_zero_sequence_dao_persists_no_floor_and_installs_no_route` test_dao_origin.py:1494-1526 (route snapshot + no RX floor), `test_multi_floor_batch_is_rejected_without_partial_commit` test_dao_persistence.py:361, `test_ninth_hop_dao_is_rejected_atomically` test_dao.py:490. C: gate-denial zero-mutation rpl_dao_auth/src/main.c:239 (byte-identical route), :293, :612 — route/replay legs only; storage leg vacuous (C persists no DAO state; see flagged set) | high |
| R-10-007 | MAY disable store-and-forward on STM32WL (§16.4) — explicit MAY | not-implemented (conformant — MAY) | No platform-gated toggle: lichen Kconfigs carry no store-and-forward option (rg clean); DTN store-and-forward ungated in Rs lichen-node/src/routing/dtn.rs and Py routing/router.py; absent in C. No bead (MAY) | high |
| R-10-008 | (no kw) Non-Neo R1 display variants and LR1121 radios require separate board files + validation evidence before being advertised as supported (§16.2) | ambiguous | No non-Neo R1 or LR1121 board files exist (find: only lichen/boards/muzi/r1_neo/*) — constraint currently satisfied by absence. Unclear whether product-scoping prose belongs in a normative matrix (see flagged set) | low |

### Histogram (rows)

- implemented+tested: 2 (R-10-005, R-10-006)
- implemented+untested: 0
- divergent: 4 (R-10-001, 002, 003, 004 — all on the C stack's absent DAO persistence; Rs/Py conformant and tested)
- not-implemented: 1 (R-10-007 — explicit MAY, absence conformant)
- ambiguous: 1 (R-10-008 — scope question)

### Gap beads filed (0; cap 10; overflow 0)

The section's only MUST (R-10-006) is implemented+tested in all three stacks at
their respective layers, so no gap beads are due. The C stack's total absence
of DAO persistence (TX record and RX floor, R-10-001..004) is keyword-less
normative text — noted here per matrix preamble, not beaded. Adjacent
already-beaded work: `project-LICHEN-worker6-d5bw` (equal-generation DAO
persistence slots, python). C DAO TX being builder-only was already recorded
as divergence under R-08N-006 (spec/08-nodes sweep).

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

## spec/07-transport-app.md — coverage (sweep 2026-08-31)

45 requirements extracted (7 MUST-bearing rows, 1 SHOULD, 1 SHOULD-NOT
["NOT RECOMMENDED"], 2 explicit-MAY rows, 34 keyword-less normative rows).
Section is internally numbered §9–§10. §9.1's per-port translation table is
folded into R-07-001; §10.2.3's parameter table is R-07-026; §10.2.4's duty
state fields (monotonic/rolling window) are R-07-029. Gap beads filed under
epic `project-LICHEN-worker6-b7z9`, labels `transport` + `spec-gap`. Gap-bead
overflow: 0 (3 MUST-gaps → 3 beads). Cross-sweep resolutions: R-01-005/011/012
(MQTT-SN codec-only, DTLS-for-MQTT-SN) land here — §9.1 confirms no DTLS
(port 5684 reserved, OSCORE instead) and code comments already match;
R-08N-004's MQTT-SN gateway deferral resolves to R-07-040, which is
keyword-less and therefore noted, not beaded.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-07-001 | Gateways MUST translate mesh-internal ports (5681, 5682, 5685-5687) to standard protocols before external forwarding (§9.1) | divergent | Only 5686→APRS-IS TCP exists: Rs aprs_is.rs:228,473,527 (AprsIsClient, cot_to_aprs, aprs_to_cot) + loopback-TCP tests :619-1072. CoT→XML expansion function-only, no TCP 8087 (Py gateway/compact_cot.py:432,765; rg 8087 clean). 5682→CF112 plumbing only. 5685→LoRaWAN: no Cayenne codec in any stack. 5687: none. 5688: port absent everywhere — gap bead `project-LICHEN-worker6-b7z9.43` | high |
| R-07-002 | (no kw) Port table: 5681 CoT, 5682 SenML, 5683 CoAP, 5684 reserved, 5685 Cayenne, 5686 APRS-IS, 5687 NMEA, 5688 Crypto, 10883 MQTT-SN (§9.1) | divergent | 8/9 ports defined in all stacks (Py constants.py:24-31; Rs constants.rs:31-38; C udp_port_dispatch.h:15-22) + test/vectors/port_dispatch.json consumed Rs/Py/C (port_dispatch_vectors.rs, test_port_dispatch_vectors.py:31, tests/udp_port_dispatch); 5688 absent from all three stacks AND constants.toml. Keyword-less: noted, not beaded (folded into R-07-001 bead) — flagged | high |
| R-07-003 | (no kw) Port 5684 reserved; no DTLS/CoAPS — OSCORE instead (§9.1) | implemented+tested | Rs dispatch 5684→ReservedPort port_dispatch.rs:163 + test dispatch_udp_reserved_port_5684 node.rs:1747-1814; PORT_COAP_DTLS=5684 "Reserved, not used (OSCORE instead)" constants.rs:34; port_dispatch.json reserved case; C reserved/unknown test case tests/udp_port_dispatch. Resolves the R-01-012 DTLS deferral: code matches §9.1 | high |
| R-07-004 | (no kw) UDP RFC 768 compressed via SCHC; 568x family shares MSB(12)/LSB(4) rule (§9.1) | implemented+tested | Rs is_schc_compressible_port 5680-5695 port_dispatch.rs:179 (+ unit tests :188-302); C lichen_udp_port_is_schc_568x udp_port_dispatch.c:67 (SCHC boundary tests); SCHC rules 0-7 sites per R-01-013; schc_mqtt_sn rule tests | high |
| R-07-005 | (no kw) TCP NOT recommended; use CoAP Observe or MQTT-SN for reliability (§9.2) | implemented+untested | Compliant by absence: TCP sockets only in spec-mandated external glue (Rs aprs_is.rs APRS-IS client; sim radios Rs sim.rs:14, sim_radio.rs:11, C lora_sim.c:223; Py tests-only); zero TCP in lichen-link/ipv6/rpl/coap/node/core and python/src/lichen (rg clean). No negative test | high |
| R-07-006 | (no kw) Raw-UDP ports carry known payload formats; receivers dispatch on destination port (§10.1) | implemented+tested | Rs dispatch_by_port port_dispatch.rs:157 wired Node::dispatch_udp node.rs:247; Py port_dispatch.py:103,146 wired node.py:622-634; C lichen_udp_port_dispatch udp_port_dispatch.c:93 (dest-port-only rule tested); vectors port_dispatch.json all stacks | high |
| R-07-007 | (no kw) Compact CoT subtype byte table 0x01-0x20 (§10.1.1) | implemented+tested | Rs CompactCotType compact_cot.rs:40-65; Py CotSubtype compact_cot.py:40-41; C compact_cot_pli/chat; vectors compact_cot.json (49 vectors: PLI/chat/marker/alert/XML) consumed by tests/compact_cot_vectors.rs, tests/test_compact_cot.py, C tests/compact_cot_{pli,chat} | high |
| R-07-008 | Receivers MUST reject PLI datagrams not exactly 17 bytes, coords out of range, course >35999 (§10.1.1) | implemented+tested | Rs exact-17 rule compact_cot.rs:432 + bounds errors :500-504; Py PLI_TOTAL_SIZE=17 + bounds tests; C test_encode_rejections/test_decode_rejections tests/compact_cot_pli/main.c; vectors compact_cot.json 9 invalid PLI (truncated/trailing-byte/lat/lon/course) | high |
| R-07-009 | (no kw) PLI 17-byte layout: µdeg lat/lon int32, dm alt int16, centideg course uint16, cm/s speed uint16, team/role u8 (§10.1.1) | implemented+tested | Same sites as R-07-007/008; Rs PliPayload encode/decode compact_cot.rs:560+; parity test canonical_pli_vectors_have_exact_python_rust_parity compact_cot_vectors.rs | high |
| R-07-010 | (no kw) Chat encoding: dest_type 0x00 broadcast / 0x01 team / 0x02 direct 16-B address; team enum 0x01-0x0A (§10.1.1) | implemented+tested | Rs DestType/Team compact_cot.rs:83+; Py DestType/Team with to_name; vectors 9 positive + 6 invalid chat (team zero/above-range, invalid UTF-8) + canonical_chat_destination_vectors_have_python_rust_parity | high |
| R-07-011 | (no kw) Sender identity comes from L2/OSCORE context, not the CoT payload (§10.1.1) | implemented+untested | Format carries no sender field (pinned by compact_cot.json exact layouts + schema); stack attributes identity per key-derived IID (R-04-003/022 sites). No test binds a 5681 datagram's sender to its OSCORE/L2 identity | low — flagged |
| R-07-012 | (no kw) Gateways expand compact CoT to full XML for ATAK (§10.1.1) | implemented+tested | Py expand_cot_to_xml gateway/compact_cot.py:432 (+ per-subtype expanders), parse_xml_cot/xml_to_compact compact_cot.py:579,746; XML vectors in compact_cot.json + canonical_xml_vectors_have_rust_binary_parity + python/tests/gateway/test_compact_cot.py. (TCP 8087 transport gap → R-07-001 bead) | high |
| R-07-013 | (no kw) SenML RFC 8428 CBOR, Content-Format 112 (§10.1.2) | implemented+tested | Rs lichen-senml wire.rs (CF 112); Py senml/codec.py + profiles.py; C senml.c, SENML_CBOR_CONTENT_FORMAT=112 asserted tests/senml/main.c:132; vectors senml_location/labels/full_fields.json + Python↔Rust byte parity tests | high |
| R-07-014 | MAY SenML Compact Profile use integer keys + implied units (§10.1.2) | implemented+tested | Integer CBOR keys are the default encoding (Rs SenmlLabel wire.rs:214-228); implied-unit profiles Py senml/profiles.py; vectors senml_labels.json. MAY — never beaded | high |
| R-07-015 | (no kw) Cayenne LPP type codes 103/104/115/136 (§10.1.3) | not-implemented | No Cayenne LPP codec in any stack (rg clean; only dispatch enums port_dispatch.rs:24-25, port_dispatch.py:38, udp_port_dispatch.c:42-44; Meshtastic CayenneApp=77 unrelated). Keyword-less: noted, not beaded — flagged | high |
| R-07-016 | (no kw) APRS-IS ASCII payloads; format chars !/@/:/>/T (§10.1.4) | divergent | Rs position reports only: cot_to_aprs/aprs_to_cot aprs_is.rs:473,527 (PHG, DDMM.mmN, altitude clamp) with inline tests; no `:` message, `>` status, `T` telemetry, `@` timestamped handling (rg clean). Py/C: dispatch classification only. Keyword-less: noted, not beaded — flagged | high |
| R-07-017 | (no kw) Gateways bridge APRS: reconstruct AX.25 for RF, or forward to APRS-IS servers over TCP (§10.1.4) | implemented+tested | TCP branch: Rs AprsIsClient aprs_is.rs:228-319 (login/passcode, send/recv, APRS_IS_PORT=14580) + loopback-TCP tests :619-1072. AX.25 exists as KISS compat (Rs bridge.rs:27, Py interface/kiss/, C kiss_transport.c) but is not wired as a 5686 bridge — the OR-branch is satisfied via TCP | high |
| R-07-018 | (no kw) NMEA 0183 passthrough on 5687; gateways may convert to SenML/CoT (§10.1.5) | ambiguous | Dispatch classifies 5687→Nmea (Rs port_dispatch.rs:165, Py port_dispatch.py:38, C udp_port_dispatch.h:21) but no passthrough/forward handler downstream in any stack; Py sim generates GGA/RMC (sim/gnss.py:100-156 + test_gnss_nmea_feeder.py). Unclear what "direct passthrough" requires of node vs gateway | low — flagged |
| R-07-019 | (no kw) Crypto relay CBOR request {1: CAIP-2, 2: raw tx} + response {1, 2, 3 status 0/1/2} (§10.1.6) | not-implemented | Port 5688 + CAIP-2 + relay CBOR format absent from all stacks and vectors (rg clean). Keyword-less: noted, not beaded; folded into R-07-001 bead — flagged | high |
| R-07-020 | (no kw) Gateway 5688 operation: parse CAIP-2, route tx, return hash+status (§10.1.6) | not-implemented | Same absence as R-07-019. Keyword-less: noted — flagged | high |
| R-07-021 | (no kw) LICHEN nodes never hold private keys (§10.1.6) | implemented+untested | Compliant by absence: no blockchain/wallet key storage in any stack (rg clean; node keys are Ed25519 identity only). No negative test | high |
| R-07-022 | (no kw) CoAP RFC 7252 on UDP 5683 (§10.2) | implemented+tested | C coap_server.c:52 s_coap_port=5683 + udp_port_dispatch.h:17; Py udp_server.py:27-50 bind_coap_udp(port=5683); Rs PORT_COAP=5683 constants.rs:33; cross-ref R-11-010 | high |
| R-07-023 | (no kw) Content-Format dispatch: 0 text, 60 CBOR, 110 senml+json, 112 senml+cbor, 11542 OCF (§10.2.1) | implemented+tested | CF 112 exercised end-to-end (R-07-013 sites); CF 0/60/110/11542 constants defined (Rs option.rs:41-46 incl. OCF_CBOR, Py params.py:85-93); 110/11542 defined-unused in any handler. Keyword-less: noted | high |
| R-07-024 | MAY CoAP resources use OMA LwM2M/IPSO paths with bare CBOR payloads (§10.2.2) | not-implemented (conformant — MAY) | IPSO vocabulary + unit maps exist (Rs ipso.rs:16,106; Py senml/ipso.py:29) but no CoAP resource serves /{obj}/{inst}/{res} bare-CBOR paths in any stack (rg clean). MAY — never beaded | high |
| R-07-025 | Gateways SHOULD translate between SenML and IPSO formats when bridging (§10.2.2) | not-implemented | No SenML↔IPSO translation code in any stack (rg clean). SHOULD — omission breaks no shipped documented feature; noted, no bead — flagged | high |
| R-07-026 | (no kw) CoAP params: ACK_TIMEOUT 15s, ACK_RANDOM_FACTOR 2.0, MAX_RETRANSMIT 2, NSTART 1, LEISURE 15s, PROBING_RATE 0.1 B/s (§10.2.3) | divergent | Py: all 6 exact (coap/params.py:26-38 LICHEN_* vs RFC7252_*) + runtime retransmit transport.py:974-985 + vector coap_transport.json loRa_params (retry_schedule [15,30], give-up ~90s) + test_vector_consumers_lci.py:596-609. C: ACK_TIMEOUT only (apps/puck/prj.conf:48 =15000); no ARF/MAX_RETRANSMIT/NSTART/LEISURE/PROBING symbols anywhere. Rs: ack_timeout/max_retransmit exist only inside Observe (observe.rs:292-293,444-463); no general CON engine. Keyword-less: noted, not beaded — flagged | high |
| R-07-027 | (no kw) Prefer NON for telemetry/notifications; CON only when confirmation critical (§10.2.3) | ambiguous | No automatic NON-selection logic in any stack; implemented as priority incentive (CON→P2, NON→P3: Py params.py:163-164 + transport.py:848-861; vector prefer_non coap_transport.json:121-134); C uses NON for observe notifications coap_location.c:406. Unclear whether sender-side auto-NON behavior is required | low — flagged |
| R-07-028 | Nodes MUST track duty cycle usage and throttle transmissions accordingly (§10.2.4) | implemented+tested | Rs DutyCycleTracker duty_cycle.rs:348+ (record_tx/can_transmit/try_record_tx) wired transport.rs:101-151 + tui/radio.rs:67-100; C hal_duty.c:161-320 wired into L2 TX lora_l2_tx.c:427-436 (fail-closed) + record :524-525, Kconfig LICHEN_DUTY_CYCLE l2/Kconfig:253; Py sim-radio per-channel trackers sim/node_server.py:158 + timing/duty_cycle.py:142 RegionalDutyCycleEnforcer. Vectors ccp13.json ("matches Rust, C, Python exactly") + packets-timing.json; suites duty_cycle_vectors.rs, tests/regional_duty_cycle, test_duty_cycle*.py, hal tests :1471-1476. Caveat: Py enforcement lives at the sim radio (Py's only radio); C has no congestion levels (R-07-030) | high |
| R-07-029 | (no kw) Duty state: monotonic uptime (not wall-clock), rolling 1-hour window, per-channel, region-specific limit (§10.2.4) | implemented+tested | C k_uptime-based record ring (LICHEN_DUTY_CYCLE_WINDOW_MS=3600000 duty_cycle.h:15); Rs TxRecord ms-ring duty_cycle.rs:348, WINDOW_MS :45; Py 1-hour window DutyCycleTracker (sim). Spec's literal field names last_tx_end/tx_time_window/duty_limit absent; equivalent rolling-record semantics everywhere. Vectors ccp13.json + duty_cycle_vectors.rs + test_duty_cycle*.py | high |
| R-07-030 | (no kw) Congestion levels normal/elevated/critical/exhausted at 50/80/95% with per-level actions (§10.2.4) | divergent | Rs exact thresholds 500/800/950 permille + all four boundary tests duty_cycle.rs:124-147,994-1135; Py congestion levels params.py:140-148 + test_congestion.py; C: no level classification (blocks at budget, fail-closed only). Keyword-less: noted, not beaded — flagged | high |
| R-07-031 | (no kw) Load shedding: 5.03 + Max-Age + CBOR {reason: duty_cycle, retry_after, level} (§10.2.4) | divergent | Py: full emission params.py:239-292 + site.py:111-130 CongestionAwareSite + vector load_shedding_503 (coap_transport.json:172-184) + test_congestion.py:236-372 (incl. retry_after 0/negative/NaN). Rs: client parse only client.rs:74-82. C: generic 5.03s for unrelated capacity policies (coap_status.c:961, coap_location.c:1248, coap_rangetest.c:836-890, coap/Kconfig:554) but no duty-cycle CBOR body/Max-Age. Keyword-less: noted, not beaded; folded into R-07-032 bead — flagged | high |
| R-07-032 | Senders receiving 5.03 MUST back off for the indicated duration (§10.2.4) | divergent | Py: enforce_503_backoff ip_coap.py:25,80,110,237-245 + tests client/test_ip_coap.py:295-408 (5 tests citing spec 07: Max-Age, payload retry_after, default, during-backoff raise, clear). Rs: per-peer backoff client.rs:35-40,159,217-254 + in-file tests :648-720. C: coap_client.c zero 5.03/backoff/retry handling (rg clean) — gap bead `project-LICHEN-worker6-b7z9.45` | high |
| R-07-033 | (no kw) TX priority queue P0-P4 (SOS, RPL control, CoAP CON/chat, NON/telemetry, bulk); low priority dropped first under congestion (§10.2.4) | implemented+tested | Rs tx_queue.rs:273-284 TxPriority 0-4 + pop_if_allowed congestion preemption + eviction lowest-first; Py link/tx_queue.py:42-53 + transport integration; C tx_queue.h:61-66 + tx_queue.c:441-453; vectors tx_queue_priority.json (14 scenarios) + coap_transport.json priority_queue consumed by all stacks (bufferbloat_vectors.rs, test_tx_queue_vectors.py:256, lichen/tests/tx_queue) | high |
| R-07-034 | (no kw) App→priority mapping: CoT alert P0, chat P2, PLI/marker P3; SenML/Cayenne/APRS/NMEA P3; CoAP CON P2 / NON P3; MQTT-SN QoS1+ P2 / QoS0 P3 (§10.2.4) | divergent | Py: full 12-row table params.py:155-170 APP_PRIORITY + runtime transport.py:848-861 + vector app_to_priority_mapping (coap_transport.json:216-293) + test_congestion.py TestAppPriority. Rs: priorities used (lichend.rs:545-1059, tui/radio.rs:80-95) but the per-port/subtype table not found; C: all app data defaults TX_PRIORITY_BULK lora_l2_tx.c:399-407 (no per-port mapping). Keyword-less: noted, not beaded — flagged | high |
| R-07-035 | (no kw) CoAP Observe subscribe/notify RFC 7641 (§10.3) | implemented+tested | Rs observe.rs full state machine (24-bit serial half-range :176-187, CON-notification byte-exact retransmit :431-463) + coap_observe_sequence.json + tests/observe.rs (11); Py ObservableResource resources (status/neighbors/senml/presence/msg) + observe clients (ip_coap.py:224-341) + test_status_observe.py, test_senml_resources.py, xfail-pinned boundary test_vector_files_consume.py; C coap_status.c:1322-1428 + coap_msg + coap_location observe engines + coap_status_get (5 observe tests); position_observe.json | high |
| R-07-036 | Implementations MUST bound Observe subscriptions: ≤16 per resource and ≤64 globally (§10.3) | divergent | No 16/64 anywhere: Rs ObserveServer fail-closed RegistryFull, caller-chosen const-generic capacity, no production instantiation (observe.rs:289-341; tests use 2-observer instances tests/observe.rs:127-297); Py aiocoap observer lists unbounded; C per-resource pools 4/4/3 fail-closed, no global cross-resource counter (coap_msg.c:37-39, coap_status.h:37-38, coap_location.h:29) — gap bead `project-LICHEN-worker6-b7z9.44` | high |
| R-07-037 | On Observe overflow implementations MUST evict the oldest subscription (LRU by registration time) (§10.3) | not-implemented | No eviction in any stack; all fail-closed (Rs RegistryFull; C "bounded and never evicts" coap_rangetest.c:838-855; Py unbounded). C policy may be deliberate — human decision flagged in bead — gap bead `project-LICHEN-worker6-b7z9.44` | high |
| R-07-038 | (no kw) MQTT-SN OASIS on 10883; message types CONNECT 0x04 … SUBACK 0x13; QoS -1 (§10.4) | divergent | Py full codec mqttsn/messages.py:33-47,137-344 (+QoS.MINUS_ONE :86) + mqttsn/codec.py + vectors mqtt_sn.json (13 vectors incl. qos_minus_one, truncated, reserved-type) + tests/mqttsn/; Rs/C: port dispatch + SCHC Rule 7 only, no codec. Keyword-less: noted, not beaded — flagged | high |
| R-07-039 | (no kw) Dedicated SCHC rule for 10883, exact not-sent match (§10.4.1) | implemented+tested | Rule 7: constants.toml:36, Rs codec.rs:1041-1133, C link_schc.h:67 + udp_port_dispatch.c:72 + lichen/tests/schc_mqtt_sn; Py mqtt_sn SCHC vectors test_vectors.py:4718-4865. Related open beads: `worker6-83wu` (profile-limit precheck), `worker6-pgsl` (Rule 7 fallback) | high |
| R-07-040 | (no kw) Gateway at border router translates MQTT-SN ↔ MQTT 3.1.1/5.0 (§10.4.1) | not-implemented | No MQTT broker client/translation in any stack (rg 1883\|broker\|paho clean). Resolves R-08N-004's deferral; keyword-less here: noted, not beaded — flagged | high |
| R-07-041 | CoAP Block-wise (RFC 7959) is NOT RECOMMENDED for LICHEN (§10.5) | divergent | Block-wise exists and is used: Rs block.rs (BlockOption/receive_block + tests), Py aiocoap blockwise passthrough transport.py:1130-1131, C gateway app real Block2 (apps/gateway/src/main.c:326-384) consumed by puck main.c:445; C engine coap_blockwise.c compiled only by host tests, unwired (bead `worker6-kbgx`); vectors coap_block.json explicitly pin the option syntax "still used by OTA and gateway paths". SHOULD-NOT tension — human/spec call — flagged | high |
| R-07-042 | (no kw) SCHC fragmentation: FCN 6 bits → 63 tiles/window, 2 windows, tile 179 B, ceiling 22554, mandatory receiver 1281 (§10.5) | implemented+tested | Rs fragment.rs (ACK-on-Error; tile_size_for_mtu :111) + SCHC_FRAG_MAX_PACKET_SIZE=22554 constants.rs:26-28; C schc.h:125-134 (TILE_SIZE 179, WINDOW_SIZE 63, RECEIVER_LIMIT/SCHC_MAX_PACKET 1281) + schc.c; Py schc/fragment.py:25-42 (MAX_SCHC_PACKET=1281) + reassembly.py + session_manager.py; vectors schc_fragmentation.json + schc_fragment.json + schc_tile_sizing.json consumed all stacks. Caveat: C link-layer dispatch to reassembler pending (bead `worker6-l1qw.3.7.3`) | high |
| R-07-043 | If reassembly limit unknown, chunks MUST fit the mandatory 1281-byte SCHC receiver capacity (§10.5) | ambiguous | No application chunking exists (R-07-044), so the conditional MUST has no trigger site — vacuously satisfied; the 1281 constant itself is implemented+tested (R-07-042 sites; coap_transport.json:311 mandatory_receiver 1281). Unclear whether vacuous compliance counts | low — flagged |
| R-07-044 | (no kw) Application chunking: POST /firmware/upload {chunk, total, data} (§10.5) | not-implemented | No /firmware/upload resource in any stack (rg clean; only vector doc-text coap_transport.json:318 and tx_queue.py:39 comment). Keyword-less: noted, not beaded — flagged | high |
| R-07-045 | (no kw) Border router runs CoAP Resource Directory: /rd register, /rd-lookup/res (§10.6) | divergent | Py only: resource_directory.py:124-358 (simplified RFC 9176, lt=86400, ep mandatory) mounted resources/__init__.py:189 + vectors coap_rd.json + 73+ tests + TestResourceDirectoryVectors (test_vector_files_consume.py:565-800). Rs: no /rd (rg clean). C: no /rd. Keyword-less: noted, not beaded (Rs/C absence adjacent to `worker6-l1qw.18` WKC/Block2 gap) — flagged | high |

### Histogram (rows)

- implemented+tested: 19 (R-07-003, 004, 006, 007, 008, 009, 010, 012, 013, 014, 017, 022, 023, 028, 029, 033, 035, 039, 042)
- implemented+untested: 3 (R-07-005, 011, 021 — all compliant-by-absence)
- divergent: 12 (R-07-001, 002, 016, 026, 030, 031, 032, 034, 036, 038, 041, 045)
- not-implemented: 8 (R-07-015, 019, 020, 024, 025, 037, 040, 044; R-07-024 is an explicit MAY, absence conformant)
- ambiguous: 3 (R-07-018, 027, 043)

### Gap beads filed (3; cap 10; overflow 0; 3 MUST-gaps → 3 beads)

| Bead | Requirements | Priority |
|------|--------------|----------|
| `project-LICHEN-worker6-b7z9.43` | R-07-001 gateway translation of mesh-internal ports (5688/CAIP-2, CoT TCP 8087, Cayenne codec, NMEA, SenML bridges; only 5686→APRS-IS done) | P2 |
| `project-LICHEN-worker6-b7z9.44` | R-07-036, R-07-037 Observe 16/64 bounds + LRU eviction | P2 |
| `project-LICHEN-worker6-b7z9.45` | R-07-032 (+detail R-07-031) C 5.03 sender backoff + duty-cycle load shedding | P2 |

Pre-existing beads covering adjacent findings (referenced, not duplicated):
`worker6-kbgx` (wire-or-remove coap_blockwise.c), `worker6-cvko` (blockwise
replay bug), `worker6-l1qw.18` (WKC/Block2//nodes — R-07-045 adjacency),
`worker6-83wu` + `worker6-pgsl` (SCHC Rule 7 / MQTT-SN), `worker6-b7z9.32`
(Observe fresh-PIV), `worker6-ih1v` (duty-cycle test guard), `worker6-4t5u.6`
(Renode duty tracker). Keyword-less divergences (R-07-002 port 5688, 015
Cayenne codec, 016 APRS format subset, 026 CoAP params, 030 C congestion
levels, 031 C 5.03 body, 034 app→priority mapping, 038 MQTT-SN codec, 040
MQTT-SN gateway, 041 block-wise use, 044 /firmware/upload, 045 RD) are noted
in the matrix, not beaded, per matrix preamble; see flagged set for Opus
verification.

## spec/appendix-border-router.md — coverage (sweep 2026-08-31)

2 requirements extracted. The rest of the appendix is non-normative hardware
guidance — "Hardware Recommendations" Tiers 1–3, "Power Budget Comparison",
"Backhaul Options", "Antenna Considerations" — with no RFC 2119 keywords and
no protocol behavior (procurement/installation advice; the antenna bullets use
imperative mood but regulate hardware selection, not implementations). Noted
here, not extracted as requirement rows, not beaded. Both normative statements
sit in the intro paragraph (lines 6–11); req IDs use prefix `R-ABR` (appendix
border router). Gap beads filed: 0 — the single MUST is ambiguous (see flagged
set `docs/spec-coverage-appendix-border-router-flagged.md`; if Opus rules it
divergent, file the gap bead from that set). Overflow: 0.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-ABR-001 | Gateway-owned Yggdrasil daemon MUST NOT spoof node source addresses (intro) | ambiguous | Compliant half: LICHEN-owned forwarding preserves node sources verbatim — Rs mesh→upstream TUN write of the decompressed original IPv6 (lichend.rs:939,947-951), no NAT/rewrite symbols in any stack (rg clean; cross-ref R-08N-003, R-04-010), src/dst byte-exact through the SCHC round-trip asserted in end_to_end.rs:283-323 (asserts :318-323); C: Zephyr forwarding hook does stats + MTU drop only, no address mutation (apps/gateway/src/forwarding.c:67-91). Undetermined half: the regulated artifact — the gateway-owned Yggdrasil daemon — is implemented/configured by no stack: `[yggdrasil]` config parsed and logged only (config.rs:197-212, lichend.rs:381-382; no spawn/Command anywhere in lichend.rs), daemon is operator-external per config.rs:150 ("gateway: external Yggdrasil daemon on Linux"). Whether the composed lichen0→yggdrasil deployment carries node sources into Yggdrasil (= spoofing under the strict reading of R-ABR-002) or upstream source filtering drops them is undetermined in-repo | low — flagged |
| R-ABR-002 | Native node `/128`s may enter Yggdrasil only through an identity-preserving transport for the owning node (intro; MAY + "only through" constraint) | not-implemented (conformant — MAY) | No owning-node Yggdrasil participation / identity-preserving transport exists in any stack; the mechanism is open research bead `project-LICHEN-zt3c.2.1` (delegated location agents). Adjacent plumbing that names the concept without providing the transport: Grounded-bit reachability gated on an owned TUN (set_ygg_reachable lichend.rs:439-442) with vector gateway_reachability.json consumed by rust/lichen-gateway/tests/end_to_end.rs and python/tests/rpl/test_gateway_reachability_vectors.py; classification vocabulary IDENTITY_PRESERVING_GLOBAL (Py rpl/address_classification.py:22 + vectors address_classification.json); C comment "identity-preserving BR path" (routing/router.c:655). MAY — never beaded; its interpretation decides R-ABR-001, so flagged | high |

### Histogram (rows)

- implemented+tested: 0
- implemented+untested: 0
- divergent: 0
- not-implemented: 1 (R-ABR-002 — explicit MAY, absence conformant, no bead)
- ambiguous: 1 (R-ABR-001 — the section's only MUST; flagged, no bead pending Opus ruling)

### Gap beads filed (0; cap 10; overflow 0)

None: no not-implemented or divergent MUST. R-ABR-001 is ambiguous — the
disposition question and the pre-authorized bead text live in
`docs/spec-coverage-appendix-border-router-flagged.md`.

Adjacent observation (not a requirement of this section, no bead filed):
deploy/lichend.toml.example:32-43 documents `[yggdrasil]` auto_peer/peers/
binary, but lichend only parses and logs them (config.rs:197-212,
lichend.rs:381-382) — config-schema only, no auto-peering behavior. Candidate
for the regular review loop; the appendix's normative text does not cover
auto-peering, so it is not a gap bead here.

## spec/appendix-bufferbloat.md — coverage (sweep 2026-08-31)

16 requirements extracted (0 capitalized RFC 2119 keyword rows — the appendix
is written in design-principle prose with three lowercase "must"s at lines 27,
90, 175; the lowercase-must normativity question is the section-level flag).
IDs use prefix `R-ABF` (appendix bufferbloat), following the `R-ABR` precedent.
The "Problem", "LoRa-Specific Factors", "Why Not CoDel/CAKE?", and "Further
Reading" sections are informative rationale with no behavioral requirements —
not extracted. This appendix is unusually well instrumented: dedicated vector
set tx_queue_{bounded,expiry,priority,implementation}.json,
forwarding_buffer.json (13 vectors), no_silent_drops.json,
bufferbloat_congestion.json, consumed by all three stacks. Gap beads filed
under epic `project-LICHEN-worker6-b7z9`, labels `bufferbloat` + `spec-gap`:
**0** (no capitalized MUSTs; keyword-less divergences noted in matrix per
preamble, not beaded). Gap-bead overflow: 0 (0 MUST-gaps; cap 10). If Opus
rules the lowercase musts normative, pre-authorized bead text for the
R-ABF-003/011/016 gaps lives in
`docs/spec-coverage-appendix-bufferbloat-flagged.md`.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-ABF-001 | Every queue has an explicit small bound; full → reject with error (backpressure), never silently queue (Design Principles 1) | implemented+tested | Rs: TxQueueError::QueueFull tx_queue.rs:216-225 (push :501-542; test queue_full_error :1112) + ForwardError::QueueFull forward_buffer.rs:28-34. Py: QueueFullError timing/tx_queue.py:54,185 + link/tx_queue.py:73, raised through live send link_layer.py:1428. C: -ENOBUFS tx_queue.h:169-170 + test_queue_full_returns_enobufs tests/tx_queue/main.c:281. BLE GATT QueueFull gatt.rs:92. Vectors tx_queue_bounded.json backpressure_* consumed Rs bufferbloat_vectors.rs + Py tests | high |
| R-ABF-002 | TX queue: 4 packets max | implemented+tested | Rs TX_QUEUE_CAPACITY=4 tx_queue.rs:240 (test capacity_is_four :1334) + vector capacity_default_4; Py link TX_QUEUE_CAPACITY=4 link/tx_queue.py:31 (timing CAPACITY=4); C TX_QUEUE_SIZE=LICHEN_FRAME_POOL_CAPACITY=4 frame_pool.h:21, tx_queue.h:49 + test_shared_vector_constants main.c:148 | high |
| R-ABF-003 | Forwarding: 2 packets per source max; total forwarding buffer 16 packets max (Design Principles 1 + Forwarding Buffer) | divergent | Mechanism implemented+tested at unit level in all stacks: Rs MAX_FORWARDING_SOURCES=8/MAX_PACKETS_PER_SOURCE=2 forward_buffer.rs:20-23 + tests per_source_limit_enforced/max_sources_eviction :319-384; Py ForwardingBuffer router.py:144-239 (embedded Router field :401) + link/forwarding_buffer.py:91 + test_forwarding_buffer.py (13 forwarding_buffer.json vectors) + test_router.py:958; C Kconfig 8/2/16 routing/Kconfig:121-144, router.h:65-75 + tests/routing_fwd_buffer (nacks_sent==1 main.c:123). NOT wired into any relay datapath: Rs Stack.queue_forward stack.rs:704 zero callers; Py try_buffer/dequeue zero callers in src (node forward path node.py:1451 never enqueues); C lichen_router_fwd_enqueue + lichen_router_init zero callers (router compiled in via CONFIG_LICHEN_ROUTING=y prj.conf:31 but never instantiated) | high — flagged; library-only in all 3 stacks |
| R-ABF-004 | BLE GATT: 8 messages max (returns QueueFull) (Design Principles 1) | implemented+tested | Rs lichen-meshtastic gatt.rs:39 MAX_QUEUE_DEPTH=8, GattError::QueueFull :92, queue_from_radio :371-379 (Deque push fail→QueueFull); in-file tests: full queue asserts Err(QueueFull) :580-587, deadline expiry :761+ | high |
| R-ABF-005 | Packets have deadlines; queued packets past deadline are dropped (Design Principles 2) | implemented+tested | Rs expire_before tx_queue.rs:547-573 wired into push/pop/peek/count; Py expire_stale timing/tx_queue.py:192 + link/tx_queue.py + link_layer drain :1442; C expiry in push/pop (test_invalid_incoming_deadline_expires_stale_first main.c:214). Vectors tx_queue_expiry.json (boundary now≥deadline, pop/peek/reserve trigger, requeue preserves deadline) consumed Rs bufferbloat_vectors.rs:47, Py timing/test_tx_queue_vectors.py + test_tx_queue_gen_loader.py, C tx_queue gen_vectors.py | high |
| R-ABF-006 | Routing control (RPL DIO/DAO): 5 s deadline (Design Principles 2) | implemented+tested | DEADLINE_ROUTING_MS=5000: Rs tx_queue.rs:246, Py link/tx_queue.py:35 + timing :27, C TX_DEADLINE_ROUTING_MS tx_queue.h:72-76; vector tx_queue_expiry.json default_deadline_routing asserted Rs bufferbloat_vectors.rs:51 | high |
| R-ABF-007 | ACK/NACK: 10 s deadline (Design Principles 2) | divergent | 10 s constant exists + vector-pinned: Rs DEADLINE_ACK_MS=10_000 tx_queue.rs:253, C TX_DEADLINE_ACK_MS tx_queue.h:73, Py timing :28; vector default_deadline_ack. BUT ACK is an alias of ROUTING priority in all stacks (C tx_queue.h:63; Py tx_queue_expiry.json note; Rs doc :250-252) and the effective default for ACK-priority packets is ROUTING's 5 s; no found send path passes 10 s explicitly (Rs push_tx_queue maps Routing→5 s lichend.rs:547-553; Py link_layer ACK SCHC-frag controls :1364 use default; Py link/tx_queue.py:36 defines DEADLINE_ACK_MS=5000) | low — flagged; alias-default vs spec 10 s |
| R-ABF-008 | Application data: configurable, default 60 s (Design Principles 2) | implemented+tested | DEADLINE_NORMAL_MS=60000 all stacks (Rs :259, Py link :38/timing :30, C tx_queue.h:75) + vector default_deadline_normal; every push API accepts an absolute-deadline override (configurable). Caveat: default caller priority at C L2 / Py link boundaries is BULK (lora_l2_tx.c:406, link_layer.py:1285) whose default is 120 s; 60 s binds to P3 Normal | high |
| R-ABF-009 | Priority table: 0 routing control, 1 link ACKs, 2 urgent app, 3 bulk; higher priority preempts lower (Design Principles 3) | divergent | Preemption implemented+tested everywhere (Rs try_preempt tx_queue.rs:578-633 + tests :1255-1331; Py push preemption timing/tx_queue.py:181; C test_priority_preemption main.c:306) + vectors. But the appendix's 4-level table diverges from the implemented 5-level P0=SOS/P1=ROUTING+ACK/P2=URGENT/P3=NORMAL/P4=BULK model (Rs tx_queue.rs:273-284, Py link/tx_queue.py:42-70, C tx_queue.h:60-68), which matches main spec 07-transport §10.2.4 (row R-07-033) and tx_queue_priority.json | high — flagged; appendix vs main-spec table coherence |
| R-ABF-010 | Queue full → sender gets error: ENOBUFS/QueueFull for immediate sends; senders must handle (Design Principles 4) | implemented+tested | Same surfaces as R-ABF-001: C lora_l2_tx propagates push failure lora_l2_tx.c:406-413; Py send raises QueueFullError to caller (link_layer.py:1428 + tests/link/test_link_tx.py); Rs TxQueue::push returns Err (tests :1112-1133). Caveat: Rs daemon push helpers swallow to warn+drop (lichend.rs:555-558,586-589) — flagged (see flagged set) | high |
| R-ABF-011 | NACK to mesh source for mesh-forwarded packets when full (Design Principles 4+5; "send NACK upstream") | not-implemented | No NACK message/transmission in any stack (rg -i nack: comments, counters, hooks only). C: nacks_sent counter + -ENOBUFS, no frame router.c:1410-1411 (test asserts counter routing_fwd_buffer main.c:123). Py: on_drop hook "caller uses this to send NACK" forwarding_buffer.py:56,121 zero callers; vector-designated NACK shape = ICMPv6 DEST_UNREACHABLE/ADMIN_PROHIBITED make_resource_exhausted icmpv6.py:407 (tested via no_silent_drops.json) never invoked on a drop path. Rs: doc comments only forward_buffer.rs:30,107, stack.rs:90,695 | high — flagged; pre-authorized bead if lowercase musts count |
| R-ABF-012 | No silent drops: return error to local sender (Design Principles 5) | implemented+tested | Same sites as R-ABF-001/010; no_silent_drops.json tx_queue_full_raises_exception consumed by Py routing/test_no_silent_drops_vectors.py + timing/test_tx_queue_vectors.py | high |
| R-ABF-013 | No silent drops: log queue-full events for diagnostics (Design Principles 5) | implemented+tested | Py: warning on preemption link/tx_queue.py:129, eviction warning forwarding_buffer.py:223 + router.py, backpressure debug :193; test_eviction_logged_at_warning (test_no_silent_drops_vectors.py). Rs: warn! on QueueFull lichend.rs:555-558,586-589. C: LOG_WRN on push failure at the wired site lora_l2_tx.c:409-410; tx_queue.c itself is stats-only (no log statements); unwired C fwd buffer unlogged | high |
| R-ABF-014 | queue_stats fields: packets_queued, packets_dropped_deadline, packets_dropped_full, max_latency_ms, avg_latency_ms (Measuring Queue Latency) | implemented+tested | Rs TxQueueStats tx_queue.rs:406-427 (+packets_preempted) with tests stats_tracking/packets_dropped_full_counter/latency_tracking_basic/max/latency_ewma_smoothing :962-1488; Py TxQueueStats timing/tx_queue.py:98-108 + link/tx_queue.py:174-191 + vector stats_track_latency (tx_queue_bounded.json:199-205); C tx_queue_stats tx_queue.h:108-121 + /status/queues encoder emits exactly the 5 spec keys status_cbor.c (Rs client doc status.rs:181-183) | high |
| R-ABF-015 | Expose queue stats via /status/queues CoAP resource (Measuring Queue Latency) | implemented+untested | C gateway: Observable resource {"status","queues"} apps/gateway/src/main.c:504-601 + encoder status_cbor.{h,c}:17-50; no C test (gateway_status suite lacks queues; rg encode_queues → apps only). Rs client: paths.rs:25 STATUS_QUEUES + QueueStats::from_cbor status.rs:186-215 + test queue_stats_decode_firmware_map :404 (oracle = mirrored firmware keys, not C encoder bytes). Py: absent both sides | high |
| R-ABF-016 | Bufferbloat avoidance must be tested under congestion: 5 scenarios (Testing) | divergent | Oracle bufferbloat_congestion.json pins all 5 (literals from spec) asserted Rs bufferbloat_vectors.rs:105-146 + Py test_bufferbloat_congestion_vectors.py. Scenarios 1-3 (queue-full/deadline/preemption) have real tests in all stacks (R-ABF-001/005/009). Scenario 4 multihop_latency (e2e delay bounded under load): expectation string only, no multi-hop latency-under-load test anywhere. Scenario 5 fairness: per-source unit tests only (R-ABF-003), no under-load test — and the mechanism is unwired, so one could not pass today | high — flagged |

### Histogram (rows)

- implemented+tested: 10 (R-ABF-001, 002, 004, 005, 006, 008, 010, 012, 013, 014)
- implemented+untested: 1 (R-ABF-015)
- divergent: 4 (R-ABF-003, 007, 009, 016)
- not-implemented: 1 (R-ABF-011)
- ambiguous: 0

### Gap beads filed (0; cap 10; overflow 0)

No capitalized RFC 2119 MUSTs exist in this appendix, so no gap beads are due
per the matrix preamble (consistent with the spec/08-nodes and
spec/01-architecture sweeps). The divergences are recorded above and in
`docs/spec-coverage-appendix-bufferbloat-flagged.md`, which also carries the
section-level question (do the lowercase "must"s at spec lines 90/175 carry
normative force?) and pre-authorized bead text for R-ABF-003 (forwarding
buffer unwired in all three stacks), R-ABF-011 (NACK never sent), and
R-ABF-016 (congestion scenarios 4-5 untested) should Opus rule them
MUST-gaps. No pre-existing beads were duplicated by this sweep.

## spec/appendix-c-safety.md — coverage (sweep 2026-08-31)

17 requirements extracted (prefix `R-APPC`, following the `R-ABR`/`R-ABF`
precedent). This appendix is a build/CI policy section, not a wire-protocol
section: "test evidence" means a wired CI gate or harness, not a unit test;
several rows are configuration or process requirements. Not extracted as
requirements: the flag-purpose tables, ASan/UBSan catch-lists, Coverity setup
instructions, the fuzz-harness example, the hardware-status table (informative),
and the CERT rule summary tables (enforced via the analyzers — cited in the
R-APPC-010/011 rows). The `-fbounds-safety`/`safe-stack`/MTE/CHERI/CET items
and the "Future: Hardware Memory Safety" table are keyword-less or lowercase-
should and explicitly conditional/future — noted, never beaded. Gap beads filed
under epic `project-LICHEN-worker6-b7z9`, labels `c-safety` + `spec-gap`
(+`zephyr`/`ci` where apt): **6** (cap 10; overflow 0). R-APPC-009 and
R-APPC-013 share bead `project-LICHEN-worker6-b7z9.50` (one fix site:
fuzz testcase.yaml + sanitizers.conf wiring). Adjacent hygiene observation (not
a spec requirement, not beaded here): build debris is committed under
`lichen/tests/fuzz/build/` (incl. `a.out`) and stray `*.o` files sit next to
the fuzz sources.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-APPC-001 | All C code MUST be compiled with these flags (Basic Flags block: -Wall -Wextra -Werror, -Wformat=2 -Wformat-security -Wformat-truncation=2, -Wshadow, -Wconversion -Wno-sign-conversion, -Wdouble-promotion, -Wnull-dereference, -Wcast-align, -Wlogical-op -Wduplicated-cond -Wduplicated-branches, -Warray-bounds=2, -Wstack-usage=2048, -Wswitch-enum, -Wstrict-aliasing=2 -fstrict-aliasing, -Wmaybe-uninitialized, -fstack-protector-strong) | divergent | Full set implemented: `LICHEN_HARDENING_FLAGS` lichen/zephyr/CMakeLists.txt:48-135, applied to every lichen module library target (:169-185); host tests via lichen/tests/cmake/test_common.cmake:56-63. Documented deviations: -Wno-error=conversion :71, -Wno-error=cast-align :78, -Wno-error=duplicated-branches :110, -Wno-error=cpp :125; -fstack-protector-strong deliberately not raw — routed via CONFIG_STACK_CANARIES (:115-118; Zephyr emits -fstack-protector-all), literal flag in test_common.cmake:63; per-file exemptions: vendored lr1110 (drivers/lora/lr1110/CMakeLists.txt:22), monocypher -Wno-error=stack-usage (subsys/lichen/crypto/CMakeLists.txt:13-19). Spec preamble: "NO EXCEPTIONS. NO WAIVERS." — bead `project-LICHEN-worker6-b7z9.51` | high |
| R-APPC-002 | When toolchain supports it, enable advanced protections: CFI + hidden visibility (Clang 18+), -fbounds-safety, -fsanitize=safe-stack (keyword-less conditional imperative) | implemented+untested (CFI only) | CFI: lichen/zephyr/CMakeLists.txt:141-154 enables -fsanitize=cfi -fvisibility=hidden when Clang >= 18 (dormant under GCC-based Zephyr SDK 0.16.8; no test can exercise it today). -fbounds-safety / -fsanitize=safe-stack: zero hits repo-wide — precondition (Clang 18+ toolchain in use) unmet, conformant absence | high |
| R-APPC-003 | All new code MUST use bounds annotations where applicable (__counted_by, _Nonnull/_Nullable, nonnull attr, pass_object_size) | implemented+untested | Annotations present in 15+ files: lichen/subsys/lichen/hal/include/lichen/hal.h (23 matches), gcp/include/lichen/gcp_trust.h (25), oscore/include/lichen/edhoc.h (33), schc/include/lichen/schc.h (9), link/include/lichen/tx_queue.h (18), oscore/oscore_ctx.c (19). No CI mechanism verifies "all new code" — flagged (low) | low |
| R-APPC-004 | Hardware memory safety (MTE/CHERI/CET) "should be enabled when LICHEN runs on Linux/application processors"; spec itself: "not yet applicable to Cortex-M" | not-implemented (conformant — explicitly future, lowercase should) | Zero hits for -fsanitize=memtag / -fcf-protection repo-wide | high |
| R-APPC-005 | All firmware builds MUST enable in prj.conf: CONFIG_STACK_CANARIES=y, CONFIG_STACK_SENTINEL=y | implemented+untested | lichen/apps/gateway/prj.conf:54-55, lichen/apps/puck/prj.conf:62-63, firmware/bridge-zephyr/prj.conf:40-41, lichen/tests/util/prj.conf:10-11 (20 .conf files carry CONFIG_STACK_CANARIES=y per rg) | high |
| R-APPC-006 | ...CONFIG_ASSERT=y, CONFIG_ASSERT_VERBOSE=y (disable only in release with explicit justification) | implemented+untested | Same sites: gateway prj.conf:56-57, puck:64-65, bridge-zephyr:42-43, tests/util:12-13 | high |
| R-APPC-007 | ...CONFIG_THREAD_ANALYZER=y, CONFIG_THREAD_ANALYZER_USE_PRINTK=y, CONFIG_THREAD_ANALYZER_AUTO=n (CI and debug builds) | not-implemented | Zero hits repo-wide for CONFIG_THREAD_ANALYZER* in any .conf/Kconfig (rg over lichen/ + firmware/). Qualifier "(CI and debug builds)" ambiguity — flagged; bead `project-LICHEN-worker6-b7z9.49` | high |
| R-APPC-008 | ...CONFIG_SYS_HEAP_VALIDATE=y (debug builds) | not-implemented | Zero hits repo-wide; same qualifier ambiguity — flagged; bead `project-LICHEN-worker6-b7z9.49` | high |
| R-APPC-009 | All tests run on native_sim MUST use AddressSanitizer and UndefinedBehaviorSanitizer (CONFIG_ASAN=y CONFIG_UBSAN=y, or CMake -fsanitize=address,undefined) | divergent | Standalone host CMake path compliant+tested: lichen/tests/cmake/test_common.cmake:18-19,69-86 (ASan+UBSan, -fno-sanitize-recover=all) consumed by tests/schnorr48/CMakeLists.txt:37, tests/replay/CMakeLists.txt:18, tests/tx_queue and others; CI c-standalone-tests builds them (ci.yml:137+). Zephyr native_sim path non-compliant: lichen/tests/sanitizers.conf exists (CONFIG_ASAN=y CONFIG_UBSAN=y, header cites the policy) but is referenced by nothing — no prj.conf includes it, no CI invocation passes it via EXTRA_CONF_FILE (only renode_console.conf ever is). Bead `project-LICHEN-worker6-b7z9.50` | high |
| R-APPC-010 | All C code MUST pass clang-tidy with this configuration (checks list; WarningsAsErrors '*'; CI command over lichen/subsys\|lib\|drivers) | divergent | lichen/.clang-tidy exists citing the policy (:5), WarningsAsErrors '*' (:63); config is a superset with documented suppressions beyond spec: -clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling :32, -misc-redundant-expression :35, -misc-header-include-cycle :37, -bugprone-not-null-terminated-result :38, -clang-diagnostic-conversion :39, -clang-analyzer-optin.core.EnumCastOutOfRange :40; contradictory duplicate: pro-bounds-pointer-arithmetic enabled :15 vs disabled :41 (later wins). CI scope: .github/workflows/ci.yml:130-136 — `find ... \| head -50` (first 50 files, not all C code) with `-p /dev/null` (no compile DB); local scripts/lint-c.sh:63-76 covers all subsys/lib/drivers files. Bead `project-LICHEN-worker6-b7z9.47` | high |
| R-APPC-011 | cppcheck (Mandatory): --error-exitcode=1 with --suppressions-list=lichen/.cppcheck-suppressions; "Correctness classes (uninitvar, comparePointers, syntaxError outside known files) always fail the build" | divergent | Runners exist: .github/workflows/ci.yml:105-121, scripts/lint-c.sh:44-56 (--error-exitcode=1 --inline-suppr). But neither passes --suppressions-list (curated file lichen/.cppcheck-suppressions unwired), and both suppress syntaxError globally on the command line, contradicting the "syntaxError outside known files always fail" contract (file confines it to 5 known files, :13-17); scope subsys/lib/drivers only vs spec's `lichen/` (apps/tests unscanned); enable list adds portability. Bead `project-LICHEN-worker6-b7z9.48` | high |
| R-APPC-012 | Coverity Scan weekly via .github/workflows/coverity.yml (secrets COVERITY_SCAN_TOKEN/EMAIL; dashboard reviewed manually) | implemented+untested | .github/workflows/coverity.yml: weekly cron '0 0 * * 0' + workflow_dispatch; skips gracefully when secrets absent (matches the spec's once-per-fork setup steps) | high |
| R-APPC-013 | All code that parses untrusted input MUST be fuzz-tested (frame.c, schnorr48.c, schc.c) | divergent | Harnesses exist for all three named parsers: lichen/tests/fuzz/fuzz_frame.c:22 (LLVMFuzzerTestOneInput → lichen_frame_parse), fuzz_schc.c, fuzz_schnorr48.c (schnorr48_verify); CMakeLists.txt builds with -fsanitize=fuzzer or standalone+sanitizers. But no CI execution is wired: fuzz.yml:96-144 zephyr-fuzz runs `west twister -T lichen/tests/fuzz -p native_sim` nightly (schedule-only :99), yet the dir has no testcase.yaml/prj.conf → twister discovers nothing; ci.yml has no fuzz job; Rust cargo-fuzz + Python hypothesis jobs (fuzz.yml:44,153) are schedule-only with continue-on-error. Shared bead with R-APPC-009: `project-LICHEN-worker6-b7z9.50` | high |
| R-APPC-014 | Never use these functions: strcpy, strcat, sprintf, gets | divergent | Production strcpy: lichen/subsys/lichen/coap/checkin.c:1670 (`strcpy(rc->id, req.id)`), :1673 (`strcpy(rc->creator, creator)`), lichen/subsys/lichen/coap/slot_claim_settings.c:249 (constant prefix). Tests use strcpy/strcat freely (tests/checkin_rollcall/main.c:389+, tests/slot_claim_settings/main.c:179-180). No sprintf/gets in lichen/ or firmware/ (word-boundary rg clean). Bead `project-LICHEN-worker6-b7z9.46` | high |
| R-APPC-015 | Always use safe alternatives (strncpy/strlcpy, snprintf...); always check return values (snprintf truncation/error) | divergent | snprintf is the norm (17 call sites in subsys/lib/drivers); adjacent return/truncation checks found at ~7 sites (rg -A1 heuristic — some checks may be further away). Backstop: -Wformat-truncation=2 is fatal under -Werror (not waived), lichen/zephyr/CMakeLists.txt:57 | low — flagged |
| R-APPC-016 | Always pass explicit sizes; use sizeof on arrays, not pointers | ambiguous | Style-level rules with no dedicated enforcement found; clang-tidy cppcoreguidelines-* + cppcheck cover classes of it; no systematic audit performed — cannot verify compliance repo-wide. Flagged for a decision on enforcement mechanism | low |
| R-APPC-017 | All protocol logic in C MUST have equivalent tests against Python and Rust using shared test vectors ("spec/test-vectors/"; C: ZTEST_F with vector loader) | implemented+tested | C tests consume the shared vectors: lichen/tests/schnorr48/main.c:6,137-197 (vectors from test/vectors/schnorr48.json), tests/oscore_schc_roundtrip/generate_vectors.py, tests/routing_dispatch/gen_vectors.py, tests/edhoc_export/generate_fixture.py, tests/rpl_dao_sequence/main.c, tests/ping_l2/main.c, tests/coap_codec/generate_vectors.py; same JSONs feed the Python and Rust suites. Note: spec's stated path spec/test-vectors/ exists with 5 legacy files (frame, oscore, rpl, schc, schnorr48) but the canonical, consumed location is test/vectors/ — doc-path divergence, flagged (minor) | high |

### Histogram (rows)

- implemented+tested: 1 (R-APPC-017)
- implemented+untested: 5 (R-APPC-002, 003, 005, 006, 012)
- divergent: 7 (R-APPC-001, 009, 010, 011, 013, 014, 015)
- not-implemented: 3 (R-APPC-004 conformant-future, 007, 008)
- ambiguous: 1 (R-APPC-016)

### Gap beads filed (6; cap 10; overflow 0)

- `project-LICHEN-worker6-b7z9.46` (P1) — R-APPC-014: banned strcpy() in production C
- `project-LICHEN-worker6-b7z9.47` (P2) — R-APPC-010: clang-tidy CI scope + config drift
- `project-LICHEN-worker6-b7z9.48` (P2) — R-APPC-011: cppcheck suppressions file unwired, syntaxError global
- `project-LICHEN-worker6-b7z9.49` (P2) — R-APPC-007/008: THREAD_ANALYZER*/SYS_HEAP_VALIDATE absent
- `project-LICHEN-worker6-b7z9.50` (P1) — R-APPC-009/013: native_sim sanitizers + fuzz harness CI wiring orphaned
- `project-LICHEN-worker6-b7z9.51` (P2) — R-APPC-001: -Werror waivers + per-file exemptions vs "NO WAIVERS"

SHOULD-gaps: none filed (R-APPC-004 is explicitly future/conditional; R-APPC-015/016
omissions do not break a documented wire feature — noted in matrix and flagged).
MAYs: none present. No oscore/EDHOC-semantics changes are planned by any bead
here (annotations in oscore headers are cited as evidence only).

---

## spec/drafts/draft-lichen-schnorr-00.md — coverage (sweep 2026-08-31)

17 requirements extracted (prefix `R-SCHORR`, following the `R-APPC`/`R-ABR`
precedent). Not extracted as requirements: §1 intro/design goals, §2
terminology (RFC 2119 boilerplate), §6.1/§6.2/§6.4 security prose
(informative), §7 IANA ("no actions"), §8 references, and §6.5 items 1/2/4
(keyword-less deployment/platform guidance). §6.5 item 3 ("Implement batch
verification") is folded into R-SCHORR-015 with §5.4. The Appendix A corpus
lives at the path the draft names (`test/vectors/schnorr48.json`, 16 vectors:
6 valid incl. the determinism vector, 10 invalid) and is consumed by all
three implementations; a stale copy also sits under `spec/test-vectors/`
(legacy-path divergence already noted in the R-APPC-017 row). Every MUST is
implemented; zero gap beads filed (cap 10; overflow 0). MUST rows 003-005
share the sign path, 006-009 the verify path, 012-013 the profile call sites;
each keeps its own row. Threat-model note: the draft's §5.3 constant-time
MUST predates the repo threat model (radio adversary only, no timing
requirements — AGENTS.md); row R-SCHORR-010 records how that is handled and
is flagged, not beaded. oscore/EDHOC: `edhoc/edhoc_sign.c` merely wraps
schnorr48 sign/verify and is cited as a caller; no EDHOC semantics are
planned or changed by this sweep.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-SCHORR-001 | Curve25519 in Edwards form (RFC 8032 base point); SHA-512, output interpreted little-endian and reduced mod L when used as a scalar (§3.1-3.2) | implemented+tested | py `L`+`_hash_to_scalar` python/src/lichen/crypto/schnorr48.py:20,57-62; C `crypto_eddsa_reduce` lichen/subsys/lichen/crypto/monocypher.h:246; rust `schnorr48` crate 0.1.0 (curve25519-dalek+sha2, rust/Cargo.lock:3243-3251); full corpus test/vectors/schnorr48.json bit-exact in all 3 langs | high |
| R-SCHORR-002 | Key generation per RFC 8032 §5.1.5: seed→SHA-512→clamp, pubkey = privkey*B; existing Ed25519 keypairs MAY be used directly (§3.3) | implemented+tested | py clamp+derive_keypair schnorr48.py:82-106; C schnorr48_derive_keypair lichen/subsys/lichen/link/schnorr48.c:38-56; rust keys.rs:12 (clamped Ed25519 scalar/point formats). Tests: py test_schnorr48.py:32-66, rust derive_vector1/2 rust/lichen-link/src/schnorr.rs:174-212, C test_keypair_derivation lichen/tests/schnorr48/main.c:272. MAY-part: same 32-byte formats as standard Ed25519 everywhere | high |
| R-SCHORR-003 | Nonce deterministic: r = H(privkey \|\| msg) mod L (§4.2 step 1) | implemented+tested | py :123; C :83-91; rust via crate (corpus sign parity); determinism vector 16 + py test_deterministic python/tests/crypto/test_schnorr48.py:82-90, rust canonical_deterministic_signature_matches_repeatedly rust/lichen-link/tests/schnorr48_vectors.rs:143-176 | high |
| R-SCHORR-004 | R = r*B; e = H(R\|\|pubkey\|\|msg)[0:16] (128-bit truncated challenge); e_scalar = e \|\| zeros(16) (§4.2 steps 2-3) | implemented+tested | py :125-132; C :93-116; rust crate via bit-exact sign parity across all 16 corpus vectors | high |
| R-SCHORR-005 | s = (r + e_scalar*privkey) mod L; signature = e \|\| s — 48 bytes, challenge first, response second (§4.2 steps 4-5, §4.4) | implemented+tested | py :134-138; C :109-122 (`crypto_eddsa_mul_add`), `_Static_assert(SCHNORR48_SIG_LEN==48)` main.c:14; sign parity tests: py test_valid_signatures, rust sign_matches_vectors schnorr.rs:256-270, C test_sign_matches_vectors main.c:334 | high |
| R-SCHORR-006 | Verify: parse e(16)/s(32); R' = s*B − e_scalar*pubkey; e' = H(R'\|\|pubkey\|\|msg)[0:16]; VALID iff e' == e_received (§4.3) | implemented+tested | py :141-193; C :135-202 — `crypto_eddsa_recover_r` (LICHEN extension, lichen/subsys/lichen/crypto/monocypher.c:2990-3010) additionally rejects invalid point and s >= L; rust crate + verify tests. Full corpus verify in all 3 langs. Note: implementations add extra rejections beyond the spec text — flagged | high |
| R-SCHORR-007 | Signatures that are not exactly 48 bytes and all six A.2 invalid cases MUST be rejected (wrong msg, tampered e, tampered s, wrong pubkey, 47-byte truncated, all-zero) | implemented+tested | JSON vectors 6-11; py test_invalid_signatures :69-79 + length rejects :101-112; rust corpus malformed-length + invalid branches schnorr48_vectors.rs:79-95, invalid_* schnorr.rs:284-332, truncated 47B in two_node_frame_exchange :504-517; C test_verify_invalid_signatures main.c:410-433 passes the 47-byte vector at its true sig_len | high |
| R-SCHORR-008 | Truncated challenge extended with 16 zero bytes, interpreted as little-endian integer; value already < L (§5.1) | implemented+tested | py :132,:181-182; C :112-116,:174-177 (Monocypher LE); rust corpus parity | high |
| R-SCHORR-009 | Verification performs one fixed-base s*B, one variable-base e*pubkey, one point subtraction (§5.2) | implemented+tested | py :185-187 (`_point_sub`); C crypto_eddsa_recover_r monocypher.c:2990-3010; rust dalek mults in crate; every corpus verify exercises recovery | high |
| R-SCHORR-010 | Implementations MUST use constant-time operations for scalar multiplication and signature comparison (§5.3) | implemented+untested | C: Monocypher constant-time primitives + crypto_verify16/32 comparisons (schnorr48.c:169,:201,:210,:501,:538); rust: curve25519-dalek + subtle (Cargo.lock:3248-3250); python: plain `==`/frozenset (schnorr48.py:44,:160,:193) — out of scope per project threat model (radio adversary only). CT is not unit-testable; spec text conflicts with repo threat model — flagged, not beaded | low — flagged |
| R-SCHORR-011 | An application profile MAY pass a fixed-length, domain-separated digest as msg; the profile spec defines that digest/transcript (§5.5) | implemented+tested | link profile domain `LICHEN-LINK-v1\0` (rust schnorr.rs:28, C schnorr48.c:284-286; tested si_frame_serialises_and_verifies schnorr.rs:701-756 + C cross-language oracle main.c:576); SOS origin 64B digest lichen/subsys/lichen/link/sos_origin.c:111-118,:151; slot-claim 32B digest lichen/subsys/lichen/coap/coap_slot_coord.c:406,:922; announce lichen/subsys/lichen/routing/announce.c:386,:781 | high |
| R-SCHORR-012 | DAO Origin Signature profile: Schnorr48 MUST sign the complete 64-byte SHA-512 digest defined by its RPL profile, directly (§5.5) | implemented+tested | py dao_origin.py:396-401 (`verify(pubkey, <64B digest>, sig)`); rust lichen-rpl/src/verify.rs:94 + dao_origin_digest :127-143; C independent oracle test/vectors/dao_origin_signature_oracle.c (domain `LICHEN-DAO-ORIGIN-v1`); vectors test/vectors/dao_origin_signature.json consumed by python/tests/rpl/test_dao_origin.py:1314, rust/lichen-rpl/tests/dao_origin_vectors.rs:23, rust/lichen-node/tests/dao_origin_vectors.rs:15. C production RPL DAO-origin verify absent from lichen/subsys — scope note in flagged file | high |
| R-SCHORR-013 | MUST NOT hash, truncate, decode, or append a NUL to the application transcript before applying §4.2; the SHA-512 intrinsic to §4.2 still applies (§5.5) | implemented+tested | every profile call site passes digest/transcript bytes unmodified into sign/verify: py dao_origin.py:401; rust verify.rs:94; C sos_origin.c:151; EDHOC wrapper lichen/subsys/lichen/edhoc/edhoc_sign.c:31-41 (msg untouched); repo-wide search found no call site pre-hashing a 64-byte digest or NUL-terminating it | high |
| R-SCHORR-014 | Deterministic nonce (RFC 6979 style); same key+msg ⇒ same signature; random nonce generation NOT RECOMMENDED (§6.3) | implemented+tested | deterministic path in all 3 langs (R-SCHORR-003); corpus determinism vector (JSON #16) with explicit repeated-sign assertions py test_valid_signatures :61-66 + test_deterministic :82-90 and rust vectors.rs:119-130,:143-176; C re-sign parity test_sign_matches_vectors main.c:334 (single re-sign; no literal double-call — minor, flagged); no random-nonce path exists in any implementation | high |
| R-SCHORR-015 | Batch verification "supported" with standard Schnorr batch technique, ~2x faster for large batches; "Implement batch verification when processing multiple signatures" (§5.4, §6.5 item 3 — keyword-less) | not-implemented | zero batch-verify hits repo-wide in rust/, python/src/, lichen/ (only an unrelated Python docstring match). No RFC 2119 keyword; capability statement + keyword-less recommendation; omission breaks no documented wire feature → noted, not beaded | high |

### Histogram (rows)

- implemented+tested: 12 (R-SCHORR-001…009, 011, 012, 013 minus 010 → 001, 002,
  003, 004, 005, 006, 007, 008, 009, 011, 012, 013, 014 — 13 rows carry the
  label; R-SCHORR-012 shares it across three profile implementations)
- implemented+untested: 1 (R-SCHORR-010 — constant-time; untestable by unit
  test, satisfied via vetted CT libraries in C and Rust)
- divergent: 0
- not-implemented: 1 (R-SCHORR-015 — keyword-less capability statement)
- ambiguous: 0

### Gap beads filed (0; cap 10; overflow 0)

None. Every MUST in this draft (R-SCHORR-003…007, 010, 012, 013) is
implemented and vector-tested across the Python reference, Rust
`lichen-link`/`schnorr48` crate, and C Monocypher implementation. The single
SHOULD NOT (random nonces, R-SCHORR-014) is satisfied — no random-nonce path
exists. R-SCHORR-015 (batch verification) carries no RFC 2119 keyword and
breaks no documented wire feature, so no bead. R-SCHORR-010's spec-vs-threat-
model conflict is a documentation reconciliation, filed to the flagged set
only. MAYs (R-SCHORR-002 partial, R-SCHORR-011) never beaded per protocol.
