<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

## spec/12-apps.md — coverage (sweep 2026-09-01)

No decisions in `spec/decisions.jsonl` target 12-apps (Step 0: clean).

Statuses: IT = implemented+tested, IU = implemented+untested, D = divergent, NI = not-implemented, A = ambiguous.

### 18.1 Messaging

| Req | Spec text (trimmed) | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-001 | All features use CoAP with CBOR payloads | IT | `python/src/lichen/coap/resources/messaging.py:424-442`; test `test_messages_resource.py::test_post_valid_lci_message_body`; vectors `test/vectors/messaging.json` | high |
| R-12-002 | POST /msg/inbox → 2.01 + Location-Path /msg/sent/{id} | IT | messaging.py:424-442; Rust `lichen-client/src/msg.rs:85-141`; C `coap_msg.c` | high |
| R-12-003 | GET /msg/inbox observable, `{messages, unread}` | IT | messaging.py:223,314-320; tests `test_observe_notified_on_deliver/post`; vector `inbox_get_observable` | high |
| R-12-004 | When ack:true, recipient POSTs /msg/ack with id/status/ts | IT | messaging.py:525-600; `receipt_vectors.rs`; vectors `receipt_cbor.json` | high |
| R-12-005 | GET /msg/canned returns configurable catalog (5 default entries) | IT | messaging.py:445-456; `test_default_catalog_matches_spec`; `messaging_vectors.rs:261 canned_catalog_matches_spec_18_1_3` | high |
| R-12-006 | POST {"canned": N} expands canned message | IT | messaging.py:349-360; `test_post_canned_expands_body` | high |
| R-12-007 | Message CBOR fields id/from/to/ts/body/ack/priority/reply_to/ttl | IT | messaging.py:361-394; msg.rs:89-124; vector `inbox_post_full_message` | high |
| R-12-008 | ts included only when wall_clock_valid; receivers MAY accept ts absent/0 | D | Senders rebound `from` (messaging.py:339-348) but no wall_clock_valid gating or ts=0 "time unknown" acceptance found | low |
| R-12-009 | Nodes without wall-clock SHOULD NOT enforce TTL expiry | NI | No TTL expiry enforcement exists on /msg at all (only validation, messaging.py:376-377); C struct has no ttl field (coap_msg.h:70-83) | low |
| R-12-010 | Store-and-forward nodes advertise `rt="msg.store"`; MUST comply with storage limits (8/16/64 msgs, TTL 1-24h) | NI | No `/msg/store` resource anywhere; grep msg/store, msg.store negative | high |
| R-12-011 | Eviction: expired → per-destination fair-share → FIFO | NI | Fair-share-per-destination eviction not found; inbox eviction is plain FIFO (messaging.py:278-279) | high |
| R-12-012 | Back-pressure: 5.03 storage_full / 4.13 too large / 4.03 blacklisted / 4.00 TTL too long | D | Only ad hoc: 4.13 on >1024B body, 5.03 on msg-id exhaustion (messaging.py:330,398); spec form only exists for deaddrop (deaddrop.py:593) | low |
| R-12-013 | S&F MUST NOT dynamically allocate starving routing/buffers | IU | C uses static buffers (`s_inbox` coap_msg.c:136-138); no S&F module exists to violate this | low |

### 18.2 Position Sharing

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-014 | Nodes with GPS SHOULD periodically broadcast position via PUT /pos | IT | C `coap_location.c:195-230` (NON PUT, senml+cbor, ff02::1); Py receiver `senml.py:126-233`; test `coap_location_beacon` | high |
| R-12-015 | Beacon interval 60s moving / 300s stationary, configurable | IU | `coap_location.h:22-23` (60000/300000), selection coap_location.c:427-428; C test main.c:374-466; no Python scheduler | high |
| R-12-016 | Receivers update position cache; GET /pos/cache | IT | Py `position.py:22-165`; Rust pos.rs:218-252; tests `test_position_cache.py`, `position_cache_vectors.rs`; vector `position_cache.json` | high |
| R-12-017 | GET /sensors/location returns SenML lat/lon/alt/speed/heading | IT | `senml.py:54-123`; test `test_senml_location_vectors.py`; vector `senml_location.json` | high |
| R-12-018 | Observe /sensors/location; notify on distance/time threshold | IT | ObservableResource senml.py:54; Rust `PositionSubscription` pos.rs:286-292; vector `position_observe.json` (threshold logic not evidenced — flagged) | low |
| R-12-019 | Privacy modes public/group/private/off at /config/privacy | D | C has all 4 (coap_location.h:34-38); Python has only 3, no "off" (position_privacy.py:23-28); no Rust client | high |
| R-12-020 | Unauthenticated queries to non-public nodes → 4.01 `oscore_required` | D | C enforces (coap_location.c:1174-1175,1383-1413); Python `PositionPrivacyPolicy.check_read` returns 4.01 (position_privacy.py:90-107) but NOT wired into `SenMLLocationResource.render_get` (senml.py:110-113) | high |
| R-12-021 | Group mode: beacons encrypted with group OSCORE key to ff35 mcast | NI | No ff35 or OSCORE-encrypted beacon path; C beacons public-mode only (bead l1qw.10.5.1.4 tracks) | high |
| R-12-022 | Private mode: no beacons, whitelist via PUT /config/privacy/allowed | IT | Py `privacy_config.py:43-83`, policy whitelist position_privacy.py:51-74; C coap_location.c:1547-1550; tests `test_privacy_config.py` | high |
| R-12-023 | Presence is not hideable; no cover traffic (design constraint, no requirement) | — | Documentation only; no implementation requirement | n/a |

### 18.3 Waypoints / Routes

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-024 | /waypoints list/get/create/share/broadcast/delete CRUD | IT | Py `waypoints.py:190-355`; Rust `waypoint.rs:332-418`; C `coap_waypoints.c:864-1190`; tests `test_waypoints_resource.py`, `waypoint_vectors.rs:27`, C coap_waypoints; vectors `waypoint.json` (23) | high |
| R-12-025 | MUST bound: 32 waypoints per originator IID, 256 global | IT | waypoints.py:20-21,155-160,252-258; coap_waypoints.h:16-17; tests `test_waypoints_reject_33rd_per_originator`, `test_waypoints_capped_at_max` | high |
| R-12-026 | Full table POST → 5.03 with `{reason:"waypoint_limit",per_originator:32,global:256}` | IT | waypoints.py:162-175; coap_waypoints.c:284-290; C test `test_global_limit_is_256_with_503_body` | high |
| R-12-027 | /routes, /routes/{id} — same CRUD as waypoints | NI | No /routes waypoint resource in Py/Rust/C (only routing-table /status/routes) | high |

### 18.4 Emergency / SOS

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-028 | All SOS messages MUST be authenticated (link-layer signature, verified at each node before rebroadcast) | IT | C sos_origin.c:126-158, coap_server.c:530; Py emergency.py:232-256; `sos_origin_vectors.rs` (vector sos_signature.json); `test_sos_origin.py` | high |
| R-12-029 | Unsigned/invalid SOS silently dropped | D | C: silent no-relay (sos_origin.h:19); Python returns 4.01 (emergency.py:237-238) — rejects, not silent drop | low |
| R-12-030 | Per-source rate limits: 10-min cooldown, 3/hour, burst 2 | IT | sos_ratelimit.h:37-43, sos_ratelimit.c:104-179; Py emergency.py:31-33,122-152; `sos_rate_limit_vectors.rs` (sos_rate_limiting.json); C `lichen/tests/sos_ratelimit/` | high |
| R-12-031 | Rate limiting uses monotonic uptime, not wall-clock | IT | sos_ratelimit.h:20-24, k_uptime_get; Py `time.monotonic` emergency.py:93 | high |
| R-12-032 | Exceeding rate limit: dropped and logged, not relayed | IT | sos_ratelimit.c:137-149; Py 4.29 + retry_after emergency.py:263-271 | high |
| R-12-033 | Soft blacklist reputation (-1/-2/-10, reset, 7d expiry) | NI (MAY-gated feature; no impl) | No reputation scoring anywhere; noted, not filed (MAY) | n/a |
| R-12-034 | Nodes SHOULD support operator override (clear limit, blacklist, disable) | NI (SHOULD-gap) | No operator override API found; noted in matrix, not filed | n/a |
| R-12-035 | SOS CBOR format type/node/ts/lat/lon/msg/seq + alert types table | IT | sos_alert.h:10-27, sos_alert.c codec; vectors sos_cbor.json; `sos_cbor_vectors.rs` | high |
| R-12-036 | POST coap://[ff02::1]/sos (multicast SOS endpoint) | NI | Only unicast POST /sos (coap_server.c:574; emergency.py:202) | high |
| R-12-037 | Receiving nodes: display, re-broadcast once TTL-limited, log to /sos/log | D | Re-broadcast once implemented (sos_relay.py:111-196, tests test_sos_relay.py); `/sos/log` not implemented | high |
| R-12-038 | SOS button behavior (3s hold, triple-press, update, cancel) | NI | No hardware button mapping found | high |
| R-12-039 | GET /sos (active emergencies) | IU | C stub coap_server.c:560-575; Py emergency.py:197-200 | low |
| R-12-040 | Priority routing: SOS packets priority in TX queue | IT | tx_queue.h:61 `TX_PRIORITY_SOS=0`, deadline 2000ms; C tx_queue tests | high |
| R-12-041 | Beacon boost: originating node beacons every 30s during SOS | NI | Only `SosResource.retrigger()` primitive (emergency.py:192-195); no 30s scheduler | high |
| R-12-042 | SOS remains active until cancelled or 4-hour timeout | D | 4h only as relay dedup expiry (sos_relay.py:41-43); no auto-deactivation of active SOS | high |

### 18.5 Presence and Status

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-043 | /presence GET/PUT (2.04 Changed) | IT | presence.py:185,190-224; presence.rs:628,642; C presence.c; tests test_presence_resource.py, presence_vectors.rs | high |
| R-12-044 | Observe peer presence | IT | presence.py:60 ObservableResource; test_status_observe.py | high |
| R-12-045 | /presence/cache (all known nodes, addr/status/battery/age_s) | IT | presence.py:234-360; presence.rs:426-480; test_presence_cache.py; vectors presence_cbor.json | high |
| R-12-046 | Status values available/busy/away/offline/emergency | IT | PRESENCE_STATUSES presence.py:29; presence.rs:267-288; C presence.h:77 | high |
| R-12-047 | Auto status: moving/stationary/away>30min/SOS→emergency/battery<10% | IT | presence.py:296-342 (AWAY_AFTER_S, STATIONARY_AFTER_S, LOW_BATTERY_PCT); presence.rs:509-537; tests test_presence.py | high |

### 18.6 Check-In / Roll Call

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-048 | POST /checkin with node/ts/lat/lon/status/msg; 2.04 | IT | emergency.py:482-604; C checkin_resource.c; C tests checkin_rollcall; vectors checkin_rollcall.json | high |
| R-12-049 | Roll call via multicast POST /rollcall (id/from/ts/timeout_s) | D | Unicast POST /rollcall implemented (emergency.py:413-452; checkin_resource.c:229-285); multicast addressing `[ff02::mesh]` not evidenced | low |
| R-12-050 | GET /rollcall/{id} with responded/missing lists | IT | emergency.py:454-467; checkin_resource.c:287-320; checkin.rs:148-150 | high |
| R-12-051 | /config/checkin scheduled check-in (enabled/target/interval_s/include_location) | D | C only (checkin_resource.c:341-383, checkin.h:16,57-71); no Python/Rust | low |

### 18.7 Range Testing

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-052 | ICMPv6 Echo Request/Reply for basic ping | IT | lichen/tests/icmpv6/src/main.c:103,139,280; lichen/tests/ping_l2/ | high |
| R-12-053 | POST /diag/rangetest → SenML seq/rssi/snr/sf/freq | IT | rangetest.py:191-254; coap_rangetest.c; rangetest.rs:79-138; vectors rangetest.json; tests test_rangetest_vectors.py/.rs | high |
| R-12-054 | Observe /diag/rangetest continuous with interval_ms | IT | rangetest.py:87,143-189; rangetest.rs:281; rangetest vectors | high |
| R-12-055 | GET /diag/traceroute with hops/total_hops/total_rtt_ms | IT | rangetest.py:257-310; rangetest.rs:59-70,360-361; vectors rangetest.json (no C resource — partial interop) | low |

### 18.8 Groups and Channels

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-056 | POST /groups creation, 2.01 + Location-Path + master_secret | IT | groups_collection.py:274-336; test_groups_collection.py:55,118 | high |
| R-12-057 | Group CBOR document (id/name/mcast/owner/admins/members/key_id/key_epoch) | IT | groups_collection.py:304-314,218-235; vectors groups_cbor.json | high |
| R-12-058 | Invitation COSE_Sign1, alg -65537 (Schnorr48-Ed25519), bstr-wrapped protected header | IT | group_membership.py:188-226; delegation_tokens.py:72-78; test_groups_cose.py:58 (test_protected_header_is_bstr_wrapped_alg_65537) | high |
| R-12-059 | Invite payload keys 1-7 per spec table | IT | group_membership.py:150-156,208-322; test_groups_cose.py:111 wire-types test | high |
| R-12-060 | Sig_structure "Signature1"/protected/external_aad h''/payload; sig = Schnorr48(SHA256(CBOR(Sig_structure))) | IT | delegation_tokens.py:81-100; group_membership.py:220-223,323-325; test_groups_cose.py:71 | high |
| R-12-061 | Invitee 12-step validation (alg, kid, sig, invitee_iid, expiry, nonce, authority, accept/reject responses) | IT | groups_invite.py:70-126; group_membership.py:321; test_groups_cose.py:234,270,295 | high |
| R-12-062 | Per-inviter nonce ledger: 32-entry ring, RAM-only; collision → reject | IT | groups_collection.py:254-257 (deque maxlen=32); groups_invite.py:106-115; test_groups_cose.py:234; test_groups_invite_replay.py | high |
| R-12-063 | Key distribution POST /groups/{gid}/key over pairwise OSCORE, never plaintext | IT | groups_collection.py:739-809 (identity + invitation required); test_groups_item.py:271-599 | high |
| R-12-064 | Member voluntarily leaves: DELETE own group, delete key material | D | DELETE is owner-only authoritative delete (groups_collection.py:713-731); no member self-leave path | high |
| R-12-065 | POST /groups/remove: remover signature validated owner/admin, then target deletes | IT | groups_remove.py:59-104 (fail-closed sig verify, replay preimage, rekey on removal); test_groups_remove.py | high |
| R-12-066 | Full membership list NOT broadcast; roster only via protected /members | IT | public_group_document omits rosters (groups_collection.py:218-235); /members protected :661-675; test_groups_rekey.py:149 | high |
| R-12-067 | Rekeying on removal: epoch+1, new secret, old epoch rejected after 1h grace | IT | groups_collection.py:38 (REKEY_GRACE_S=3600),338-479; test_groups_rekey.py; vectors groups_rekey.json | high |
| R-12-068 | Only owner can promote/demote admins (POST /groups/{gid}/admins) | NI | No /admins endpoint; admin role only via admin-role invitation at join (groups_collection.py:793-796) | high |
| R-12-069 | Group mcast ff35:0040:<owner 0200::/8 /64>::<16-bit gid> | IT | groups_collection.py:184-197 → ipv6/addr.py `group_multicast_from_id`; test_groups_collection.py:238 | high |
| R-12-070 | MUST NOT persist invitation ledgers / revocation markers / retired epoch lists (RAM-only) | IT | groups_collection.py:254-257; in-RAM dicts, no persistence path found | high |
| R-12-071 | Admin demotion does NOT cascade-revoke outstanding invitations; owner MUST remove members or rekey | IT | Rekey burns outstanding invitations groups_collection.py:385-395; demotion → can_invite fails group_membership.py:347-355; test_groups_rekey.py:454 | high |
| R-12-072 | Delegation tokens: COSE_Sign1 payload keys 1-5 (delegate/scope/resource/expiry/seq) | IT (crypto layer only) | delegation_tokens.py:64-69,145-190,193-273; test_delegation_tokens.py:138; vectors delegation_tokens.json | high |
| R-12-073 | Scope bitmap bits 0-4; admins may delegate only scope & 0x13 | IT (crypto layer) | delegation_tokens.py:36-61,56-58,391-396; test_admin_scope_exceeded :443 | high |
| R-12-074 | Token issuance endpoint POST /groups/{gid}/tokens | NI | No CoAP resource for /tokens | high |
| R-12-075 | Token presentation: `delegation` field in /groups/invite; receivers verify chain and cache (delegator,delegate,resource,seq) | NI | groups_invite.py has no `delegation` field handling; `cached_seq` is a parameter with no caller-side cache (delegation_tokens.py:323,388) | high |
| R-12-076 | Tokens not revocable; rekey/demotion invalidate; MUST verify full delegation chain | D | Rekey invalidation implemented (groups_collection.py:385-395); full-chain verification exists only as library function, never invoked by a resource | low |

### 18.9 Dead Drop

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-077 | /deaddrop CoAP messages MUST use project SCHC rule set; MUST match compressed-packet test vectors | IU | SCHC pre-provisioned rules referenced (constants.toml); deaddrop vectors exercise CBOR/OSCORE but no explicit SCHC-compressed deaddrop vector found | low |
| R-12-078 | POST MUST be OSCORE-protected; unprotected → 4.01 oscore_required | IT | deaddrop.py:586-594,114-149; test_deaddrop_resource.py:171-265; Rust deaddrop_vectors.rs `oscore_wrapped_dead_drop_matches_vector` | high |
| R-12-079 | GET: private non-matching → 4.04 (conceal), group non-matching → 4.03 | IT | deaddrop.py:694-700,420-433; test_private_drop_hidden_and_forbidden :862 | high |
| R-12-080 | Rate limit 6 POSTs/hour/context; 4.29 + Retry-After | IT | deaddrop.py:29,367-392,608-614; test :460,478; Rust `rate_limit_rejection_matches_vector` | high |
| R-12-081 | Max drop 1536 B → 4.13; storage 8 KB leaf / 32 KB BR → 5.03 storage_full | IT | deaddrop.py:30-32,597-598,618-629; tests :442,489; C coap_dtn.c:267 | high |
| R-12-082 | Retention 24 h default, max 7 d; eviction expired-first then oldest; no dynamic allocation | IT | deaddrop.py:33-34,222-258,411-418; tests :523,557 | high |
| R-12-083 | SenML payload CF 112; GET collection w/ Observe + query params ?type=&after=; GET /deaddrop/{id} | IT | deaddrop.py:152-196,281,560-584,694-700; tests :592,885; Rust client deaddrop.rs:43-96 (20 vector tests) | high |
| R-12-084 | MUST produce identical SenML output for test vectors | IT | test/vectors/deaddrop.json consumed by Py tests + `rust/lichen-client/tests/deaddrop_vectors.rs:113 spec_limits_match_python_reference` | high |

### 18.10 Confessions

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-085 | /confessions POST/GET/Observe (2.01, Location-Path, Max-Age) | IT | confessions.py:207,538-582,584-687; test :885,904 | high |
| R-12-086 | `anonymous` flag default true; non-anonymous carries sender; MAY reject non-anonymous | IT | confessions.py:191-200,169-180,623-629; tests :276-618; vectors confessions.json | high |
| R-12-087 | Rate limits: 1/30s, 12/hour, monotonic uptime, keyed per-node IID → 4.29 Retry-After | IT | confessions.py:30-31,152-166,257,315-342,608-613; tests :160-512; C coap_dtn.c:490-520 (k_uptime_get_32); vectors confessions_rate.json | high |
| R-12-088 | Max 768 B → 4.13; storage 2 KB leaf / 8 KB BR | IT | confessions.py:34-36,247-248,589-590; tests :433,183 | high |
| R-12-089 | Retention 12 h (max 48 h); eviction oldest FIFO, silent, no back-pressure | IT | confessions.py:39-40,435,352-356; tests :725,749; Rust confessions_vectors.rs:234 | high |
| R-12-090 | No-log guarantee: RAM only, cleared on any reboot, never in /sos/log, /msg/sent, beacons, or persisted OSCORE context | IT | confessions.py:210-222,260-262,405-410,457-458,669-672; tests `test_reboot_clears_ram`, `test_no_log_storage_is_ram_only`, Rust `no_log_guarantee_checks` :599 | high |
| R-12-091 | Operator persist override MUST surface `logging: true` in GET metadata | IT | confessions.py:520-521,837 | high |
| R-12-092 | OSCORE optional on writes; reads public; group context RECOMMENDED for unlinkability; MUST NOT persist OSCORE context info | IT | confessions.py:152-166,221-222; C coap_dtn.c:461-478; Rust vectors :378,400 | high |
| R-12-093 | Query API: count/since, rate_remaining, rate_reset_s, storage_used_kb/max_kb | IT | confessions.py:487-522,546-579; tests :323,797; Rust confessions.rs:512-513 | high |
| R-12-094 | MUST produce identical SenML output for test/vectors/confessions.json (5 vector categories) | IT | test/vectors/confessions.json + confessions_rate.json; consumed test_security_app_vector_consumers.py:981-1131; Rust confessions_vectors.rs (17 tests) | high |

### 18.11–18.12 Summaries

| Req | Spec text | Status | Evidence | Conf |
|---|---|---|---|---|
| R-12-095 | Resource summary table (cf 18.11) | — | Informational; /msg/sent, /diag/* present; /sos/log absent (see R-12-037) | n/a |
| R-12-096 | Content-Format IDs: CBOR 60, senml+cbor 112, link-format 40 | IU | CBOR 60 and senml 112 used throughout (messaging.py, deaddrop.py); link-format 40 used in discovery (`python/tests/coap/test_discovery.py`) | low |

## Overflow notes (SHOULD/MAY gaps not filed)

- R-12-034 operator override (SHOULD) — no implementation; doesn't break a documented feature end-to-end, matrix-noted.
- R-12-033 soft blacklist reputation (MAY) — never filed per protocol.
- 18.10.6 e-ink UI flow (descriptive UI, not protocol).
- Delegation token revocation compensating controls (RECOMMENDED 24h expiry) — crypto layer enforces expiry; not filed.

## MUST-gap bead overflow count

10 gap beads filed (at cap). Additional MUST-gaps beyond cap: 0 — all identified MUST-gaps fit within the cap (S&F cluster R-12-010/011/012 filed as one bead).
