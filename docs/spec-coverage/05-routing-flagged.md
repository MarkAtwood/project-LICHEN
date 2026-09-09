# spec/05-routing.md — flagged set for Opus verification (sweep 2026-09-09)

Every row below had low confidence, an ambiguous/divergent classification, or touches
oscore/EDHOC semantics (per protocol §5c). Each entry: requirement, classification,
evidence, and the specific question to answer.

---

## F1. R-05-002 — `is_off_mesh()` semantics (§7.2)

- **Classification:** divergent (low confidence)
- **Spec:** link-local → False; non-02xx → True; 02xx → True only when no gradient AND `has_rpl_route(dst)` is False.
- **Evidence:** No stack implements a named `is_off_mesh`. The hybrid decision (rust/lichen-node/src/hybrid.rs:264-289; lichen/subsys/lichen/routing/router.c:670-716; python/src/lichen/routing/router.py:519-565) consults gradient + LOADng, then forwards 02xx to the RPL parent (upward). Downward RPL route state (the root's routing table) is only consulted when an SRH is already present in the packet, never by the 02xx forwarding decision.
- **Question for Opus:** Is "gradient → LOADng → RPL-parent-upward" an acceptable concretization of the spec's `is_off_mesh` (which requires consulting RPL route state before declaring off-mesh), or is the missing `has_rpl_route(dst)` check a real divergence that would send locally-DODAG-routable 02xx destinations to the BR unnecessarily? Should the spec pseudocode be amended to match the implemented decision order (gradient → LOADng → RPL parent), noting GPSR currently runs before LOADng (see F12)?

## F2. R-05-010 — Martian filter at the forwarding decision (§7.3 + 04-network §6.3.5)

- **Classification:** divergent (low confidence)
- **Spec:** "a router MUST NOT forward a packet whose source or destination is policy-invalid, MUST drop it at the forwarding decision, and MUST report the rejection locally without transmitting a protocol error onto the mesh. Link intake stays byte-preserving."
- **Evidence:** The full martian table (unspecified/loopback/multicast/IPv4-mapped src; unspecified/loopback/IPv4-mapped dst; multicast scope 2-14) exists only as the **emission (TX) endpoint policy**: rust/lichen-schc/src/codec.rs:241-263 `validate_address_policy` (TX-only, per adjudicated decision `rule255-rx-decode`); C schc_helpers.c:462-488; python schc/headers.py:223-249. The forwarding decision checks only a subset (unspecified/multicast source, multicast scope 0/15, hop-limit 0, relay-claims-own-source): C router.c:340,600-605,627-636,664-668; rust rpl_stack/util.rs:297-313 `survey_routing_headers`. No stack checks loopback/IPv4-mapped at forwarding. "Report locally without protocol error onto the mesh": rejections surface as error returns; test/vectors/no_silent_drops.json B.2.5.2 expects an ICMPv6 ADMIN_PROHIBITED NACK-to-source while runtime records drops locally — a documented vector-vs-runtime divergence (docs/spec-coverage/appendix-bufferbloat.md R-BB-012).
- **Question for Opus:** Does the 04-network §6.3.5 martian filter need re-application at the forwarding decision for loopback/IPv4-mapped (currently only enforced at SCHC emission), and which resolution does the no_silent_drops divergence take (amend vector B.2.5.2 to local-report-only, or add a local-report mechanism)? Note the tension with adjudicated decision `rule255-rx-decode` (RX decode must stay byte-preserving) — the fix must attach policy to the forwarding decision, not to RX decode.

## F3. R-05-011 — Conformance device-class matrix (§7.3)

- **Classification:** ambiguous (low confidence)
- **Spec:** Constrained (≤64KB) / Router (≥256KB) / BR (≥1MB) classes with per-class MUST/SHOULD/MAY rows (announce relay, LOADng relay, backpressure, DTN, opportunistic).
- **Evidence:** No device-class model exists in any stack. Nearest gates: C Kconfig (`LICHEN_ROUTER` default y, `LICHEN_LOADNG` default n — contradicts "LOADng originate MUST all classes" if default-n means constrained builds ship without it; `LICHEN_ROUTER_DTN_BUFFER_SIZE` default 0), Rust runtime `loadng_enabled` flag, Python optional `Router.loadng` injection.
- **Question for Opus:** Is the device-class table a classification of *deployment profiles* (Kconfig/build configs) rather than runtime code paths? If so, should spec §7.3 say so, and should C's `LICHEN_LOADNG` default-n be flagged as violating "LOADng originate MUST" for the constrained class?

## F4. R-05-018 — Trickle Imax "17 min" (§8.3) vs adjudicated decision `trickle-imax-1024s`

- **Classification:** divergent (spec text vs settled decision)
- **Evidence:** spec/05-routing.md:214 says "Trickle Imax | 17 min" (1020 s). Decision `trickle-imax-1024s` (decided 2026-09-01) settles Imax = 17.07 min = 1024 s and records that all three stacks + packets-timing.json already use 1024 s (confirmed: rust trickle.rs:7-11 IMAX_MS=1,024,000; C Kconfig doublings 8; python constants.py:58-60). The decision's `specs` array lists only 09-packets-timing.md, so this sweep did not edit 05-routing.md.
- **Question for Opus/human:** Should 05-routing.md §8.3 be amended to "17.07 min (1024 s)" under the settled decision (one-line change), or does the "See Appendix B for full RPL configuration" summary-table framing make "17 min" acceptable rounding? (All code and vectors say 1024 s; nothing uses 1020 s.)

## F5. R-05-019..022 — Root DODAG Version Authorization (§8.4.1): three-way mechanism divergence + 0x16 wire-type collision

- **Classification:** divergent (high confidence in the divergence itself; low confidence in the right remediation)
- **Spec:** every root DIO MUST carry one DODAG Version Authorization Option, type 0x16, Data Length 81, Schnorr48 over "LICHEN-RPL-DODAG-VERSION-v1" transcript; non-root routers propagate it unchanged; receivers derive DODAGID from Root Pubkey via canonical 0200::/8 and verify independently of the DIO link signer.
- **Evidence:** Rust implements the exact wire profile (rust/lichen-rpl/src/message.rs:80-89 OPT_DODAG_VERSION_AUTHORIZATION=0x16, DL 81; router.rs:35-65, 548-566, 987-1009; upstream oracle rust/lichen-node/tests/dodag_version_authorization_upstream.json + test/vectors/dodag_version_authorization.json). **C defines `LICHEN_RPL_OPT_RF_METRICS 0x16`** (lichen/subsys/lichen/rpl/include/lichen/rpl_messages.h:78) — the same option type value assigned to a *different* option (RF-metrics DIO TLV) — and implements version authorization instead as a COSE_Sign1 Root DIO Signature (root_dio_sig.c + root_dio_replay.c per spec 06 §8.10.1). Python has no version-authorization mechanism at all (dodag.py:428,628-637 adopts any lollipop-newer version unauthorized).
- **Question for Opus:** (1) Is the C 0x16 double-assignment (RF-Metrics vs Rust's version-authorization) a confirmed interop hazard to file as its own wire-collision bug? (2) Should C migrate to the §8.4.1 0x16 option (retiring or renumbering RF-Metrics), or is the COSE root-DIO-signature mechanism the intended C-stack equivalent pending a spec reconciliation between §8.4.1 and 06 §8.10.1? (3) Python's lollipop-only version adoption is the weakest — confirm it should be brought to the §8.4.1 profile.

## F6. R-05-036 — Leaf DAO "Serialization MUST accept an exact-size output buffer" (§8.4.4)

- **Classification:** implemented+tested with API-shape divergence (low confidence)
- **Evidence:** C conforms exactly (`build_dao` requires `len >= 62`, ERR_BUF_SMALL, commit-only-on-success; lichen/tests/rpl_dao_tx_persist). Rust: `Dao::write_to`/`RplTarget::write_to`/`TransitInfo::write_to` accept caller buffers and return BufferTooSmall, but the *builder* API (`build_dao_inner`, routing.rs:1021-1058) returns `Vec<u8>`. Python builder returns a DAO object (serialization via separate to_bytes). Rejected-build counter atomicity holds in all three (C explicit; Rust/Prython by construction).
- **Question for Opus:** Does the MUST bind the *builder convenience API* or the *serialization primitive*? If the former, Rust/Python need a caller-buffer builder variant; if the latter, all three conform and the row can be reclassified implemented+tested.

## F7. R-05-041/049/053/054/056/057 — C DAO Origin receive-side replay floor absent

- **Classification:** divergent (gap bead filed)
- **Evidence:** Rust and Python maintain crash-safe per-pubkey (high-water sequence, digest) floors with full freshness classification (rust routing.rs:637-648 + persistence.rs; python dao_origin.py:406-431 + dao_persistence.py). C has **no receive-side high-water/digest store anywhere** in lichen/subsys/lichen/rpl/ (verified by symbol search); its only replay classification is per-target Path Sequence *after* signature verification (rpl_dao_process.c:896-904); it also does not reject Origin Sequence 0 (Rust message.rs:527 and Python dao_origin.py:314 do); and `lichen_rpl_dao_manager_process_dao_ex`'s pinned-key parameter has no production caller (lichen/apps/gateway/src/rpl_root.c:275 unwired). Related tracked: project-LICHEN-worker6-b7z9.135 ("C DAO RX replay floor not persisted before route exposure", spec 16.7), project-LICHEN-worker6-ndrz (delegation gate keyed by address not pubkey).
- **Question for Opus:** Is b7z9.135 the same defect as this finding (C RX replay floor missing/not-persisted), and should my new bead supersede/be merged with it? Also: is the Rust(SHA-256)/Python(SHA-512) floor-digest algorithm difference acceptable under "collision-resistant digest", or should one be pinned for cross-stack floor-record interchangeability?

## F8. R-05-064 — "MUST NOT infer support" vs implemented generalized profile (§8.7 vs §8.7.1/8.7.2)

- **Classification:** divergent (low confidence — spec-internal tension)
- **Spec:** "current implementations MUST NOT infer support for prefix lengths other than /128, Target Descriptors, prefix canonicalization, or external egress (E=1)."
- **Evidence:** All three stacks implement the future generalized profile: Rust accepts prefix_len 1..=128 + RPL Target Descriptor option (routing.rs:1491-1526, OPT_RPL_TARGET_DESCRIPTOR); C delegation table + descriptor grammar (rpl_dao_process.c:154-197,329-451; lichen/tests/rpl_dao_auth); Python descriptors (dao_manager.py:1478-1490) with /128-only manager targets. E=1 is rejected everywhere (that part conforms). The same spec's §8.7.2 mandates delegated-prefix DAO support, so the MUST NOT clause and §8.7.2 cannot both be read literally.
- **Question for Opus:** Is the intended reading "MUST NOT *infer* (i.e., assume peer support / advertise) while MAY implementing the generalized profile behind explicit delegation"? If yes, spec 8.7 wording needs a clarifying edit. If no, Rust/C are over-implementing a reserved profile and the descriptor/delegation paths need gating behind an explicit profile flag.

## F9. R-05-081/083 — IPv6-in-IPv6 encapsulation coverage + orphan vector

- **Classification:** divergent (gap bead filed)
- **Evidence:** Rust implements both directions with tests (gateway.rs mesh_to_mesh 1829-1939, inner_hop_limit_after_encapsulation 1713-1728, tests encapsulation_*; egress decap stack.rs:648, rpl_stack/receive.rs:307,379). C implements SRH codec + egress decapsulation (rpl_srh.c, router.c route_packet_checked 560-594, test test_ipv6_in_ipv6_egress_decap) but has **no root-side encapsulation builder**. Python implements SRH (routing.py:126-427) but **no IPv6-in-IPv6 at all** (NextHeader enum lacks 41, ipv6/packet.py:24-34). test/vectors/tunnel_encapsulation.json (5 encapsulation + 5 decapsulation cases pinning the RFC 6554 model and inner-hop-limit arithmetic) has **no consumer in any stack** — orphaned vector.
- **Question for Opus:** Confirm the intended per-stack scope: is C's decap-only stance deliberate (Zephyr root never originates downward tunnels?) and Python's omission a planned gap, or should the bead require encapsulation in all three? Should a consumer test for tunnel_encapsulation.json be a child of the bead?

## F10. R-05-026 — Gateway-centric bit parsed but not consumed in Rust (§8.4.2)

- **Classification:** implemented+tested (wire) with behavioral sub-divergence
- **Evidence:** Rust parses/stores DODAG-config bit7 (`gateway_centric`, message.rs:700, router.rs:642) but never calls `DodagState::set_gateway_centric` (dodag.rs:361 has no production caller) and ignores the DIO flags byte entirely (message.rs:193 reads, nothing consumes). C consumes the config bit and DIO flags bit0 (dodag.c; test_gateway_centric_root_authoritative) — with a tracked mode-flapping bug (project-LICHEN-worker6-rrrw: accepted from any authenticated neighbor). Python consumes both (messages.py:68 DIO_FLAG_GATEWAY_CENTRIC, dodag.py:732).
- **Question for Opus:** What is the *intended* semantic of the gateway-centric extension (who may set it, what behavior it gates)? The spec assigns the bit but §8.4.2 does not define receiver behavior; C's flapping bug suggests the semantics are under-specified. Spec clarification or behavior pin needed before Rust parity work.

## F11. R-05-030 — DAO-ACK Status semantics + C local-instance-ID divergence (§8.4.3)

- **Classification:** implemented+tested with noted sub-divergences (low confidence)
- **Evidence:** Status is preserved raw without remapping in all three (spec's MUST is preserve-only). The spec's *classification* (1-127 recommend alternate parent, 128-255 reject parent service) has no consumer behavior anywhere. C `dao_ack_parse` accepts local RPLInstanceID 0xC0-0xFF (Rust rejects: message.rs:601-603; Python's DAO path rejects).
- **Question for Opus:** (1) Should a receiver *act* on Status 1-127/128-255 (spec defines meanings but only MUSTs preservation), or is preserve-only conformant? (2) Should C's acceptance of local instance IDs in DAO-ACK be filed as a bug (Rust/DAO-path treat 0xC0+ as invalid)?

## F12. R-05-109/106 — GPSR ordering + Rust coordinate validation (§9.7)

- **Classification:** divergent (gap bead filed; high confidence in divergence)
- **Evidence:** Spec makes GPSR the last resort (after no gradient, LOADng timeout, Yggdrasil unavailable). All three stacks attempt GPSR **before** LOADng and before RPL/BR fallback: rust hybrid.rs:264-289 (gradient → gpsr_forward → LOADng → RPL), C router.c:682-689 (GPSR then LOADng), python router.py:543-552 (GPSR when loadng None). Additionally rust `GeoCoords::from_app_data` (gradient.rs:55-69) skips the ±90/±180 e7 validation that C (router.c:1035-1054) and Python (coords.py:78-100) enforce, and test/vectors/announce_coords.json has no Rust consumer.
- **Question for Opus:** Is GPSR-before-LOADng an intentional implementation choice that should amend §9.7's "When GPSR is attempted" list (it does change which paths get airtime), or a conformance bug? The coordinate-validation half is unambiguous (Rust should validate + consume the vector).

## F13. R-05-105/123/126/139c/140 — low-confidence conformance rows

- **R-05-105** (rejoin stale eviction SHOULD): timeout-based expiry exists in all stacks (rust expire_old; python test_long_idle_gap_entry_expires; C lichen_gradient_expire) but the *wall-clock rejoin assessment* the spec describes depends on the unimplemented received_at (R-05-103). Question: does the SHOULD require wall-clock age, or is monotonic-timeout eviction sufficient conformance?
- **R-05-123** (TTL expiry silent drop): implemented, but "no failure notifications upstream" is conformant by absence of any notification mechanism — confirm that reading.
- **R-05-126** (partition >200 nodes MUST): deployment guidance with no code enforcement point — confirm it should stay a non-code requirement.
- **R-05-139c** (no reboot survival without anchors): confirmed conformant by absence; confirm no stack is *expected* to persist gradient tables.
- **R-05-140** (neighbor ≤64): Rust 16 / C 16 / Python 64 all satisfy the ≤64 cap; C has no dedicated routing neighbor table (L2 peer table instead). Confirm the L2 peer table counts as "the neighbor table" for §11.6.

## F14. R-05-131 — RREQ rate limiting: existing bead may be stale

- **Classification:** divergent (tracked elsewhere)
- **Evidence:** Existing bead project-LICHEN-worker6-b7z9.2 says "LOADng RREQ rate limits (10/min per IID, 30/min global) not implemented" — but C now implements both limits with tests (lichen/subsys/lichen/routing/loadng.c:41-48, applied in `lichen_loadng_seen_check_and_mark` :462-490 before processing; tests test_rreq_rate_limit_per_source/_global/_window_expiry in lichen/tests/loadng/main.c:575-630). Rust and Python still have no rate limiting.
- **Question for Opus:** Update b7z9.2 scope to "Rust + Python only, C done" rather than filing a duplicate.

## F15. §7.4 security note — OSCORE contexts survive path change (oscore semantics)

- **Classification:** informational; **human-only** (oscore/EDHOC semantics — no fix planned per policy)
- **Spec:** "OSCORE contexts survive path change (keyed by identity, not route); tunnel authorizations for the old path are stale; the new root issues fresh authorizations; link-layer trust with new neighbors established via EDHOC on first contact."
- **Evidence:** Contexts are keyed by identity in rust-oscore/lichen-oscore (no route binding found); tunnel-auth staleness on root change is partially covered by tunnel_auth revocation tests (t3b7/t6sj cluster). No LICHEN code contradicts the bullet.
- **Question for Opus:** None required; noted because it touches oscore semantics — any change here is human-adjudicated.

## F16. R-05-137/138 — passive learning + priority model divergence (§11.2/11.3)

- **Classification:** divergent (no beads filed — no explicit MUST keyword; noted per SHOULD-gap rule)
- **Evidence:** Passive learning (source="data", 60 s): implemented+tested in Rust only (hybrid.rs:511-524); C defines the tier but has no caller; Python defines the constant but no src caller. Priority: C uses a 4-tier order (Data<RPL<RREP<Announce, gradient.h:49-52) vs Rust/Python 2-tier vs spec's 2-tier-with-RPL-unranked; congestion tiebreak unimplemented everywhere (Python tracks queue depth but never consults it).
- **Question for Opus:** Should §11.3's priority table be amended to place RPL explicitly (C's placement is arguably safer: explicit advertisement beats derived state), and does missing passive learning break a documented feature (it only matters for gradient warm-up)?

## F17. Rust announce parser leniency (§9.2 context — adjudicated, listed for completeness)

- **Classification:** implemented+tested (adjudicated divergence)
- **Evidence:** Rust core parser accepts a bare announce without the 0x15 dispatch (adjudicated bead worker6-y3s5; pinned by `dispatch_prefix_leniency_pins_rust_only_contract`, announce.rs:407-430); all three *receive paths* enforce the 0x15 namespace.
- **Question for Opus:** None — recorded so a future sweep does not re-flag it. Cross-check that no new code path feeds bare announces into the processor.
