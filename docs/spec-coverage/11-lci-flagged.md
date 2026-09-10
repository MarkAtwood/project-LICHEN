# spec/11-lci.md — flagged set for verification (sweep 2026-09-09)

Flag criteria: low confidence, ambiguous or divergent classification, or
oscore/EDHOC-semantics concerns. Bead IDs refer to gaps filed this sweep under
epic `project-LICHEN-worker6-l1qw` (see `11-lci.md` §Gap beads). Note: no
finding below touches oscore/EDHOC *internal* semantics (all OSCORE evidence is
resource-level gating in coap servers/clients, which is not inside the
human-only edit bar for oscore/EDHOC internals).

---

## F1. R-11-004 — BLE Option B (6LoWPAN over BLE, RFC 7668) — low confidence

- Spec text: "Option B is OPTIONAL" (§17.3.2); IPSP/L2CAP + IPHC.
- My classification: implemented+untested (C codec exists: `ble_ipsp_transport.c:54-56` IPHC dispatch, IPSS UUID/PSM in `ble_ipsp_transport.h:53-59`).
- Why flagged: Zephyr 3.7 removed `NET_L2_BT`/IPSP, so real L2CAP IP routing cannot be exercised (validation-summary-2auf.59.4.1.3.2.2.2.4.md:49); only LCI/netif-boundary tests run.
- Question for Opus: Should Option B be re-classified as effectively not-implemented (codec present but no exercisable transport), and should the spec note the Zephyr 3.7 limitation?

## F2. R-11-008 — wire EUI-64 derived from IID by exactly one U/L toggle — low confidence

- Spec text: "The node's wire EUI-64 is obtained from that IID by toggling the U/L bit exactly once (§4.2); it is never the source of the IID."
- My classification: implemented+tested.
- Evidence: `rust/lichen-ipv6/src/lib.rs:210` (`addr[8] = eui64[0] ^ 0x02`, i.e., EUI-64→IID direction; XOR is symmetric); `lichen/tests/slip_transport` `test_node_iid`.
- Why flagged: I verified the inverse direction only in Rust; the C firmware path that *produces* the wire EUI-64 from the IID was not independently pinned, and no test asserts "IID is never derived from EUI-64" as a negative property.
- Question for Opus: Confirm the C/Zephyr wire-EUI64 producer (where?) toggles from IID (not the reverse), and whether a negative test (IID ≠ f(EUI-64) identity) exists or should be added.

## F2b. R-11-011/012/016/022/023 — Rust LCI server divergence (bead l1qw.49)

- Spec text: node exposes CoAP server on 5683 with `/.well-known/core` listing its resources; /status, /keys, /config family are node resources.
- My classification: divergent (Rust stack only; C and Python conform).
- Evidence: `rust/lichen-node/src/dispatch.rs:301-303` WKC advertises `</sensors>,</config>,</deaddrop>,</confessions>` with only stub handlers (`:323-361`, config GET returns JSON); no /status·/keys·/config/radio·/config/identity server handlers; no Rust listener on 5683; BLE UUID ≠ NUS (`lichen-kiss/src/ble.rs:18`).
- Question for Opus: Is the Rust stack scoped as an LCI *node* (must implement the server family) or client/gateway only? If the latter, spec 17.3.2/17.5 conformance for Rust should be re-scoped and the WKC stub fixed to advertise only real resources.

## F3. R-11-018 / R-11-073 — home vs current tuning MUSTs — ambiguous

- Spec text: "Status and UIs MUST distinguish home from current tuning; if current tuning is not reported, it is unknown, not inferred from home." (§17.5.3, restated §17.8.6.)
- My classification: not-implemented (bead l1qw.48).
- Evidence: no current-tuning field in any /status encoder (C ccp map `coap_status.c:667-676` emits home only); no UI displays tuning at all.
- Why flagged: No implementation *violates* the MUST (nothing infers tuning from home), but nothing satisfies it positively either — there is no "current tuning: unknown" marker, and the spec says tuning may be temporarily changed by CH0 control windows without changing home.
- Question for Opus: Does the MUST require an explicit unknown/unreported marker in /status (i.e., the status side is also non-conformant until a field exists), or is omission-compliant (home-only reporting) acceptable until a UI exists?

## F4. R-11-020 / R-11-074 — retune MUST NOT be displayed as fresh airtime budget; duty scope MUST be identified — low confidence

- Spec text: "Changing logical channels or retuning MUST NOT be displayed as acquiring a fresh airtime budget"; "Duty displays MUST identify the applicable accounting scope."
- My classification: implemented+untested (R-11-020) / not-implemented (R-11-074).
- Evidence: single continuous rolling budget per radio (`rust/lichen-core/src/duty_cycle.rs:348`; C `hal/hal_duty.c`, one ctx per radio `l2/lora_l2.c:186`) — retune structurally cannot reset it; but no per-accounting-group or per-physical-frequency bucketing exists (`duty_cycle.rs:59-78` has only EU868/US915 region limits), no display exists, and no test asserts the retune property.
- Question for Opus: Is "one continuous budget per radio" an acceptable implementation of the accounting-group requirement (with US915 per-transmission dwell as the dwell accounting), or does §17.5.3 require per-frequency/per-group buckets now? Should a retune-does-not-refresh test be mandated?

## F5. R-11-021 — SHOULD `"ts"` in diagnostic payloads — divergent (partial)

- Spec text: "Implementations SHOULD include `"ts": <unix_timestamp>` in all diagnostic event payloads exposed via LCI" (§17.5.3 cross-mesh correlation).
- My classification: divergent.
- Evidence: `ts` present in app payloads (msg/ack `coap_msg.c:605`, checkin, presence, SOS, location) but absent from /status/neighbors (`last_seen_s` only), /status/queues (`rust status.rs:186-201`), raw-diag events (`lci_raw_diag.json` ts count 0), routing-change payloads.
- Question for Opus: Does "diagnostic event payloads" cover table/status GETs (neighbors, routes, queues) or only event/notification payloads? If the former, neighbor tables need a `ts` field; if the latter, coverage is closer to adequate.

## F6. R-11-026 / R-11-027 / R-11-030 — /diag family divergent + unmounted (bead l1qw.43)

- Spec text: /diag summary map shape; /diag/raw/rx arming with max_ttl_s=300; observable /diag/raw/rx/events.
- My classification: divergent (C /diag shape) + implemented-but-unwired (Python).
- Evidence: C GET /diag returns `{ts,sub,code,detail}` event array (`lichen/subsys/lichen/diag/lichen_diag.c:92-140`); Python implements exact spec shapes but `build_site()` never mounts them (`raw_rx.py:25-159`); nothing produces rx events.
- Question for Opus: Is the C `/diag` event-array shape an intentional separate contract (diagnostics epics reference `/diag` as fleet health dashboard per ldzz) that should be reconciled in spec 17.5.4 (e.g., `/diag` = fleet health, `/diag/raw/*` = raw family), or should C /diag be reshaped to the summary map?

## F7. R-11-031 — raw TX rate limit implemented only in unmounted host library — low confidence

- Spec text: "Implementations MUST rate-limit raw TX."
- My classification: implemented+tested (Python `raw_tx.py:22-23,74-76`, 1 s interval) but the resource is not mounted by `build_site()` and no firmware implements raw TX.
- Question for Opus: Does an unmounted, vector-tested library class satisfy "MUST rate-limit" for stack conformance, or does the MUST only bite when raw TX ships? (Same question pattern as F6/F8.)

## F8. R-11-032 / R-11-033 — raw TX PHY/regulatory rejection and airtime non-preemption — divergent/not-implemented

- Spec text: "MUST reject frames or overrides that violate configured PHY/regulatory constraints"; "MUST NOT preempt committed RX, exceed adaptive airtime limits, or overrun a full operation plus guard."
- My classification: divergent / not-implemented. Python resource validates frame length only and never touches a radio; no eligibility check anywhere.
- Existing bead: project-LICHEN-worker6-b7z9.40 (raw diag server-side MUSTs unenforced).
- Question for Opus: Confirm b7z9.40's scope covers the airtime-preemption clause too, or whether the RX-preemption/guard clause needs its own bead against the TDMA eligibility path (`lichen-core/tx_queue.rs`, `tdma_scheduler`).

## F9. R-11-050 — `/messages` legacy alias advertised — divergent, arguable (bead l1qw.45)

- Spec text: "The legacy Python demo `/messages` resource is not part of LCI and MUST NOT be advertised as a native messaging resource."
- My classification: divergent.
- Evidence: `site.py:251-257` registers `LegacyMessagesAliasResource` and advertises `</messages>;rt="legacy.messages";ct="60";title="legacy demo alias"` in discovery (pinned by `test_messages_resource.py:94-104`).
- Why flagged: Two defensible readings — (a) the MUST NOT bans advertising /messages *as a native messaging resource*, and a distinctly-labeled legacy alias is compliant-labeling; (b) the letter says the resource must not be advertised at all.
- Question for Opus: Adjudicate reading (a) vs (b). If (a), the spec text should be amended to permit distinctly-labeled legacy aliases; if (b), drop the registration and the pinning test.

## F10. R-11-054 / R-11-060 — rate-limit keying "per OSCORE context or source IID" — divergent, potential spec conflict

- Spec text: §17.5.8 deaddrop "Rate limits enforced per OSCORE context or source IID"; §17.5.9 confessions "1 POST per 30 s, 12 per hour per source IID".
- My classification: divergent.
- Evidence: py/rust conform for authenticated identities, but anonymous confessions POSTs share one global bucket (`confessions.py:27,152-166` `_UNAUTHENTICATED_RATE_KEY`); C keys by IID last byte `iid7` with a 60 s cooldown (`coap_dtn.c:193-218`).
- Why flagged: Existing bead project-LICHEN-worker6-b7z9.124 asserts the spec *forbids* keying on IID ("MUST NOT key-on-IID; spec requires 128-bit/OSCORE identity") — that reads as contradicting 11-lci §17.5.9's "per source IID" wording (presumably 12-apps §18.10 is authoritative). Also note an anonymous poster has no verified IID, so "per source IID" is underspecified for unauthenticated traffic.
- Question for Opus: Reconcile 11-lci §17.5.9 wording with 12-apps §18.10 and b7z9.124: what is the required keying for (i) authenticated and (ii) anonymous confessions/deaddrop posts? Amend 11-lci if "per source IID" is wrong for the anonymous case.

## F11. R-11-053 / R-11-055 / R-11-057 / R-11-062 — C deaddrop/confessions divergences (existing bead l1qw.30)

- My classification: implemented+tested (py/rust) with C divergent: 2.04 Changed instead of 2.01+Location-Path (`coap_dtn.c:299-301,541-543`), no Observe (`coap_dtn.c:607-628`), no privacy ACL, GET lacks count/rate metadata (`coap_dtn.c:353-448`), confessions storage 2×768 B vs 2 KB.
- Also: `test/vectors/deaddrop.json` pins stale response codes 69/163 vs spec/impls 65/157 (documented in `deaddrop_vectors.rs:345-347`).
- Question for Opus: Confirm l1qw.30 covers all five C divergences (including the stale-vector sub-issue, reportedly also tracked as worker6-44m9), or whether the stale-vector fix needs a separate explicit close-out.

## F12. R-11-065 — access-control levels SHOULD — divergent fragmentation

- Spec text: "Implementations SHOULD support restricting local client access" (read-only/standard/admin; USB=admin, BLE=standard).
- My classification: implemented+tested (Python full model, vector-pinned) / divergent (Rust type defined but referenced nowhere; C binary local-admin gate only).
- Evidence: `lichen-core/src/access_level.rs:15-65` (unused outside its module); C `lichen_coap_is_local_admin()` binary gate (coap_keys.c:44-77, applied coap_server.c:167,300).
- Question for Opus: Is the two-tier C model (admin vs not) an acceptable SHOULD-conformance posture, or should the three-level model (with /diag/raw/* excluded from standard) be required in C/Rust? Note Python already implements + vector-pins the full model (`access_levels.json`).

## F13. §17.8 UI cluster (R-11-068..072, 075, 077, 078..080) — not-implemented at scale (bead l1qw.47)

- My classification: not-implemented/divergent across all surfaces (details in matrix + bead).
- Why flagged: §17.8 reads as a product-level UI mandate ("All LICHEN user interfaces… share a single information architecture"). No surface implements the 4+2 screen set, custody indicators, or Observe-driven rust TUI; e-ink and web surfaces are absent entirely.
- Question for Opus: (a) Is §17.8 normative-for-conformance (generating MUST-gap obligations per surface) or design guidance whose "MUSTs" bind only surfaces that ship? (b) If normative, does the l1qw.47 bead need splitting into per-surface issues (TUI / e-ink / mobile / web)? (c) For R-11-077 ("clients reflect the node's state… rather than maintaining independent radio queues"): is the absence of client-side radio-queue machinery sufficient evidence, or is an explicit conformance test wanted?

---

Low-confidence rows not requiring new adjudication but noted for the record:
R-11-004 (F1), R-11-008 (F2), R-11-027/030/031 (F6/F7), R-11-077 (F13c).
Ambiguous rows: none besides F3. Divergent rows not otherwise flagged are fully
covered by beads (l1qw.43/.45/.46/.48/.49/.50) with unambiguous evidence.
