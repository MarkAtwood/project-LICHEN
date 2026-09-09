<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# spec/08-gateway-coordination.md — flagged set for Opus verification (sweep 2026-09-09)

Every requirement classified divergent, ambiguous, or low-confidence, plus
oscore-adjacent semantics. Each entry: requirement, classification, evidence,
and the specific question Opus should answer.

---

## F-1. R-08-001 / R-08-062 — both federation modes MUST be supported
- **Classification:** divergent (gap bead: l1qw.15)
- **Evidence:** Rust `GatewayFederationMode{Disabled,Psk,Open}` single-select (rust/lichen-gateway/src/config.rs:119-127); daemon hard-errors on Open (bin/lichend.rs:573-575); C has PSK Kconfig labels ("closed/dual federation", lichen/apps/gateway/Kconfig LICHEN_GW_PSK) with no derivation call found; python has no PSK derivation.
- **Question for Opus:** Does the C gateway app satisfy "closed federation" purely by provisioning a raw-PSK OSCORE context elsewhere (making R-08-002 partially conformant in C), or is C closed-mode genuinely unwired as classified? Check whether any C code path turns LICHEN_GW_PSK into an OSCORE context.

## F-2. R-08-005 — multicast discovery GET never sent
- **Classification:** divergent. Encoder + server exist; no runtime sender.
- **Evidence:** rust discovery.rs:109-141 (ff02::1 :37-42); rust resources.rs:1963; C coap_slot_coord.c:1785-1802; no caller of the encoder in lichend/gateway.
- **Question for Opus:** Is the missing sender a deliberate deferral (backbone transport decision pending — cf. ljgs for slot-claim transport), or a gap? Confirm no hidden caller in python gateway runtime.

## F-3. R-08-008 — GATEWAY flag is announce-payload, not link-layer
- **Classification:** divergent.
- **Evidence:** flag = type-byte bit 0x80 in the 10-byte LoRa gateway announce (rust discovery.rs:167,176; py discovery.py:80-81); link-layer LLSec flag bits have no GATEWAY bit (rust lichen-link frame.rs:109-116; C beacon.h:54-61); C lacks the announce codec; no runtime TX/RX caller.
- **Question for Opus:** Should spec GCP-4.2 be amended to say "gateway announce payload type-byte flag" (align-spec-to-reality precedent), or should implementations move the flag into the link layer? The current text ("include GATEWAY flag in link layer") does not match any implementation.

## F-4. R-08-012 — 3-superframe hold-off: unwired in Rust/Python, absent in C
- **Classification:** divergent (Rust+Python unit-tested only; C missing).
- **Evidence:** rust multi_instance.rs:840,1139-1175; py slot_coordination.py:50,467-483; b7z9.25 tracks the unwired state; C repo-wide grep zero; new bead b7z9.115 covers the C hole.
- **Question for Opus:** Confirm C hold-off absence is a real gap (not subsumed by C desync FSM DRIFTING/REJOINING states at tdma.c) and that unwired-but-tested Py/Rust FSMs count as divergent rather than implemented for this MUST.

## F-5. R-08-015/016/017 — GCP-5.3 backbone route lifecycle
- **Classification:** divergent / divergent / not-implemented.
- **Evidence:** DaoBackboneBridge tested library, zero production callers (rust multi_instance.rs:569-779; C :338-430; py :346-611); admission = transport-identity only; no withdrawal on lifetime expiry. Bead b7z9.114.
- **Question for Opus:** Is the intended production wiring the gateway runtime (lichend) or a dedicated backbone-sync task? Also: does "same signature and admission gates" (L130) require per-destination Schnorr verification of node DAOs at import time, or is origin-identity binding (origin == OSCORE-authenticated peer) sufficient? This changes the gap's size materially.

## F-6. R-08-018/019 — gateway desync (DIO suppression + version increment)
- **Classification:** not-implemented (both MUSTs).
- **Evidence:** no wall-clock gate on gateway DIO origination (only comment lichen link/tdma.c:162); `increment_dodag_version` production-callers = 0 in all stacks; ccp16 `excessive_clock_drift_desync` UNENFORCED (py test_ccp_sync_vector_consumers.py:372). Bead b7z9.115.
- **Question for Opus:** Is "wall clock invalid" for a gateway defined by the 2a.6 wall_clock gate (R-02a-084), and should the version increment happen only after re-sync, or at desync entry? Spec text is ambiguous on timing ("returning from desync").

## F-7. R-08-022 — backbone control claims into mesh (GCP-5.5)
- **Classification:** divergent.
- **Evidence:** RX admission exists (root DIO sig: rust receive.rs:522→657-747; C rpl/dodag.c:784+; py root_dio_signature.py) but root-side TX signing unimplemented (b7z9.88 / R-06-310).
- **Question for Opus:** Does GCP-5.5's "MUST NOT forward backbone control claims without GCP-3 trust checks" add obligations beyond R-06-305/310 (root DIO signature), or is it fully discharged once b7z9.88 lands? If the former, name the additional checks.

## F-8. R-08-023/024 — time-master election divergence
- **Classification:** divergent.
- **Evidence:** C elector lowest-IID-only (coap_slot_coord.c:191); python dual electors (rpl/multi_instance.py:205-222 vs gateway/discovery.py:437-457); python 2s default (link/channel.py:20) vs 60s; backbone-CoAP sync absent. Bead b7z9.116.
- **Question for Opus:** Which python elector is canonical, and should spec pin the exact election order (GPS-preferred, then lowest IID) as a conformance vector for all three stacks?

## F-9. R-08-031 — "silently discarded": C sends no response, Rust sends empty 2.04
- **Classification:** implemented+tested with interop-shape divergence.
- **Evidence:** C slots_post returns 0 with no CoAP response (coap_slot_coord.c:1639-1645) + 1-in-32 rate-limited WARN (:348-359); rust discards with an indistinguishable empty 2.04 (resources.rs:2051-2099), no WARN anywhere in resources.rs; python returns (False, reason) to caller.
- **Question for Opus:** Does "silently discarded ... sends no CoAP response" (L320-321) mandate C's behavior (no response at all) and make Rust's empty-2.04 non-conformant, or is an empty success response acceptable "indistinguishability"? Also: should Rust add the rate-limited WARN?

## F-10. R-08-034 — 32-entry cap without Block2 (Rust); nothing in C
- **Classification:** divergent.
- **Evidence:** rust truncates at 32 (resources.rs:77,1977,2259,2320; tests :3470/:3504/:3528), Block2 unwired (in-code ref l1qw.18.3); C no cap/no Block2 (l1qw.18); python no server (b7z9.118).
- **Question for Opus:** Is truncation-instead-of-Block2 preferable to over-long responses during the interim (documented in-code), and does spec text need an interim-compliance note, or is truncation a violation of "Larger result sets require Block2 pagination"?

## F-11. R-08-033 — GCP-6.4 resource set conformance across stacks
- **Classification:** divergent (C missing /nodes; python missing everything but /handoff).
- **Evidence:** see matrix row; beads l1qw.18 (C), b7z9.118 (python).
- **Question for Opus:** Is the python gateway intended to be a full GCP participant, or is python a reference/oracle stack where resource absence is accepted? This determines whether b7z9.118 is a gap or a scope decision.

## F-12. R-08-039/042 — claim-timing gates (C 300s, python stale-tolerance)
- **Classification:** divergent.
- **Evidence:** C 300s no tolerance (coap_slot_coord.c:435-456; test comment main.c:604-607 says deliberately dropped); python STALE_CLAIM ≤5s acceptance (slot_claim.py:67-71,712-715; pinned divergence test_slot_claim_cose_vectors.py:105-121); rust conforms at 305s. Bead b7z9.117.
- **Question for Opus:** Which side is the intended canonical: strict `expiry > now` (rust) or tolerance on both bounds? Note the C +5s omission causes a legit-claim reject (interop), while python's causes a stale-accept (security-adjacent).

## F-13. R-08-041 — python kid↔payload binding skipped at decode
- **Classification:** implemented+tested (Rust/C) with python parity gap.
- **Evidence:** py binds gateway_iid to pubkey-derived IID at verify (slot_claim.py:676-680) instead of kid at decode (test skip test_slot_claim_cose_vectors.py:131-136); vector kid_payload_iid_mismatch has no unconditional python consumer.
- **Question for Opus:** Is verify-stage binding (pubkey→IID==payload IID) equivalent to spec step 6 (kid==payload IID) given step 5 already verified the signature against the pubkey? If equivalent, spec/vectors could note it; if not, python must add the decode-side check.

## F-14. R-08-044 — response-code mapping divergences
- **Classification:** divergent.
- **Evidence:** C: 4.03/4.09+winner-envelope/2.04 (coap_slot_coord.c:1639-1693) — codes not host-test-covered (resource handlers compiled out of host build, coap_slot_coord.c:103); rust: 4.09 echoes own recorded envelope (resources.rs:2163-2166) vs spec "winning gateway's claim", invalid-slot/malformed → silent empty 2.04 not 4.03 (in-code ref l1qw.20.1).
- **Question for Opus:** When the local gateway loses a conflict, whose claim is "the winning gateway's claim" in the 4.09 payload — and is Rust's own-envelope echo conformant? Confirm l1qw.20.1 covers the invalid-slot→4.03 mapping.

## F-15. R-08-046/047 — claim_seq persistence: sender dead code (Rust), absent (C); python receiver in-memory
- **Classification:** divergent (both MUSTs partially unmet).
- **Evidence:** rust ClaimSeqStore durable but dead in binary (lichend.rs:110-112, pending claim-broadcast consumer); C sender absent (sign_claim uncalled); py receiver SlotClaimReplayCache in-memory (slot_claim.py:520-522). Beads l1qw.20, gskf (receiver persistence since landed — status check), 0k8i.
- **Question for Opus:** Does the dead Rust sender mean GCP-6.5 slot claims are currently receive-only in production (no gateway ever issues claims)? If so, is that an accepted stage (blocked on ljgs transport decision) or a gap needing a sender epic?

## F-16. R-08-048 — 64-entry LRU high-water cache not implemented
- **Classification:** not-implemented.
- **Evidence:** rust StateFull no eviction (slot.rs:912-916); C CONFIG_LICHEN_SLOT_CLAIM_SEQ_CACHE_MAX=64 unused (coap_slot_coord.h:39-43), real table 8 fail-closed; python MAX_GATEWAYS=256 (slot_claim.py:532). Eviction policy bead 0k8i.
- **Question for Opus:** Should the spec's LRU-by-last-claim-timestamp be amended to the implemented fail-closed posture (align-spec-to-reality), or must stacks implement LRU eviction? Note fail-closed + LICHEN_CLAIM_REJECT_PERSIST is a liveness kill of GCP-6 when full.

## F-17. R-08-049 — rate-limiter keying divergence
- **Classification:** implemented+tested, minor divergence.
- **Evidence:** rust keys on OSCORE peer IID (resources.rs:2073-2085); C/python key on claim gateway_iid (coap_slot_coord.c:1615-1629; slot_claim.py:660-665).
- **Question for Opus:** Is either keying conformant with "per peer IID" (L366), or must all stacks key on the authenticated sender (OSCORE peer), which survives gateway_iid spoofing inside a valid signature context?

## F-18. R-08-050 — handoff "confirm to node via CoAP" unimplemented
- **Classification:** implemented+tested (core), node-confirm sub-step absent.
- **Evidence:** doc comment only (rust handoff.rs:9); no code notifies the node after accept_handoff in any stack.
- **Question for Opus:** Is node confirmation expected as a CoAP response to the node's pending request, an unsolicited POST, or implicitly via the node's next successful interaction? Spec step 4 (L376) needs a mechanism name before this can be implemented.

## F-19. R-08-051…R-08-057 — GCP-7.1 handoff COSE_Sign1 not wired anywhere
- **Classification:** divergent (format), divergent (payload keys), divergent (bitmap field), divergent (bitmap enforcement), divergent (validation), not-implemented (replay-window seeding), divergent (replay protection), low confidence on R-08-057.
- **Evidence:** all wired handoff paths are legacy plain-CBOR inside OSCORE (rust handoff.rs:119+; C coap_handoff.c:556-958; py resources/handoff.py:92); python COSE classes dead code (handoff.py:907,1042); no expiry check, no per-node seq cache, no 4.03, no bitmap enforcement in wired paths; replay engines never seeded by handoff (floor-style +1 advance: handoff.rs:1046, C :404, py :671). Vector/impl mismatch: gcp_handoff_cose_sign1.json confirm vectors carry 6 keys (no bitmap key 7) while the python COSE class requires key 7. Tracked by epic 3o0p (+.2/.3/.5).
- **Question for Opus:** (a) Should the legacy plain-CBOR handoff format be treated as the interim wire format pending 3o0p (making R-08-051..057 "planned-divergent"), or are the wired paths non-conformant today? (b) Should gcp_handoff_cose_sign1.json be regenerated to include bitmap key 7 (per spec L452-464) or the spec relaxed? (c) Confirm python `create_handoff_confirm` TypeError (missing replay_bitmap arg, handoff.py:1219-1226 vs field :848) and zero-test COSE classes are covered by 3o0p.5.

## F-20. R-08-055 — handoff invalid → 4.03 not honored
- **Classification:** divergent.
- **Evidence:** stacks return 4.00 (decode failure: coap_handoff.c:1030-1032, rust :2293) or 2.04-with-error-payload (rust :2296-2305; py test_handoff_resource.py:131 asserts CHANGED on NODE_NOT_FOUND); 4.03 absent from all handoff handlers.
- **Question for Opus:** Spec step 11 (L513) mandates 4.03 for invalid handoff requests; the 2.04-with-error-payload design is intentional (py test asserts it). Should the spec be amended to the 2.04+status design (align-spec-to-reality) or handlers changed to 4.03? Note vv1b separately tracks the error-path response-protection bug.

## F-21. Spec text bug — handoff protected-header examples encode the decoy
- **Classification:** spec defect (not an implementation gap).
- **Evidence:** spec L396/L435 `h'a10139ffff'` encodes {1: -65536} while the text says alg −65537; correct bytes `a1013a00010000` per vectors/generator/python encoder; slot-claim section (L233) declares -65536 the decoy that MUST be rejected.
- **Question for Opus:** none needed for the fix itself (beads 5brg + uqke already track it) — but flag that 5brg and uqke are duplicate filings of the same defect and should be deduplicated (bd lint candidate).

## F-22. Cross-stack vector-consumer gaps (minor)
- **Evidence:** gcp_psk_oscore.json semantic consumers: rust only (gcp_psk_oscore_vectors.rs; py only lists schema policy test_vectors.py:5588; C none). gcp_iid_comparison.json: python only. C gcp_trust.c mirrors the oracle format but has no vector consumer (comment :164).
- **Question for Opus:** Should cross-stack consumption of these two corpora be required before R-08-002/R-08-011 can be marked fully pinned, or is single-stack consumption + unit tests sufficient?

## F-23. R-08-050 C two-phase-commit divergence (found during sweep, related)
- **Evidence:** C lichen_handoff_process_request releases the node immediately (coap_handoff.c:369-371) while rust/py stage-then-commit (resources.rs:2263-2315, handoff.py:583-596); C has no tests for coap_handoff.c at all.
- **Question for Opus:** Confirm C's immediate release is an orphaning hazard requiring the same transactional fix as rust (bead worker6-mybk's rust fix, commit e72604e715), and whether that belongs under epic 3o0p or a separate C-handoff bead.
