# spec/06-security.md (Part 1: §8.1–§8.7.4) — flagged for Opus verification (sweep 2026-09-01)

Condition (c) of the sweep protocol applies (this IS 06-security), so the whole
section is in scope. Detailed entries below are the divergent / not-implemented /
low-confidence rows; the high-confidence implemented+tested rows follow in a
compact spot-check table. Companion matrix: `docs/spec-coverage/06-security-part1.md`.

## A. Divergent / not-implemented / low-confidence (detailed)

### A1. R-06-009 — root DAO validation ORDER (divergent, C only)
- **Requirement:** Root MUST validate in order: structural → pinned key/IID/transcript/origin-sig → per-key replay → semantic parsing → exact self /128 Target → replay-floor persistence → atomic route mutation (spec 8.4, lines 92–97). "A structurally and cryptographically valid replay wins over semantic or Target-validation failure."
- **Classification:** divergent. Rust conforms (rust/lichen-rpl/src/routing.rs:612-725: replay :627-640 before semantic :646-655). C runs semantic/Target (rpl_dao_process.c:841-846) before replay classification (:862-898).
- **Evidence:** full pipeline quotes in matrix row R-06-009. Both paths fail closed; only the rejection taxonomy/precedence differs.
- **Bead:** project-LICHEN-worker6-b7z9.81 (filed this sweep).
- **Question for Opus:** Confirm the C ordering is a genuine MUST violation worth fixing (rejection-label parity for dao_origin_signature.json outcome vectors), vs. amending spec 8.4 to bless either order. Interacts with project-LICHEN-worker6-b7z9.9 (.44.7 vs delegation reconciliation).

### A2. R-06-010 — replay persistence fails closed (divergent: Rust yes, C RX no)
- **Requirement:** Missing, corrupt, or unavailable replay persistence fails closed (spec 8.4 line 98).
- **Classification:** divergent. Rust: routing.rs:701-723 persists high-water before route mutation; test `unavailable_replay_storage_leaves_dao_state_unchanged` (dao_origin_vectors.rs:264). C: RX-side per-key origin-seq floor is volatile (rpl_dao_process.c:862-898 snapshots); no NV persistence found on the RX path (TX side IS persisted, rpl_dao_build.c:155-165).
- **Bead:** already tracked by project-LICHEN-worker6-b7z9.11 (C 64-bit DAO Origin Sequence persistence, spec 09 14.2).
- **Question for Opus:** Confirm the C RX floor gap is fully covered by b7z9.11's scope, or whether the §8.4 fail-closed MUST needs its own acceptance criteria (restart survival test on C).

### A3. R-06-011 — ".44.7 accepts exactly one /128 Target" vs implemented delegation profile (divergent)
- **Requirement:** Root accepts exactly one /128 Target equal to the preserved Source; general prefix delegation remains future .44.9 work (spec 8.4 lines 99–101).
- **Classification:** divergent. Code implements own-/128 OR exact delegation to the origin: rust/lichen-rpl/src/routing.rs:771-823 (`128 => prefix == origin.octets()` :805, delegation table :808-816), C `dao_targets_authorized`.
- **Bead:** already tracked by project-LICHEN-worker6-b7z9.9.
- **Question for Opus:** Spec-editor decision — amend §8.4 to describe the implemented generalized profile (delegation table + delegation-entry authorization) or narrow the code. Note §8.7/8.8 spec text and implemented profile were already adjudicated once (b7z9.9 is open, so not settled).

### A4. R-06-016 — X25519 = clamp(SHA-512(seed)[0:32]) (divergent: Rust absent)
- **Requirement:** spec 8.5 step 4 / 8.7 derivation step 4.
- **Classification:** divergent. Python identity.py:97-110 + test/vectors/x25519.json (test_vectors.py:2335); C edhoc_crypto.c:287-307 + lichen/tests/schnorr48/main.c:300. Rust: no static seed→X25519 anywhere; EDHOC ephemeral-only.
- **Bead:** project-LICHEN-worker6-b7z9.38 (labeled human-only — EDHOC semantics).
- **Question for Opus:** human-only edit bar applies to rust/lichen-oscore; confirm whether the static-key MUST should stay in spec 8.5/8.7 while Rust remains ephemeral-only, and whether the matrix row should cite the spec as the divergent party.

### A5. R-06-018 — fe80::/10 control-only vs 0200::/8 routable (implemented+untested, low confidence)
- **Requirement:** spec 8.5: link-local is for control only; key-derived 0200::/8 primary for all routable traffic.
- **Evidence:** scope checks exist in all stacks (ipv6_addr.c:104-113, router.c:42-46, node.py:570/604, rust addr.rs) but no dedicated test pins the control/routable split.
- **Question for Opus:** Is there an existing test I missed (search terms: link-local, fe80, control plane)? If truly untested, does it warrant a SHOULD-gap bead or is the split covered implicitly by SCHC rule tests (schc_compress.c:167 elides fe80::/64)?

### A6. R-06-020 / R-06-021 — §8.6 signature caching (divergent / not-implemented, spec-editor flag)
- **Requirement:** Verify at first hop, cache "verified from \<IID\>", relay without re-verify, cache keyed (source IID, seq) with TTL; entries expire after 2× mesh traversal (default 30 s).
- **Classification:** divergent — all three stacks verify every frame at every receive and relays re-verify before mutation (link_layer.rs:1128-1135; relay.rs:1-10; python link_layer.py:1609-1612; C lichen_link_rx.c:134). No cache exists. No MUST keyword in §8.6, so no gap bead filed per protocol.
- **Question for Opus (spec-editor):** §8.6 reads as a normative procedure without RFC-2119 keywords. Should it be amended to make per-hop verification the baseline (what all implementations do, strictly stronger) with the cache as an OPTIONAL optimization? Current text makes every implementation look non-conforming on a paragraph that is really a performance suggestion.

### A7. R-06-026 — private key stored securely, never transmitted (implemented+untested, low confidence)
- **Evidence:** no transmission path exists (negative property); storage hardening verified in R-06-048 evidence.
- **Question for Opus:** Accept as inherently untestable, or require a test asserting no serialized privkey ever appears on any TX path (e.g. fuzz/grep-style harness over frame builders)?

### A8. R-06-030 — node rejects further provisioning after commissioning (not-implemented)
- **Bead:** project-LICHEN-worker6-b7z9.34 (persistent lock-out absent; per-session state machine only).
- **Question for Opus:** Confirm factory-reset-persisted lock-out flag is the right fix target (Zephyr settings + gateway config), and that "factory reset to reset" needs a defined reset trigger in spec 17 (LCI) before implementation.

### A9. R-06-035 / R-06-036 — BR anchor-list distribution, revocation push, periodic fetch (not-implemented)
- **Bead:** project-LICHEN-worker6-b7z9.80 (filed this sweep, SHOULD-class).
- **Question for Opus:** Confirm the SHOULD-gap framing: spec text is capability-form with one SHOULD; the omission makes BR-provisioned fleets unmanageable (no way to distribute anchors or revoke). Should this be promoted to a MUST-gap given §8.7's "Trust Anchor Distribution" heading, or does BR provisioning remain a documented-optional feature?

### A10. R-06-041 / R-06-051 / R-06-052 — rotation attestation format divergence (divergent)
- **Requirement:** §8.7.4 COSE_Sign1 with alg -65537, protected h'47A1013A00010000', kid=old IID, payload {1,2,3,4}, sig by old key.
- **Classification:** divergent. Python library exact + tested (key_rotation_attestation.py; test_key_rotation_attestation.py) but wired to nothing (no /.well-known/key-rotation in any stack, no production importer). Rust gateway + C gcp implement the §8.7 raw transcript (no COSE envelope); Rust link uses a third format ("KEY_ROTATE:"||pubkey, trust.rs:160-184).
- **Bead:** project-LICHEN-worker6-b7z9.28 tracks the three-format divergence.
- **Question for Opus:** Should the matrix treat §8.7 (raw transcript) and §8.7.4 (COSE_Sign1) as two distinct mechanisms that must BOTH exist (transcript for store-level rotation, COSE_Sign1 for over-the-air attestation), or does §8.7.4 supersede §8.7's transcript scheme? This changes whether R-06-042 is "conformant" or "the legacy half of a split requirement".

### A11. R-06-046 — revocation: remove from local key store (implemented+untested, low confidence)
- **Evidence:** Python-only (trust.py:709-729, tested test_trust.py:372-411; revoked peers rejected during rotation trust.py:659-660). Rust gateway TrustEntry has no revoked handling found; C stores none.
- **Question for Opus:** Confirm Rust/C absence (search terms: revoked, revocation, Revoked) and whether cross-stack parity is a MUST (spec sentence has no keyword) or SHOULD.

### A12. R-06-047 — trust-store load hardening (implemented+tested on host stacks, low confidence on C parity)
- **Evidence:** Rust gateway trust.rs:733-811 and Python key_persistence.py:738-756 implement versioned schema/bounds/recompute/fail-closed fully. C uses Zephyr settings with a protection floor (coap_keys_lifecycle test) but no schema-version/bounds/recompute layer.
- **Question for Opus:** Are the §8.7 hardening MUSTs (lines 296–305) intended to apply to embedded C stores (where settings/NVS replaces host file semantics), or are they host-store requirements? If they apply, C needs its own bead (not filed — scope call).

### A13. R-06-048 — store hardening: O_NOFOLLOW missing in Rust gateway trust store (divergent)
- **Bead:** project-LICHEN-worker6-b7z9.79 (filed this sweep, P2) — **closed 2026-09-01**: O_NOFOLLOW added to all three opens; re-sweep verified `custom_flags(libc::O_NOFOLLOW)` at trust.rs:742/:849/:898 in source. Matrix row reclassified to implemented+untested (no dedicated symlink test for the gateway store; CI compile gate pending per close reason).
- **Question for Opus:** Confirm the three open sites (trust.rs:742, :849, :898) are the complete set (config.rs:245 already conforms) and that hal storage.rs inode-check pattern is the model to mirror. Is a symlink-rejection regression test required, or is the O_NOFOLLOW flag sufficient?

### A14. R-06-053 — rotation_seq persistence rules (divergent: C absent)
- **Bead:** project-LICHEN-worker6-b7z9.33 (C rotation sequence not persisted).
- **Question for Opus:** None beyond confirming coverage; Rust gateway + Python conform with tests.

### A15. R-06-055 — delivery mechanisms MAY; attestation MUST be verified before updating trust state (divergent, low confidence)
- **Evidence:** /.well-known/key-rotation absent everywhere; the MUST (verify-before-update) is satisfied in python store path (trust.py:675-679), rust gateway (trust.rs:965-1028), rust link (divergent format but verifies first).
- **Question for Opus:** No bead filed because the missing piece is MAY-class delivery. Confirm no new bead needed, or whether the endpoint should be appended to b7z9.28's scope.

### A16. R-06-014 — wio-e5 bringup firmware IID derivation diverges (found in re-sweep)
- **Requirement:** IID = SHA-512(pubkey)[0:8] with U/L cleared; MUST be SHA-512, not SHA-256 (spec 8.5 step 2 / 8.7 step 2).
- **Classification:** divergent in `rust/lichen-firmware/wio-e5/src/main.rs:33-39` — `derive_iid` copies raw `seed[0:8]` with U/L clear, never hashes the pubkey. The ponytail comment misstates the canonical upgrade path as "real impl uses SHA256" (canonical is SHA-512(pubkey), rust/lichen-core/src/addr.rs:86-92). Bringup-only firmware (hardcoded seed, placeholder radio driver), but it ships in-tree and a future flash would derive an IID incompatible with every other stack and with test/vectors/yggdrasil-derivation.json.
- **Bead:** filed in re-sweep (see matrix bead list).
- **Question for Opus:** Is bringup-only status sufficient grounds to leave the placeholder (with a corrected comment), or should wio-e5 switch to `lichen_core::addr::iid_from_pubkey_bytes` (already `no_std`, dep on lichen-core exists via `NodeId` import) now? Also: should the comment fix land independently of the code fix?

## B. High-confidence implemented+tested rows — compact spot-check list

These were classified implemented+tested / high. Opus spot-checks the riskiest assumption in each:

| Req | Spot-check question |
|-----|---------------------|
| R-06-001 | Any RPL control path that bypasses the link frame (loopback/LLCI) without signing? |
| R-06-002 | Confirm "AES-128-CCM optional" reading — C rejects E=1 frames; is silent rejection the spec-intended optional posture? |
| R-06-003 | Python originated-TX path signs every frame (only RX verified in sweep) — confirm TX-side sign call exists in python/src/lichen/link/link_layer.py |
| R-06-004 | Spec says "RFC 6979" but defines H(privkey‖msg); confirm draft-lichen-schnorr-00 wording matches implementations |
| R-06-005 | External schnorr48 crate is the Rust oracle — confirm crates.io provenance/review status is acceptable |
| R-06-006 | Python: is replay-window update strictly after verify (same order as Rust/C)? |
| R-06-007 | C relay_raw: confirm upper-layer mutable fields are updated BEFORE entering the API (comment says caller's duty) |
| R-06-008 | Confirm DAO transcript binds effective DODAGID (spec says "effective DODAGID") — verify.rs:128-142 includes dodag_id? |
| R-06-012 | 6LoRH insertion/consumption sites — confirm none mutate the signed transcript without re-sign |
| R-06-013 | "No ULA" — confirm no ULA (fc00::/7) construction anywhere (rg fc00) |
| R-06-014 | C mask is `~0x02` — equivalent to `&= 0xFD` for bit 1; confirm no other bits touched |
| R-06-015 | C ygg addr copies hash[0..8] into [8..16] — confirm that is IID (hash[0:8]) not hash again |
| R-06-017 | confirm TOFU pin happens only after successful verify (never pre-verify) — tofu_key_selection.rs asserts this |
| R-06-019 | yggdrasil-derivation.json is pubkey-based (seed removed); confirm spec 8.5 "Overview MUST match test vectors" wording still coherent with x25519.json split |
| R-06-022 | Per-hop verify adopted as universal default — confirm no config flag turns it off |
| R-06-023 | Keypair derivation identical across 3 stacks — confirmed by schnorr48.json corpus; spot-check C clamp constants |
| R-06-024 | BrProvisioned entries never bypass verify_iid_binding on load |
| R-06-025 | C first-boot key generation path (lichen_link_load_key) — confirm seed source is NVS not hardcoded |
| R-06-027 | Rust provisioning.rs mirrors python MANDATORY pubkey check — spot-check :838-870 |
| R-06-028 | Confirm EDHOC-derived provisioning key is separate from OSCORE session keys (key separation) |
| R-06-029 | wipe() is caller-invoked — confirm production call sites invoke it immediately after ACK |
| R-06-031 | C -EKEYREJECTED covers both IID-mismatch and trust-invalid; confirm enum covers 02xx mismatch too |
| R-06-032 | TOFU is default-enabled (no opt-in config required) in all stacks |
| R-06-033 | "alert" = warn-level log + error code; confirm no silent-drop path for key change |
| R-06-034 | Confirm provision_configured_peer rejects IID collision rather than replacing (fails closed :674-680) |
| R-06-037 | Mixed mode: confirm no code path lets BrProvisioned entries evict/override TOFU pins |
| R-06-042 | C gcp transcript is 103 bytes = 22+32+8+32+8+1? — verify byte count matches spec layout exactly |
| R-06-043 | Confirm slot-claim vs key-rotation domain separation covers the gateway COSE path too (resources.rs) |
| R-06-044 | Fresh replay state: confirm new entry's replay window/counter is zeroed, not inherited |
| R-06-045 | "require re-verification" — confirm re-verification is possible (new pin requires OOB/TOFU retry, not bricked peer) |
| R-06-049 | Rust floor-based rollback detection vs Python exact revision — confirm equivalence is sound for concurrent writers |
| R-06-050 | Confirm rotation-seq exhaustion (u64 max) actually blocks rotation (not just generation counter) |
| R-06-054 | Confirm equality case (seq == cached) is rejected (spec: MUST NOT accept <=) in all four code paths |
| R-06-056 | Rust link accepts divergent KEY_ROTATE as "valid attestation" — tracked under b7z9.28; confirm logging marks MITM-suspicion |

## C. Cross-cutting observations for Opus

1. **Spec self-reference drift:** spec 8.5/8.7 cite `rust/lichen-link/src/identity.rs:14-48`, `identity.rs:100`, and symbol `yggdrasil_addr_from_pubkey`; actual code has `iid_from_pubkey` (identity.rs:15) and `ygg_addr_from_pubkey` (moved to rust/lichen-core/src/addr.rs:109); `Identity::from_seed` is identity.rs:69. Open bead project-LICHEN-9k53. Recommend spec text fix (not done in this sweep — evidence belongs in matrix per protocol).
2. **test/vectors/README.md:208** still describes yggdrasil-derivation.json as seed→address although the file is pubkey-based (post project-LICHEN-worker6-8bar). Doc-only.
3. **§8.6 is the only paragraph where implementations deliberately "diverge" in the stronger direction** (per-hop verify). Everything else divergent is weaker or different-format.

# spec/06-security.md part 2 — flagged for Opus verification (sweep 2026-09-01)

All part-2 requirements concern OSCORE/EDHOC semantics, so per the sweep
protocol (c) every row is flagged; the divergent/ambiguous ones carry specific
questions. Matrix: docs/spec-coverage/06-security-part2.md.

**Scope mismatch to resolve first:** the wave prompt said "§5-§7: OSCORE,
EDHOC, group keying" but spec/06-security.md contains no §5-§7 — I swept
§8.8 + §8.9 + the OSCORE portion of §15.3. **Group keying has no section in
this file**; its implementations exist (group_oscore_key.json, groups_rekey.json,
group_oscore_wrap.py, oscore-fork/src/group.rs) — the wave runner should assign
its normative source (gateway coordination / applications spec) to a sweep.

| Req | Status | Question for Opus |
|-----|--------|-------------------|
| R-06-201 | implemented+tested | Confirm AES-CCM-16-64-128 parity is pinned by oscore.json (I cited vectors tests, did not re-run). |
| R-06-202 | implemented+tested | Confirm C 32-entry window matches the RFC 8613 default window the spec implies (spec 15.3 link table says OSCORE Partial IV; window size unstated in spec — is a window-size constant needed in the spec?). |
| R-06-203 | implemented+tested | Confirm HKDF info/label layout parity via oscore_context_parity.json. |
| R-06-204 | divergent (high) | Is "at most 64" the intended bound given C=8 (range 2-32), Python=2048, Rust=unbounded? Should spec be amended to implementation-reachable values (cf. GUARD_PPM precedent)? |
| R-06-205 | divergent (high) | C fails closed (OSCORE_ERR_NO_MEMORY) instead of evicting LRU; Python evicts; Rust neither. Which behavior is normative? Bead filed (human-only). |
| R-06-206 | implemented+untested | Descriptive overhead claim — accept by construction, or want a wire-size vector? |
| R-06-207 | ambiguous (low) | Rust has no static X25519-from-seed derivation (C/Python do). Unused-by-design under METHOD=0, or a parity gap? Bead filed (human-only). |
| R-06-208 | implemented+tested | Confirm Schnorr48-Ed25519 EDHOC mode (edhoc-schnorr48 feature) is actually exercised by a test, not just compiled (I only confirmed the Ed25519 path in vectors). |
| R-06-209 | implemented+tested | Spec writes text labels "OSCORE Master Secret"/"OSCORE Master Salt"; implementations use RFC 9528 §7.2 numeric labels 0/1. Suggest spec cite the numeric labels explicitly. |
| R-06-210 | ambiguous (low) | Rust/C nodes never establish EDHOC at runtime (lib+tests only). Is runtime EDHOC intended for Rust/C nodes, or is Python the EDHOC initiator stack with C/Rust on provisioned contexts? 24 h refresh is implemented nowhere — spec bullet should say SHOULD or be dropped. |
| R-06-211 | implemented+tested | None — confirm suite-0-only is pinned somewhere (vectors? Kconfig?). |
| R-06-212 | implemented (MAY) | None (MAY). |
| R-06-213 | divergent (SHOULD, high) | Python limits 64 global vs spec 3/peer + 10 global. Amend spec numbers or implementations? No bead (SHOULD). |
| R-06-214 | implemented+tested | Confirm C oscore_persist test covers restore-after-restart (not just serialize/deserialize round-trip). |
| R-06-215 | divergent (low) | "Authenticated record" — add MAC in C/Python, or weaken spec given radio-only threat model? Bead filed (human-only). |
| R-06-216 | implemented+tested | Confirm C commit-before-use ordering is test-pinned (I verified Rust fork contract + C persist tests exist). |
| R-06-217 | ambiguous (low) | C/Python: does the registered NVM/sqlite store provide the "independent monotonic rollback-and-deletion authority"? Rust CAS+floor does. Store-contract wording in spec may over-specify. |
| R-06-218 | implemented+untested (low) | Python corrupt-row behavior unverified; C magic/version rejection verified in code, test coverage unconfirmed. |
| R-06-219 | ambiguous (low) | No test found pinning "restore failure ⇒ context refused"; verify C create-with-eui64 restore-failure path actually fails closed. human-only. |
| R-06-220 | implemented+tested | None — key_update.rs pins sender-seq fencing. |
| R-06-221 | implemented+tested (low) | §15.3 claims "interop vectors pin the fresh-PIV requirement" — no observe case found in test/vectors/oscore*.json. Where is that pin, or is the spec claim stale? Receiver-rejection of missing-PIV notifications is not test-pinned. human-only. |
| R-06-222 | divergent (low) | C has no OSCORE Observe notification path at all (coap_oscore.c: no observe). Is C expected to serve OSCORE-protected notifications in v0.1, or should spec scope this to Rust? human-only. |

Beads filed against epic project-LICHEN-worker6-b7z9 (all human-only):
R-06-204/205 (context bound+LRU), R-06-215 (authenticated persistence),
R-06-207 (Rust X25519-from-seed).

# spec/06-security.md part 3 — flagged for Opus verification (sweep 2026-09-01)

Condition (c) of the sweep protocol applies (this IS 06-security), so the whole
section is in scope. Detailed entries below are the divergent / not-implemented /
low-confidence rows; the high-confidence implemented+tested rows follow in a
compact spot-check table. Companion matrix: `docs/spec-coverage/06-security-part3.md`.

## A. Divergent / not-implemented / low-confidence (detailed)

### A1. R-06-305 / R-06-310 — Root DIO signature: receiver wired only in Rust; no TX producer anywhere (divergent)
- **Requirement:** Receiver validation of the COSE_Sign1 root-signature DIO option (kid, alg, trust store, payload↔DIO cross-checks, expiry, root_seq cache keyed (dodag_id,instance)) — spec 8.10.1 L659-669; root SHOULD sign when CONFIG_LICHEN_RPL_ROOT_SIG=y (L693-696).
- **Classification:** divergent. Rust is fully wired in the production RX path (rust/lichen-node/src/rpl_stack/receive.rs:522→657-747, RootSeqCache rust/lichen-rpl/src/root_seq_cache.rs:45-97, TOFU pin store announce.rs:287). C has the complete decode/structural/replay library (lichen/subsys/lichen/rpl/root_dio_sig.c, root_dio_replay.c) but **zero production call sites** — dodag.c RX never consumes the option; only lichen/tests/rpl_root_sig calls it. Python's module (crypto/root_dio_signature.py) is an unwired oracle, and includes the **only root-side signing** implementation. No stack appends the option to outgoing DIOs; CONFIG_LICHEN_RPL_ROOT_SIG exists nowhere.
- **Bead:** project-LICHEN-worker6-b7z9.88 (filed this sweep; residual of closed b7z9.37, which predates the Rust RX wiring).
- **Question for Opus:** Is "Rust normative receiver, C/Python library-only" an acceptable steady state for a MAY defense-in-depth feature, or should C receiver wiring (one call site in dodag.c) be prioritized? Also: should the root-side signer be ported to Rust/C before the CONFIG switch exists, so the option can actually appear on the wire?

### A2. R-06-307 — expired root signature → Baseline: implemented, untested in RX path (low confidence)
- **Requirement:** Expired signature treated as unsigned; accepted with link-layer auth only (spec 8.10.1 L689).
- **Classification:** implemented+untested. Rust maps expired → Baseline (receive.rs:713-715); the only expiry test (root_sig.rs:489) is at the structural layer, not the RX outcome layer.
- **Bead:** none (single-line test gap; fold into the A1 bead's acceptance criteria if Opus agrees).
- **Question for Opus:** Should the A1 bead's acceptance criteria include an RX-path test pinning "expired ⇒ Baseline, not Reject" (the vector set currently has valid_far_expiry but no expired case)?

### A3. R-06-309 — root re-election must clear cached root_seq: no explicit clear anywhere (low confidence)
- **Requirement:** Root re-election ⇒ clear cached root_seq; new root starts fresh (spec 8.10.1 L686).
- **Classification:** implemented+untested (transitive). No stack clears the cache on re-election. Mitigation: the cache is keyed (dodag_id, instance) and DODAGID is cryptographically bound to the root's key (structural check root_dio_sig.c:419-423), so a genuinely new root necessarily produces a new dodag_id and a fresh cache key — the spec's intent (stale root's seq floor must not veto the new root) appears satisfied by construction. But a same-dodag_id re-election (root re-formation under the same DODAGID) has no path to reset the floor.
- **Bead:** none (flagged; may be spec-text clarification rather than code).
- **Question for Opus:** (a) Can a re-elected root reuse the same DODAGID in LICHEN's key-derived-address model? If not, propose amending the L686 table cell to note the dodag_id keying rationale. If yes, a clear-on-new-root hook is a real gap.

### A4. R-06-341 — §15.2 key storage MUST vs plain-flash implementations (divergent; threat-model tension)
- **Requirement:** Private keys MUST be stored in a hardware secure element (preferred) or flash with readout protection; never transmitted over the air (spec 15.2 L1211-1216).
- **Classification:** divergent. Never-over-the-air holds in all stacks (no private-key TX path). Storage is plain flash with integrity (C LIKY record + CRC + settings rollback authority; Rust Zeroizing + abort-on-fail; Python 0600 two-slot store citing spec 15.2 verbatim). No secure element, no flash readout protection (RDP) support anywhere.
- **Bead:** project-LICHEN-worker6-b7z9.87, filed this sweep, human-labeled — the project threat model (AGENTS.md) explicitly excludes physical/cold-boot attackers, which is the only adversary RDP/SE defends against. This is a spec-text vs threat-model adjudication, not a code fix.
- **Question for Opus (human decision):** Amend §15.2 to match the threat model ("stored in flash; never transmitted; secure element preferred where hardware provides it"), or keep the MUST and treat it as hardware-deployment guidance? Recommend the former (mirrors the GUARD_PPM-style align-spec-to-reality precedent).

### A5. R-06-342 — §15.3 "epoch increments on wrap" vs implemented never-wrap exhaustion (divergent, spec-text candidate)
- **Requirement:** Link-layer replay epoch persisted to flash; increments on wrap or reboot (spec 15.3 L1229-1230).
- **Classification:** implemented+tested with one wording divergence: all three stacks deliberately never wrap — epoch 255 is exhausted → fail closed / identity rotation (C replay.h "Epochs … never wrap"; Rust lichend.rs:211-236 fails at 255; Python EpochExhaustedError). Wrapping would reopen the replay window, so the implementations are safer than the spec sentence.
- **Bead:** project-LICHEN-worker6-b7z9.86 (filed this sweep; spec-text alignment; mirrors adjudicated-decision practice, e.g. trickle Imax).
- **Question for Opus:** Confirm the spec should read "epoch increments on reboot; epoch space is never wrapped — exhaustion at 255 fails closed and requires identity rotation" (or similar), matching all three implementations and epoch_rollover.json.

### A6. R-06-302 — RPL preinstalled secure mode (CONFIG_LICHEN_RPL_SECURE_MODE / RPL_PSK) absent everywhere (not-implemented, MAY)
- **Requirement:** Optional RPL preinstalled mode adds a network-wide control-plane PSK (spec 8.10 L555-582); §15.6 item 3 recommends enabling it in adversarial environments.
- **Classification:** not-implemented (no Kconfig, no code, no PSK MAC over RPL control in any stack). MAY-level ⇒ no bead per protocol; noted because §15.6's recommendation is currently unactionable.
- **Question for Opus:** Confirm the feature stays optional/deferred (docs/spec-chapter-breakdowns.md:937 lists it as planned P2), and whether §15.6 item 3 should be reworded until it exists.

### A7. R-06-318 — C authorization table bound 8 (max 32) vs recommended 256 LRU (divergent detail)
- **Requirement:** Authorization table MUST be bounded; recommended 256 entries LRU (spec 8.11 L809-812).
- **Classification:** implemented+tested — the MUST (bounded) is met in all stacks; C's default 8 / max 32 is below the *recommendation* only, and C compensates with fail-closed replay-floor history. STM32WL RAM constraints may justify the smaller bound.
- **Question for Opus:** Bless C's 8/32 bound (STM32WL memory budget) or require a Kconfig default closer to 256 for non-constrained gateway builds?

### A8. R-06-326 / R-06-327 — Python capability-announce resource quirks (divergent details)
- **Requirement:** Root validates capability announcements and bounds the capability table, MAY reserving 25% for egress-bit entries (spec 8.12 L949-984).
- **Classification:** implemented+tested overall, with two Python-only quirks: (a) verify re-encodes the protected header instead of hashing received bytes (capability_announcements.py:316) — equivalent for canonical messages, differs on exotic headers; (b) resource calls record() without egress= (:172-177), so the 25% egress reservation never engages (the MAY feature is inert; the MUST bound still holds at 256).
- **Bead:** none — (b) is a MAY-feature omission and (a) is equivalence-preserving on canonical input.
- **Question for Opus:** Is (a) worth a fail-closed tightening (hash received bytes like Rust), or document canonical-only?

### A9. R-06-315 — route_hash hops are caller-supplied; no SRH extraction at this site (low confidence)
- **Requirement:** route_hash computed from hop IIDs "in source-route order … matches the order in the IPv6 Source-Route Header" (spec 8.11 L758-767).
- **Classification:** implemented+tested at the library level (vector route_hops_hex pins the order); but no stack parses the hops out of an actual IPv6 Source-Route Header at this site — that is part of the unwired data path (R-06-311, b7z9.35).
- **Question for Opus:** Confirm b7z9.35's acceptance criteria include "hops extracted from the received SRH, order verified against the route_hash" so the spec sentence gets a live-wire test.

## B. Compact spot-check table (implemented+tested, high confidence)

| Req | Topic | Key evidence |
|-----|-------|--------------|
| R-06-301 | Unsigned RPL control rejected; no permissive mode | link_layer.rs:1092-1096; authenticated_dio.py:291-326; test_rpl_control_link_signatures.py:249 |
| R-06-303 | Root-sig option 0x17 + COSE_Sign1 format | message.rs:85; messages.c:176-223; root_dio_signature.json (14 vectors) |
| R-06-304 | Payload keys 1-7 + Sig_structure/SHA-256/Schnorr48 | root_sig.rs:146-347; root_dio_sig.c:226-392; cross-stack byte parity |
| R-06-306 | Graceful degradation (MUST NOT reject for missing root sig) | receive.rs:638-648, 681-712; rpl_root_sig main.c:200 |
| R-06-308 | root_seq MUST NOT wrap | root_seq_cache.rs:131-138; root_dio_replay.c:31-33; vector valid_seq_max |
| R-06-312/314/315 | tunnel-auth COSE envelope, payload keys 1-6, route_hash | tunnel_auth.rs:11-17/526-607/470-480; tunnel_authorization.json all-stack byte parity |
| R-06-316 | Egress 10-step validation, 2.04/4.03 | tunnel_auth.rs:282-372; tunnel_auth.c:327-367; tunnel_auth.py:438-494; 26 post_cases |
| R-06-317 | Decap policy checks (as library) | decapsulation_cases (13) driven by all three stacks |
| R-06-320/321 | Root-change table clear API; restart clears by design | set_root/change_root + root_rotation vectors |
| R-06-322 | COSE_Sign1 -65537 as standard envelope | root-sig, capability, slot-claim, delegation tokens all use it |
| R-06-323/325 | Capability bits + payload keys 1-6 (Rust/Py) | capability_announcements.json; reserved-bits vectors |
| R-06-342 | 32-entry replay window + epoch persistence | replay.h:59-64; replay.rs:39-75; replay.py:40; lichen/tests/replay*; epoch_rollover.json |
| R-06-343 | Key-derived stable addresses; no privacy extensions | addr.rs:86; short_addr.rs:23; identity_addr.c:28; ipv6-addresses.json |

## C. Already-tracked divergences (no new beads; verify owners still active)

- Tunnel-auth production wiring (CoAP endpoint C/Rust, data-path decap gate, root triggers, DIO root-change detection): `project-LICHEN-worker6-b7z9.35` + children `m9i4`, `utw0`; Rust sub-bugs `4j1y`, `tpbv`, `b3le`, `t6sj`.
- Capability-announce system layer (spec-path dispatch, C resource, re-announce on root change): `b7z9.36` + children `7nnl`, `7nnl.3`, `99sg`, `p7mv`.
- Node credentials + local facts (§8.13/§8.13.1, rows R-06-331…340): epic `project-LICHEN-worker6-bedw` + children `.1`-`.10`.
