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
