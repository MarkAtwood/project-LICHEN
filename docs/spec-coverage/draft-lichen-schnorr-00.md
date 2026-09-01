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
