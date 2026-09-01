## spec/06-security.md (part 2 of 3: §8.8 OSCORE, §8.9 EDHOC, §15.3 OSCORE replay) — coverage (sweep 2026-09-01)

Scope note: the wave prompt named "§5-§7: OSCORE, EDHOC, group keying", but
spec/06-security.md has no §5-§7 (it numbers §8.1-§8.13 + §15.1-§15.6). This
part sweeps the OSCORE/EDHOC material: §8.8, §8.9, and the OSCORE-specific
replay content of §15.3 (lines 1232-1275). §8.1-§8.7 and §8.10-§8.13/§15
belong to parts 1 and 3. **Group keying has no dedicated section in this
spec file** — group OSCORE keying is implemented (test/vectors/group_oscore_key.json,
groups_rekey.json, python/src/lichen/crypto/group_oscore_wrap.py,
python/tests/crypto/test_group_oscore*.py) but its normative source lives in
another spec (gateway coordination / applications), not 06-security.

Req numbering: `R-06-2NN` for part 2, to avoid collision with parts 1/3.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-06-201 | OSCORE confidentiality: AES-CCM-16-64-128 | implemented+tested | rust/oscore-fork/src/lib.rs:46-47 (`type AesCcm = Ccm<Aes128, U8, U13>`); lichen/subsys/lichen/oscore/oscore_protect.c:311,473 (lichen_aes_ccm_encrypt/decrypt); python/src/lichen/crypto/oscore.py:197 (default AES-CCM-16-64-128). Tests: rust/lichen-oscore/tests/vectors.rs, lichen/tests/oscore, test/vectors/oscore.json | high |
| R-06-202 | OSCORE replay protection via sequence number | implemented+tested | rust/oscore-fork/src/seqnum.rs + ownership fencing; lichen/subsys/lichen/oscore/oscore_replay.c (32-entry window); python sqlite_store.py:262 (restore_replay_window). Tests: test/vectors/oscore_cross_exchange.json, lichen/tests/oscore, rust/lichen-oscore/tests/vectors.rs | high |
| R-06-203 | Key derivation: HKDF from master secret | implemented+tested | lichen/subsys/lichen/oscore/hkdf.c; rust/oscore-fork/src/edhoc/kdf.rs:35 (hkdf_extract); python crypto/oscore.py. Tests: test/vectors/oscore_context_parity.json, python/tests/crypto/test_oscore_context_parity.py, rust/lichen-oscore/tests/context_parity.rs | high |
| R-06-204 | MUST bound OSCORE security contexts to at most 64 entries | divergent | C bound ≤64 ✓ (lichen/subsys/lichen/oscore/Kconfig:20-23, `LICHEN_OSCORE_MAX_CONTEXTS` default 8, range 2-32); Python 2048 ✗ (python/src/lichen/coap/secure/channel.py:144 `_MAX_ACTIVE_PEER_CONTEXTS = 2048`); Rust node unbounded ✗ (rust/lichen-node/src/secure.rs:443 `contexts: HashMap<[u8;8], Context>`, inserts at :565,:579 with no cap found). **human-only (oscore semantics)** | high |
| R-06-205 | MUST evict least-recently-used context on overflow (LRU by last message timestamp) | divergent | C: full table returns OSCORE_ERR_NO_MEMORY, no eviction (lichen/subsys/lichen/oscore/oscore_ctx.c:379-388 "Find free slot ... if (ctx == NULL) return OSCORE_ERR_NO_MEMORY"); Python LRU eviction ✓ but bound 2048 (channel.py:416-435 `_evict_peer_contexts_if_needed`); Rust node: no eviction found (secure.rs:565/579). **human-only (oscore semantics)** | high |
| R-06-206 | OSCORE overhead 8-13 bytes (Partial IV + Tag) | implemented+untested | Consistent across stacks: 8-byte tag (`Ccm<Aes128, U8, U13>`), PIV ≤5 (lichen/subsys/lichen/oscore/include/lichen/oscore.h:96 `OSCORE_PIV_MAX_LEN 5`); descriptive bound, no dedicated test | high |
| R-06-207 | x25519_private = clamp(SHA-512(seed)[0:32]); clamping per RFC 7748 §5 REQUIRED | ambiguous | C ✓ (lichen/subsys/lichen/edhoc/edhoc_crypto.c:287 `x25519_keypair_from_seed`, documented at edhoc_internal.h:89-94; exercised by lichen/tests/edhoc_handshake); Python ✓ (python/src/lichen/crypto/identity.py:98-103 `x25519_private`, :119 `x25519_public`); Rust ✗ static-from-seed derivation not found anywhere in rust/ (fork edhoc uses random ephemeral X25519, initiator.rs:180, and Ed25519 seed only for signatures, sign.rs:77). Unclear whether Rust needs it: METHOD=0 (sig/sig) never uses static DH. **human-only (EDHOC semantics)** | low |
| R-06-208 | EDHOC msg 2/3 authenticate via Ed25519 (or Schnorr variant) signatures from existing link-layer keypairs | implemented+tested | rust/oscore-fork/src/edhoc/initiator.rs:224 (METHOD=0 signature/signature), credential.rs:59-65 (Ed25519 CCS), sign.rs (ed25519_dalek); schnorr48 variant feature exists (rust/oscore-fork/Cargo.toml:59 `edhoc-schnorr48`); Python python/src/lichen/crypto/edhoc.py; C lichen/subsys/lichen/edhoc/. Tests: test/vectors/edhoc.json, lichen/tests/edhoc_handshake, python/tests/crypto/test_edhoc.py | high |
| R-06-209 | OSCORE Master Secret = EDHOC-Exporter(...,16), Master Salt = EDHOC-Exporter(...,8) | implemented+tested | RFC 9528 §7.2 numeric labels 0/1 (spec's text labels are informational): rust/oscore-fork/src/edhoc/kdf.rs:31-135 (LABEL_OSCORE_SECRET=0 → KEY_LEN 16; LABEL_OSCORE_SALT=1 → 8); python/src/lichen/crypto/edhoc.py:571-572,844-845; C lichen/tests/edhoc_export/src/main.c `test_rfc9529_export_chain` (label 7→10→0/1 chain, master_secret+master_salt pinned) | high |
| R-06-210 | When to run EDHOC: lazy on first OSCORE request; explicit POST /.well-known/edhoc; periodic refresh 24 h / seq exhaustion | ambiguous | Python: lazy ✓ (channel.py:126-131 docstring + `_establish` path :1449-1460), explicit endpoint ✓ (python/src/lichen/coap/resources/edhoc.py, registered at site.py:285); 24 h periodic refresh: not found in any stack; Rust node: no EDHOC integration (no edhoc refs in rust/lichen-node/src — edhoc only in lichen-oscore lib/tests); C node: EDHOC lib + tests only (lichen/subsys/lichen/edhoc, lichen/tests/edhoc_handshake). Unclear: whether Rust/C nodes are intended to establish EDHOC at runtime at all (nodes MAY use pre-shared contexts per §8.9) | low |
| R-06-211 | EDHOC cipher suite 0 (AES-CCM-16-64-128 / SHA-256 / X25519 / Ed25519) REQUIRED | implemented+tested | rust/oscore-fork/Cargo.toml:58 (`edhoc` = x25519-dalek + ed25519-dalek), SHA-256 KDF (kdf.rs), AES-CCM (lib.rs:46); python/src/lichen/crypto/edhoc.py:8 ("Why Suite 0 ... Matches link-layer Ed25519"); C lichen/subsys/lichen/edhoc. Tests: test/vectors/edhoc.json, edhoc_export_rfc9529.json | high |
| R-06-212 | Nodes unable to run EDHOC MAY use pre-shared OSCORE contexts provisioned out-of-band | implemented+untested (MAY) | C oscore_ctx_create* (lichen/subsys/lichen/oscore/oscore_ctx.c:311+) fed by provisioning; python crypto/provisioning.py; vector test/vectors/gcp_psk_oscore.json exists as parity input | high |
| R-06-213 | SHOULD rate-limit concurrent EDHOC handshakes to ≤3 per peer IID and 10 globally | divergent (SHOULD) | Python: global-only bound 64, no per-peer cap (python/src/lichen/coap/secure/channel.py:144 `_MAX_CONCURRENT_EDHOC = 64`, check at :1456-1460); no EDHOC handshake limiting found in Rust or C (neither node integrates EDHOC at runtime). SHOULD-gap noted in matrix, no bead filed (hardening recommendation; omission breaks no documented feature) | high |
| R-06-214 | OSCORE sender seq reservations, recipient replay window, response replay state MUST remain valid across restart | implemented+tested | C: NVM callbacks + SSN restore (lichen/subsys/lichen/oscore/oscore.h:272, oscore_persist.c); Rust: `ContextStateStore` compare_exchange + `reserve_sender` durable commit (rust/oscore-fork/src/lib.rs `reserve_sender` "Storage advances before this returns"); Python: sqlite_store.py:262,339-342 (replay window + sender seq persisted). Tests: lichen/tests/oscore_persist, rust/lichen-oscore/tests/key_update.rs | high |
| R-06-215 | Persistent state MUST be a versioned, authenticated record bound to the exact Security Context | divergent | C: versioned ✓, authenticated ✗ — MAGIC + FORMAT_VERSION only, no MAC/checksum over state (lichen/subsys/lichen/oscore/oscore_persist.c:12,170-171,204-205); context binding ✓ (record_id_derive, oscore_ctx.c:368-378); Python: no version or authentication found in sqlite_store.py; Rust: trait contract + app-level store (rust/lichen-gateway/src/gateway.rs:1072 `save_atomic_with_floor`). **human-only (oscore semantics)** | low |
| R-06-216 | Sender reservation committed before nonce use; replay state committed before plaintext/result released | implemented+tested | Rust: reserve→commit ordering (rust/oscore-fork/src/lib.rs reserve_sender doc: "a crash can only skip the reserved sequence"; Conflict for competing contexts); receiver ownership fencing (rust/lichen-oscore/src/ownership.rs:26-31). Tests: rust/lichen-oscore/tests/ownership.rs, key_update.rs; C: lichen/tests/oscore_persist | high |
| R-06-217 | Persistent state MUST be protected by an independent monotonic rollback-and-deletion authority, updated atomically | ambiguous | Rust ✓ (compare_exchange_sender CAS + `save_atomic_with_floor`, rust/lichen-gateway/src/gateway.rs:1072,1185; fork lib.rs KeyUpdateStore/ContextStateStore). C: NVM callback abstraction (oscore_ctx.c:194-205) — whether the registered store provides monotonic rollback authority is store-implementation-defined, unverified. Python: sqlite transactions, floor semantics unverified. Unclear: C/Python store guarantees | low |
| R-06-218 | Missing/corrupt/torn/stale/rolled-back state MUST fail closed | implemented+untested | C: load validates MAGIC+FORMAT_VERSION and rejects otherwise (oscore_persist.c:204-205); Rust: ReservationError::Conflict / fail-closed paths (fork lib.rs; ownership.rs:48 refuses at capacity). Python fail-closed behavior on corrupt rows: unverified | low |
| R-06-219 | If state cannot be restored, MUST NOT reuse the affected context; fresh context with distinct key/nonce material required | ambiguous | C header documents re-create flow on restore failure (lichen/subsys/lichen/oscore/include/lichen/oscore.h:219-220,272); Rust re-key path exists (key_update.rs). Whether every restore-failure path actually refuses the old context (vs. proceeding) is not pinned by a test I found. **human-only (oscore semantics)** | low |
| R-06-220 | Clearing a replay window while retaining the old context MUST NOT re-accept previously accepted messages | implemented+tested | Rust: key updates fence sender sequence without resetting acceptance (rust/lichen-oscore/src/lib.rs:300 "Key updates only fence the sender sequence"); test rust/lichen-oscore/tests/key_update.rs; C oscore_replay.c window persistence | high |
| R-06-221 | Every Observe notification MUST carry a fresh, nonzero Partial IV; receivers MUST reject any notification lacking one (deliberate RFC 8613 §4.1.3.5 deviation) | implemented+tested | Sender: fresh PIV by construction — rust/oscore-fork/src/protect.rs:52-74 `protect_response_with_piv` uses the reserved sender sequence as response PIV (nonce = compute_nonce(sender_id, response_piv), :483); request PIV feeds AAD only (:498). Node test rust/lichen-node/src/secure.rs:3145 `protected_observe_registration_notifications_retries_blocks_and_reset`; rust/lichen-oscore/tests/observe_responses.rs. Receiver-rejection of a missing/fresh-PIV-less notification: no pinning test found; §15.3 claims "interop vectors pin the fresh-PIV requirement" but no observe case exists in test/vectors/oscore*.json. **human-only (oscore semantics)** | low |
| R-06-222 | LICHEN servers (Rust and C) MUST always include a fresh Partial IV per notification | divergent | Rust ✓ (secure.rs:3145 test, protect.rs construction above). C: no OSCORE-protected Observe notification path found — coap_oscore.c has no observe handling; C coap_client.c:175,193 has client-side observe only. C server OSCORE notifications: not-implemented. **human-only (oscore semantics)** | low |

## Histogram

| Status | Count |
|--------|-------|
| implemented+tested | 9 (201,202,203,208,209,211,214,216,220) |
| implemented+untested | 2 (206,212) |
| divergent | 5 (204,205,213,215,222) |
| ambiguous | 6 (207,210,217,218,219,221) |
| not-implemented | 0 |

## Gap beads

Filed 3 (cap 10, overflow 0), all `human-only` per oscore/EDHOC edit bar:
1. R-06-204 + R-06-205 — context bound ≤64 + LRU eviction divergent across stacks (C bound ok but no eviction; Python 2048; Rust unbounded).
2. R-06-215 (+ R-06-218 C/Python residue) — persisted OSCORE state not authenticated (C: magic+version only; Python: no version/auth found).
3. R-06-207 — Rust lacks static X25519-from-Ed25519-seed derivation (C/Python have it; may be unused-by-design under METHOD=0).

SHOULD-divergence noted in matrix only (no bead): R-06-213 rate-limit values.
MAY rows never filed: R-06-212.

## Group keying

Not a section of spec/06-security.md — no R-06 requirements extracted for it.
Implementation evidence exists (test/vectors/group_oscore_key.json, groups_rekey.json,
python/src/lichen/crypto/group_oscore_wrap.py, python/tests/crypto/test_group_oscore*.py,
rust/oscore-fork/src/group.rs, lichen/subsys/lichen/oscore Kconfig `LICHEN_OSCORE_GROUP_MAX`);
its normative source should be swept under whichever spec owns it (gateway coordination /
applications), flagged for the wave runner to assign.


