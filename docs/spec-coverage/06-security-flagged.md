# spec/06-security.md — flagged for Opus verification (sweep 2026-09-09)

Condition (c) of the sweep protocol applies (this IS 06-security), so the whole
section is in scope. Detailed entries below are the divergent / not-implemented /
ambiguous / low-confidence rows plus the decision-alignment edits made this
sweep; the high-confidence implemented+tested rows follow in a compact
spot-check table. Companion matrix: `docs/spec-coverage/06-security.md`.
This sweep consolidates and re-verifies part1/part2/part3 (their R-06 numbering
is reused; updated classifications are called out in the matrix notes).

## A. Step-0 decision alignment — spec edits made this sweep (confirm)

### A1. §15.2 amended per decision `spec-15.2-key-storage`
- The text still carried "Private keys MUST be stored in … Flash with readout
  protection" though the decision (2026-09-02) dropped the SE/RDP MUST.
- **Edit made:** replaced with "stored in flash (with integrity protection),
  never transmitted; secure element preferred where hardware provides it;
  readout protection not required (threat model excludes physical readout)."
- **Question for Opus:** confirm the amendment wording satisfies the decision;
  existing bead project-LICHEN-worker6-b7z9.87's driver is resolved — can it be closed?

### A2. §8.8 amended per decision `oscore-context-bound`
- The text said "MUST bound … to at most 64 entries" — a hard ceiling the
  decision explicitly rejects ("floor 8 and recommendation 64, not a hard ceiling").
- **Edit made:** MUST bound (finite) + MUST evict LRU on overflow + RECOMMENDED 64
  + constrained nodes MUST support at least 8.
- **Question for Opus:** confirm; and note the code now lags the amended text in
  all three stacks (bead project-LICHEN-worker6-b7z9.94).

## B. Divergent / ambiguous / not-implemented (detailed)

### B1. R-06-315 — route_hash hop width: spec+Python (16-byte addresses) vs Rust+C+committed vector (8-byte IIDs)
- **Requirement:** §8.11 route-hash amendment: route_hash = SHA-256 over the FULL
  16-byte hop addresses as reconstructed from the SRH, "not IIDs" (AddrForKey
  addresses embed no IID).
- **Classification:** divergent. Python conforms (tunnel_auth.py:155-163);
  Rust hashes `[[u8;8]]` (tunnel_auth.rs:493-503); C hashes 8-byte IIDs
  (tunnel_auth.c:201-216); test/vectors/tunnel_authorization.json:61-65 pins the
  8-byte form. Note part-3's sweep recorded this row as implemented+tested when
  the spec still described IIDs — the spec paragraph has since been amended.
- **Bead:** project-LICHEN-worker6-b7z9.93 (filed this sweep).
- **Question for Opus:** Confirm the 16-byte amendment is the settled intent
  (the rationale paragraph reads as a deliberate fix for IID-embedding and the
  false loop-rejection), so Rust/C/vectors migrate — or is the 8-byte fixture
  form the intended baseline and the spec paragraph should revert? Either way,
  three of the four parties must change.

### B2. R-06-204/205 — OSCORE context bound + LRU (decision `oscore-context-bound`)
- **Classification:** divergent in all stacks (C: bound 8, no eviction, no
  min-8 floor; Python: 2048 + LRU; Rust: unbounded). Part-2 marked rows
  "human-only (oscore semantics)"; the decision makes them implementation
  obligations — reclassified.
- **Bead:** project-LICHEN-worker6-b7z9.94. **Question for Opus:** confirm the
  human-only label from part-2 is superseded by the decision, and that the C
  Kconfig range (2-32) needs an enforced floor of 8.

### B3. R-06-215/217 — Python OSCORE persisted-state lacks MAC + rollback authority (decision `oscore-persist-auth`)
- **Classification:** divergent. C and Rust conform (MAC/sealed records +
  rollback authority, tested). Python sqlite_store.py has no record
  authenticator and does not consume rollback_anchor.py.
- **Bead:** project-LICHEN-worker6-b7z9.95. **Question for Opus:** confirm the
  MAC should cover the full record and bind to context identity the way C's
  BLAKE2b binding does (oscore_settings.c:108-139 analog).

### B4. R-06-324 (+051/052/055, 303) — COSE_Sign1 tag-18/untagged accept-both (decision `cose-sign1-tag18`)
- **Classification:** divergent per envelope and in both directions: C
  capability-announce rejects tag-18; Rust root-sig rejects untagged; Python
  root-sig rejects tagged; Python+Rust capability accept both.
- **Bead:** project-LICHEN-worker6-b7z9.96. **Question for Opus:** confirm
  accept-both for EVERY envelope (root-sig, tunnel-auth, key-rotation,
  credentials, slot-claim) and that existing single-form vectors stay valid.

### B5. R-06-324/328/329 — capability-announce production wiring remainder
- **Classification:** divergent. Rust mounts /.well-known/lichen-gw/* instead of
  the spec path; C resource exists but no app wires the handler (4.04);
  node-side announcer Python-only (MUST re-announce on root change unmet in
  Rust/C); join-time announce absent everywhere.
- **Bead:** project-LICHEN-worker6-b7z9.97 (b7z9.36 is stale). **Question for
  Opus:** is the Rust /.well-known/lichen-gw/* prefix an intentional
  coordinator namespace (spec path then wrong for Rust) or a spec violation to
  fix? Decide before implementing.

### B6. R-06-319/330 — DAO→tunnel-auth trigger + capability-table consult
- **Classification:** divergent/not-implemented in all stacks (hooks exist,
  nothing calls them; no capability-table consult).
- **Bead:** project-LICHEN-worker6-b7z9.98. **Question for Opus:** the SHOULD
  trigger breaks the documented tunnel-auth feature loop (authorizations are
  only ever provisioned manually); confirm this SHOULD-gap should be worked as
  a feature-completion bead (it was filed P2) rather than left as SHOULD-class.

### B7. R-06-048/049 — trust/private-key store hardening: Rust gateway + C gaps
- **Classification:** divergent. Rust: no interprocess lock (no flock anywhere
  in rust/), no exact-revision CAS (monotonic floor instead), temp files
  without explicit 0600. C: in-process mutex only — embedded-scope question
  (NVS replaces host-file semantics; part-1 flagged A12 raised the same).
- **Bead:** project-LICHEN-worker6-b7z9.100. **Question for Opus:** (a) does a
  monotonic-floor + rename scheme satisfy "exact revision comparison and fail
  rather than silently overwrite", or is a literal CAS required? (b) do the
  §8.7 host-file hardening MUSTs apply to the C/NVS store, or is C out of scope?

### B8. R-06-051/052/055 — §8.7.4 COSE attestation unwired
- **Classification:** divergent (Python library exact+tested, wired to nothing;
  Rust/C use the §8.7 raw transcript; rust-link a third format).
- **Bead:** project-LICHEN-worker6-b7z9.99 (formats: b7z9.28; C persistence: b7z9.33).
- **Question for Opus:** does §8.7.4 supersede the §8.7 transcript scheme
  (part-1 flagged A10 — still unresolved), and should the matrix treat the
  raw-transcript rotation as conformant for §8.7 while the COSE form is the
  over-the-air mechanism?

### B9. R-06-336/351 — local facts: Python library only
- **Classification:** divergent (no endpoint in any stack; Rust/C absent;
  caller-side seq cache absent).
- **Bead:** project-LICHEN-worker6-b7z9.102. **Question for Opus:** should the
  per-issuer seq cache be a store of record (persisted, revision-guarded like
  the trust store) or in-memory mesh-lifetime state per §8.13.1's
  "mesh-lifetime" framing?

### B10. R-06-049 — Rust floor-based CAS vs spec "exact revision comparison"
- Split from B7 because it is a judgment call, not a plain gap: part-1
  accepted monotonic-floor + rename as equivalent-or-stronger; the decision
  text is literal. **Question for Opus:** pick a reading and note it on the
  bead (b7z9.100) so the fix or the spec text can land.

### B11. R-06-004 — RFC 6979 nonce mislabel (spec-text)
- All stacks implement H(privkey‖msg) mod L — the spec's own pseudocode; the
  "RFC 6979" parenthetical is wrong. **Bead:** b7z9.101. **Question:** relabel
  spec, or change implementations to true RFC 6979? (Spec pseudocode + vectors
  say hash construction; recommend relabel.)

### B12. R-06-209 — exporter label phrasing; R-06-221 — "interop vectors pin fresh-PIV" claim
- Implementations use RFC 9528 numeric labels 0/1; spec writes text labels. No
  interop vector pins the fresh-PIV deviation despite the spec's claim (unit
  tests do). **Bead:** b7z9.101 (both). **Question:** add vectors or fix text?

### B13. R-06-353 — §15.3 time-bounded dedup MUSTs (ambiguous)
- Relay dedup exists (node.py:335 — Hop-Limit-normalized, not message-ID
  absolute-expiry keyed) and SOS relay TTL dedup (§18.4.3); no DTN
  store-and-forward message-ID dedup store with absolute-TTL expiry located.
- **Question for Opus:** is the DTN message-ID dedup table specified here
  actually the 05-routing custody/dedup mechanism (cross-sweep scope)? If
  06-security owns it, a gap bead is needed; currently ambiguous, not beaded.

### B14. R-06-020/021 — §8.6 signature caching (carried from part-1 flagged A6)
- All stacks verify every frame per hop (stronger); no cache, no 30 s TTL;
  §8.6 has no RFC-2119 keywords so every implementation reads non-conforming on
  a performance suggestion. **Question for Opus (spec-editor):** amend §8.6 to
  make per-hop verification the baseline with the cache OPTIONAL.

### B15. R-06-046 — local revocation implemented Python-only
- Rust gateway TrustEntry and C stores have no revoked handling (searched:
  revoked, revocation). Spec sentence has no keyword. **Question:** MUST,
  SHOULD, or covered by §8.7 revocation text? (Be only if MUST.)

### B16. R-06-309 — root re-election: no explicit root_seq cache clear
- Cache keyed (dodag_id, instance) + DODAGID bound to root key ⇒ new root ⇒ new
  key ⇒ fresh cache entry transitively. Same-DODAGID re-election by a different
  key is impossible under the AddrForKey binding. **Question for Opus:** accept
  the transitive argument, or require an explicit clear-on-reelection test?

### B17. R-06-353 — dedup MUSTs (see B13 above, same item; kept here for the row index)
- Classification ambiguous — needs ownership arbitration (06 vs 05-routing).

## C. High-confidence implemented+tested rows — compact spot-check list

These are the riskiest assumptions behind rows classified implemented+tested/high:

| Req | Spot-check question |
|-----|---------------------|
| R-06-001/301 | Any RPL control path that bypasses the signed link frame (loopback/LLCI) without signing? |
| R-06-004 | Confirm draft-lichen-schnorr-00 wording — does the draft itself claim RFC 6979, or only the security section? |
| R-06-006 | Python replay-window update strictly after verify (same enforced order as Rust/C)? |
| R-06-009/010 | C DAO RX precedence + volatile floor — confirm b7z9.81/b7z9.11 scopes cover the §8.4 MUSTs without new beads |
| R-06-015 | Upstream anchor byte-equality: confirm all three stacks consume test/vectors/yggdrasil_address.json anchor verbatim (not regenerated) |
| R-06-015 (quarantine) | legacy/yggdrasil-derivation.json ygg_addr fields regenerated to upstream values — acceptable quarantine hygiene, or should the file be regenerated/annotated? |
| R-06-016/207 | Rust static seed→X25519: confirm human-only bar applies and Rust METHOD=0 ephemeral-only is spec-conformant (b7z9.38) |
| R-06-033 | C mismatch operator alert (coap_keys_alert.c) covers all mismatch classes (IID derivation + key change), not just key change |
| R-06-042 | C gcp transcript 103-byte layout matches spec byte-for-byte (22+32+8+32+8+1) |
| R-06-047 | C store's absence of a 0200:: recompute acceptable (no field exists), or must C store + recompute the 0200 address per the MUST? |
| R-06-056 | With the §8.7.4 COSE path unwired, is the gateway raw transcript the only conformant rotation path? (b7z9.99) |
| R-06-204 (C) | C Kconfig range permits 2 < min-8 floor — confirm the floor must be enforced in code, not just documented |
| R-06-211 | Suite-0 rejection covers ERR_WRONG_SELECTED_CIPHER_SUITE in rust fork too (python/C pinned by suite_negotiation.json) |
| R-06-311 | C egress gate ponytail caveats (single-hop SRH, uptime-vs-unix time) acceptable interim, or must expiry go live now? |
| R-06-313 | Rust tunnel-auth dispatch under coordinator namespace vs spec path — same question as B5 for tunnel-auth (resources.rs:2350) |
| R-06-318 | C auth-table capacity 8 (max 32) — MUST met, recommendation not; acceptable for C nodes or bump default? |
| R-06-321 | Confirm no stack persists the authorization table (mesh-lifetime by design) |
| R-06-327 | Python resource never passes egress= to record() so the 25% reservation is inert — wire it or drop the MAY? |
| R-06-342 | Rust lichend.rs epoch persistence is binary-level; node library callers that don't use lichend get caller-supplied epochs — acceptable? |
| R-06-221 | Spec's "interop vectors pin the fresh-PIV requirement" — add the vector (b7z9.101 item 3) or fix the claim |
| R-06-346 | Broadcast limiter naming drift (sender_iid vs /128) — align vector field names with post-migration spec? |
| R-06-341 | Spec §15.2 amendment this sweep resolves b7z9.87 — confirm closure |

## D. Cross-cutting observations for Opus

1. **Two spec amendments landed this sweep** (Step 0 decision enforcement:
   §15.2, §8.8). No other spec text was modified; all other spec findings are
   filed as beads, not edited (b7z9.101 holds the spec-text corrections).
2. **b7z9.35/b7z9.36 are partially stale** — tunnel-auth endpoints/egress gates
   and capability resources/table have landed since they were filed; the
   remaining trigger/consult/wiring gaps are re-filed as b7z9.97/b7z9.98.
   Recommend re-scoping those two beads to their residuals.
3. **Decisions now fully reflected in spec text:** epoch-never-wrap (§15.3 was
   already amended) and spec-15.2-key-storage + oscore-context-bound (amended
   this sweep). b7z9.86 and b7z9.87 drivers are resolved — closure candidates.
4. **§8.6 remains the only paragraph where implementations "diverge" in the
   stronger direction** (per-hop verify everywhere, no cache).
5. **Stale quarantine hygiene** (cosmetic, in b7z9.101): legacy fixture comments
   claim rejected-profile bytes while the fields hold upstream values.
