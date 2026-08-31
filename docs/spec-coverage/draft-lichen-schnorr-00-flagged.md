<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Flagged set — spec/drafts/draft-lichen-schnorr-00.md (sweep 2026-08-31)

Requirements flagged for Opus verification: low confidence, ambiguous/
divergent classification, or a documentation conflict needing a decision.
Gap beads filed for this section: **0** — every MUST is implemented and
vector-tested (see `docs/spec-coverage.md`, R-SCHORR rows).

---

## F-1. R-SCHORR-010 — constant-time MUST vs project threat model (low confidence)

- **Requirement (§5.3):** "Implementations MUST use constant-time operations
  for: Scalar multiplication, Signature comparison."
- **My classification:** implemented+untested.
- **Evidence:**
  - C: Monocypher constant-time primitives; comparisons via
    `crypto_verify16`/`crypto_verify32`
    (`lichen/subsys/lichen/link/schnorr48.c:169,201,210,501,538`).
  - Rust: `schnorr48` crate 0.1.0 built on curve25519-dalek + subtle
    (`rust/Cargo.lock:3243-3251`).
  - Python: plain `==` and frozenset membership
    (`python/src/lichen/crypto/schnorr48.py:44,160,193`) — not constant-time.
- **The conflict:** the repo threat model (AGENTS.md) says the radio
  adversary is the only adversary — "NO side-channel or timing requirements…
  Python: never flag constant-time comparisons". The draft's §5.3 MUST
  predates/outside that scoping.
- **Also:** the comment at `schnorr48.py:158-160` ("Uses constant-time
  comparison per spec §5.3 to prevent timing attacks") is factually wrong —
  the low-order check it labels is a frozenset lookup and the final challenge
  compare is `==`. Threat-model-wise this is harmless; comment-accuracy-wise
  it is misleading.
- **Question for Opus:** should the draft be amended to scope §5.3 per the
  project threat model (constant-time delegated to the vetted primitive
  libraries — Monocypher/dalek/subtle — with Python explicitly exempt), and
  should the inaccurate comment at schnorr48.py:158-160 be reworded to match
  reality (e.g. "rejection is value-based, not timing-sensitive, per the
  project threat model")?

## F-2. R-SCHORR-006/007 — spec silence on extra validation; cross-implementation acceptance sets differ on adversarial inputs

- **Requirement (§4.3):** verification is exactly: parse, recover R', re-hash,
  accept iff `e' == e_received`. The spec nowhere requires rejecting
  low-order public keys, non-canonical s, s == 0, or a zero challenge.
- **My classification:** implemented+tested (the spec equation), with
  undocumented extra rejections in all three implementations:
  - Python rejects: invalid point, low-order pubkey, e == 0, s == 0, s >= L
    (`schnorr48.py:152-178`).
  - C rejects: invalid point/low-order pubkey (`schnorr48_pubkey_valid`,
    `schnorr48.c:204-213`), s == 0 (`:169`), s >= L via
    `crypto_eddsa_recover_r` (`monocypher.c:2990-3010`) — but NOT e == 0.
  - Rust `schnorr48` crate: rejects low-order/identity pubkey, zero s,
    non-canonical s (tests `schnorr.rs:338-389`); e == 0 not special-cased.
- **Why it matters (theoretically):** a signature with e == 0 and a valid
  (s, pubkey) equation would be accepted by C and Rust but rejected by
  Python. Constructing one requires ~2^128 hash work, and honest signers can
  never emit one, so no interop failure is reachable in practice — but the
  acceptance sets are implementation-defined, not spec-defined.
- **Question for Opus:** should draft §4.3 (or a new §4.5) codify the
  mandatory validation rules (low-order/invalid pubkey, s == 0, s >= L, and
  whether e == 0 is rejected) so all implementations derive their rejection
  behavior from the spec rather than from defensive habit? The test corpus
  already contains vectors for all of these except "e == 0 with valid
  equation" (unconstructible).

## F-3. R-SCHORR-012 — C production code has no DAO-origin signature verifier (cross-reference, not a classification doubt)

- **Requirement (§5.5):** the DAO Origin Signature profile's 64-byte digest is
  signed/verified directly by Schnorr48.
- **My classification:** implemented+tested — for the Schnorr48 behavior
  itself, in all three languages (Python `dao_origin.py:396-401`, Rust
  `lichen-rpl/src/verify.rs:94` + `dao_origin_digest:127-143`, C independent
  oracle `test/vectors/dao_origin_signature_oracle.c`, shared vectors
  `test/vectors/dao_origin_signature.json` consumed by all three).
- **The gap I could not close:** inside `lichen/subsys/` (C production), the
  only DAO-origin-signature code is the standalone oracle under
  `test/vectors/`; `lichen/subsys/lichen/link/sos_origin.c` is the SOS Origin
  profile (`LICHEN-SOS-ORIGIN-v1` domain), not DAO. No C production RPL path
  verifies the DAO Origin Signature option.
- **Question for Opus:** confirm this belongs to the spec/08 (or 05-routing
  §8.6) coverage sweep rather than this one — the schnorr draft only binds
  Schnorr48 to not transform the digest, which C does correctly wherever it
  signs/verifies. If the C DAO-origin verifier is supposed to exist by now,
  it should be filed as a spec-08 gap bead, not here.

## F-4. R-SCHORR-015 — batch verification claimed by the draft, implemented nowhere (informational)

- **Requirement (§5.4, §6.5 item 3):** the scheme "supports batch
  verification"; "Implement batch verification when processing multiple
  signatures". No RFC 2119 keyword → no gap bead per sweep protocol.
- **My classification:** not-implemented (zero hits repo-wide).
- **Question for Opus:** is batch verification worth planning for the
  border-router/gateway verify path (many signatures per burst), or should
  §5.4 be downgraded to informative until a consumer exists? Note the
  curve25519-dalek backend does not expose a batch API, so implementing it
  would mean a new dependency or custom code — the latter violates the
  no-hand-rolled-crypto rule; flag before anyone tries.

## F-5. R-SCHORR-014 — corpus determinism note not literally exercised in C (minor)

- **Requirement:** `test/vectors/schnorr48.json` vector 16 note: "Test
  implementations MUST verify repeated sign() calls with same inputs yield
  this exact signature."
- **Evidence:** Python asserts sign→sign→canonical
  (`test_schnorr48.py:61-66`, `:82-90`) and Rust does the same
  (`schnorr48_vectors.rs:119-130`, `:143-176`). The C host test re-signs each
  valid vector once and compares to the canonical bytes
  (`main.c:334-377`) — equivalent for a deterministic algorithm, but it never
  literally calls sign twice on the same input.
- **Question for Opus:** is the single re-sign parity check sufficient to
  declare the corpus note satisfied for C, or should
  `lichen/tests/schnorr48/main.c` add a literal double-call assertion (one
  line, e.g. sign twice and memcmp)? I judge it sufficient (the signing path
  has no entropy source at all), but the corpus note says MUST.
