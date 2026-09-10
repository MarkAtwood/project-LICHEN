# spec/10-implementation.md — flagged set (sweep 2026-09-09)

Items where confidence was low, classification was ambiguous/divergent, or the
content needs a second opinion. None of these are oscore/EDHOC semantics.

## F-1. R-10-004 — I-D table divergent: 3/9 drafts exist, wrong directory

- **Requirement:** §16.6 lists nine `draft-lichen-*` documents (link, schc, addr,
  rpl, security, lci, senml, apps, border) as the project's IETF-style documents.
- **Classification:** divergent (descriptive deliverables table, no RFC2119 keyword).
- **Evidence:** `spec/drafts/` contains only `draft-lichen-link-01.md`,
  `draft-lichen-schc-lora-00.md`, `draft-lichen-rpl-lora-00.md`, plus two unlisted
  drafts (`draft-lichen-schnorr-00.md`, `draft-lichen-ota-00.md`). §16.1's tree puts
  drafts at `docs/draft-lichen-*.md`; `docs/` contains none.
- **Question for Opus:** amend §16.6 (and §16.1's path) to the actual `spec/drafts/`
  inventory, or treat the six missing I-Ds as pending deliverables that need beads?

## F-2. R-10-011/013/015/016/017/018 — entire logfmt convention unimplemented in all three stacks

- **Requirement:** §16.8 MUST: logfmt baseline (key=value, quoted strings) with
  `ts`/`level`/`layer`/`event` on every line and per-implementation notes
  (C: LOG_* + `CONFIG_LICHEN_DIAG_VERBOSE`; Rust: tracing + `info_span!`, defmt
  logfmt conventions; Python: structlog bound loggers).
- **Classification:** not-implemented/divergent in **all three stacks**. Zero
  implementation matches for `logfmt`, `layer=`, `event=`, `info_span`,
  `CONFIG_LICHEN_DIAG_VERBOSE`. Current state: Rust gateway/cli default
  `tracing_subscriber::fmt()` (lichend.rs:49, cli/main.rs:151); C freeform LOG_*
  (coap_msg.c:433); Python stdlib logging with pkt_id interpolated into prose
  (node.py:104, 915).
- **Question for Opus:** is the logfmt convention (spec 16.8, added deliberately)
  still the intended baseline, or has the three-way drift (tracing / LOG_* /
  stdlib+structlog-in-sim-only) become de facto and the spec should be amended?
  If logfmt stands: should Rust adopt a logfmt formatter, Python move the packet
  path onto structlog, and C get a field-format convention + the missing
  `CONFIG_LICHEN_DIAG_VERBOSE` Kconfig symbol? Gap bead filed for the MUST parts.

## F-3. R-10-014/019/021 — pkt_id correlation: Python-only

- **Requirement:** §16.8.1/16.8.3: pkt_id on all packet-path lines; monotonic
  wrapping u32 assigned at link RX entry and TX queue push; forwarded packets get
  a new pkt_id with `event=forward in_pkt_id=<rx> pkt_id=<tx>` logged.
- **Classification:** divergent — Python implements the mechanism
  (link_layer.py:1551-1554, 1701/1730; tx_queue.py:258-296, 412; forward logs
  node.py:1104/1163, though not the exact spec format). Rust: zero `pkt_id`
  matches in rust/. C: zero matches in lichen/.
- **Question for Opus:** confirm the Python model is the intended reference
  (shared node-wide counter, RX-entry + TX-push assignment, local-only) so the
  Rust/C gap bead has a concrete target, and confirm whether the exact
  `event=forward in_pkt_id=<rx> pkt_id=<tx>` format is required or Python's
  `in_pkt_id=%d` prose suffices.

## F-4. R-10-007/008 — C RX-side DAO floor persistence divergent; prior coverage pointer now stale

- **Requirement:** §16.7: RX stores only pubkey + accepted high-water sequence +
  digest; persist the RX floor before exposing the route or returning success.
- **Classification:** divergent (C). Rust conforms (routing.rs:710-731, test
  `unavailable_replay_storage_leaves_dao_state_unchanged` dao_origin_vectors.rs:262-310);
  Python conforms (dao_manager.py:1103-1145 persist-before-apply; RX catalog in
  dao_persistence.py). C: `rg "rx_floor|dao_rx|origin_high_water"` over
  lichen/subsys/lichen/rpl/ → 0 hits; RX floor is volatile (rpl_dao_process.c),
  only TX state is NV (rpl_dao_tx_persist.c).
- **Complication:** docs/spec-coverage/06-security-part1.md (R-06-010) said this was
  "covered by existing bead project-LICHEN-worker6-b7z9.11", but that bead has since
  CLOSED with a close reason that verifies the **TX** machinery only (reserve/finalize,
  two-slot, suites green). The RX-side gap appears untracked.
- **Question for Opus:** confirm C genuinely lacks RX-floor NV persistence (my grep
  says yes) and that the closed b7z9.11 scope does not subsume it; if confirmed, the
  new bead `[spec-gap][R-10-007]` should be worked rather than assumed covered.

## F-5. R-10-010 — C tests do not (visibly) snapshot state around rejected DAOs

- **Requirement:** §16.7 MUST: snapshot complete route, replay-floor, and storage
  state around rejected DAOs to prove no partial mutation.
- **Classification:** implemented+tested in Rust (storage/route snapshots across the
  52-vector rejection matrix, dao_origin_vectors.rs:200-258) and substantively in
  Python (dao_manager.py:941 + test_dao_origin.py); **C unverified** — rpl_dao_auth /
  rpl_routing host suites assert accept/reject outcomes; I could not locate
  route+storage snapshot assertions around rejected DAOs.
- **Question for Opus:** does any C host test assert state-snapshot equality around
  rejected DAOs? If not, is that a C-test gap to fold into the R-10-007 bead or a
  separate bead?

## F-6. §16.5 dependency table drift (descriptive, low risk)

- **Observation:** the spec's crate/library tables no longer match the build:
  ed25519-dalek unused (curve25519-dalek + in-repo schnorr48 crate),
  aes-gcm absent from Cargo.lock (OSCORE via oscore-fork), coap-lite unused
  (hand-rolled lichen-coap), smoltcp explicitly rejected
  (lichen-ipv6/Cargo.toml:12), libschc evaluated-and-rejected
  (RECONCILIATION.md c0b, 2026-06-30). heapless and monocypher claims are accurate.
- **Question for Opus:** amend §16.5 tables to the real dependency set, or keep as
  historical intent? (All actual deps remain GPL-3.0-compatible, so R-10-003 holds.)

## F-7. §16.1 repository tree drift (descriptive)

- **Observation:** actual tree diverges from the §16.1 code block: Zephyr module is
  `lichen/` with `subsys/lichen/<name>` dirs (not `zephyr/subsys/lichen_link/...`);
  no `riot/`; `test/` has only `vectors/`; `tools/wireshark/` not
  `wireshark-dissector/`; no lichen-craft/, lichen-keygen/, lichen-web/;
  app binaries under rust/ not apps/; samples/ has only lora_ping.
- **Question for Opus:** is this tree meant to be aspirational (keep) or should the
  spec block be regenerated from the actual layout? (Prior sweeps treated the tree
  as documentation; no MUST is involved.)

## F-8. Stale `bd show` tracking references (descriptive)

- **Observation:** §16.2 and §16.3 reference `bd show python-wdr`, `python-dqc`,
  `python-ypk`, `python-oae` — all four return "no issue found" (checked 2026-09-09).
- **Question for Opus:** pure spec hygiene — remove the four references or repoint
  them at live beads. No code impact.

## F-9. R-10-005 — Python TX record lacks explicit pubkey binding (sub-detail)

- **Requirement:** §16.7: TX stores the public-key identity alongside the reserved
  Origin Sequence and complete signed DAO bytes.
- **Classification:** implemented+tested overall (Rust `DaoTxState.public_key` +
  KeyMismatch error, persistence.rs:139-147/119; C payload layout `[0..32) public key`,
  rpl_dao_tx_persist.h:10-17; tests green). Python `TxState` is `(sequence, dao_bytes)`
  only (dao_persistence.py:73-78); the pubkey binding is indirect — restore-time
  validation of the restored DAO's origin against `origin_identity.pubkey`
  (dao_manager.py:382).
- **Question for Opus:** is Python's indirect binding acceptable conformance for
  "stores the public-key identity", or should the Python TX slot record the pubkey
  explicitly (matching Rust/C `KeyMismatch` fail-closed on key rotation)?
