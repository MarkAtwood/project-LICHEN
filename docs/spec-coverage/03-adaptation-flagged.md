## spec/03-adaptation.md — flagged for Opus verification (sweep 2026-09-01)

Criteria: low confidence, ambiguous/divergent classification, or section 06 /
oscore-EDHOC semantics. 11 entries.

---

### F1 — R-03-079: Rule 255 RX decode is byte-preserving (structure + checksums only)
- **Classification:** divergent (Rust + C); Python conformant.
- **Evidence:** Decision `rule255-rx-decode` (decisions.jsonl, 2026-08-31, FINAL):
  "decode accepts any well-framed packet with valid checksum regardless of
  endpoint addresses. Address validation is TX-only." Python
  `validate_full_ipv6` (headers.py:152-180) + `decode_rule255` (233-244) match.
  Rust `validate_full_ipv6_structure` (rust/lichen-schc/src/codec.rs:285-297,
  reached from `decode_rule255` codec.rs:1562) rejects unspecified/multicast
  source + unspecified destination on RX; its own docstring (codec.rs:265-270)
  claims byte-preserving. C `validate_ipv6_transport_lengths`
  (lichen/subsys/lichen/schc/schc_helpers.c) does the same via the
  `validate_payload` hook (schc.c:525). Stale vectors:
  `rule255_rx_structural_reject` in test/vectors/schc_adaptation.json + both
  consumers (rust adaptation_vectors.rs:1109, python test_vectors.py:4874 — the
  Python consumer contradicts its own byte-preserving library; suite currently
  dormant, jsonschema missing from python/.venv). Spec 5.7 paragraph restored to
  byte-preserving wording this sweep. Bead b7z9.66 (discovered-from l9jj).
- **Question for Opus:** Confirm the spec edit correctly captures the decision's
  intent (fully byte-preserving RX, emission policy TX-only), and that the right
  remediation is to strip the RX structural address checks from Rust and C and
  rewrite the three vectors — not the other direction (re-adding RX checks to
  Python, which would contradict the recorded decision and the
  `validate_datagram_source_policy` TX-gate design).

### F2 — R-03-063: tombstone/admission-floor tables <=256 per direction + evict-oldest on overflow
- **Classification:** ambiguous.
- **Evidence:** Rust bounds tombstones to 2 per direction per signer entry
  (fragment.rs:196-197) with time-based expiry (1220-1247); Python bounds are 64
  sender records / 128 rejection tombstones / 16 pending-ACK receipts
  (fragment.py:46-48) removed by hold-down expiry. Both satisfy "at most 256";
  neither implements an overflow -> evict-oldest-by-terminal-time policy (they
  fail closed or expire by time instead).
- **Question for Opus:** Is the evict-oldest clause conditioned on the 256-entry
  bound (making it vacuous for implementations bounded far below 256), or does it
  prescribe the overflow policy for whatever table an implementation actually
  has (making fail-closed a divergence that needs a bead + spec wording fix)?

### F3 — R-03-062: counter 0xffffff cannot be reused or wrapped under the same key
- **Classification:** implemented+tested (Python); low confidence (Rust).
- **Evidence:** Python: MAX_LINK_REPLAY_COUNTER=0xFF_FFFF (fragment.py:43),
  explicit fail-closed (session_manager.py:513-514), test 1039. Rust: contract
  documented at rust/lichen-link/src/seqnum.rs:121-124 ("Epoch 255 / seqnum
  65535 is 0xFFFFFF, the last valid tuple before link-key rotation. Epoch MUST
  NOT wrap 255 -> 0") + logical_counter test (seqnum.rs:176), but no explicit
  exhaust guard was found in lichen-schc or the link epoch allocation path;
  node only requires boot epoch >= 128 (stack.rs:236-245).
- **Question for Opus:** Verify the Rust epoch allocation actually refuses to
  increment past epoch 255 (or otherwise guarantees 0xFFFFFF is never reissued
  under the same key); if not, that is a MUST gap needing a bead.

### F4 — R-03-069: non-root serializer MUST require the authenticated root-originated DODAG version as input and preserve it byte-for-byte
- **Classification:** implemented+tested, low confidence on architectural
  equivalence.
- **Evidence:** Rust production builder emits the local current() option
  (router.rs:882 -> message.rs:217-218), which equals the DODAG version only
  because admission permits v3 exclusively; the root-signed proof travels in the
  separate 0x16 DODAG Version Authorization option (router.rs:843-857,
  message.rs:255-259). Python appends (0x13, RULE_SET_VERSION) when the caller
  supplies none (messages.py:338-339). No vector exercises root-version !=
  local-version.
- **Question for Opus:** Does admission-gating (root version can only ever be 3)
  satisfy "MUST require the authenticated root-originated version as input and
  preserve byte-for-byte", or should the non-root DIO builder take the
  authenticated version as an explicit input so a future v4 root is propagated
  byte-for-byte rather than silently re-stamped as 3?

### F5 — R-03-065 / R-03-088: "Version number MUST increment on any rule change"
- **Classification:** implemented+untested (process-level).
- **Evidence:** RULE_SET_VERSION=3 constants with history comments in all three
  implementations (rules.rs:19-26, rules.py:185-189, rpl_messages.h:85); the
  only pin is the descriptor-hash fingerprint vector
  rule_set_v3_registry_fingerprint (rule_versioning.json), which detects
  registry drift but cannot enforce a version bump.
- **Question for Opus:** Is a vector fingerprint + release-process convention an
  acceptable realization of this MUST, or should a CI check assert
  fingerprint-change implies RULE_SET_VERSION bump?

### F6 — R-03-006: Python rules 64/65/66 MUST be rejected as unknown packet Rule IDs
- **Classification:** implemented+tested (indirect only).
- **Evidence:** Registry exclusion asserted (test_codec.py:349-353 asserts 64/65/66
  not in RULES; rust rules.rs:566 asserts 64..=66 absent from V3 registry);
  unknown-ID rejection paths exist (context.py:129-131, headers.py:944-967,
  codec.rs:2396). No test in any implementation feeds 64/65/66 literally as the
  first byte of a SCHC packet.
- **Question for Opus:** Should a dedicated negative vector (Rule ID 64/65/66 on
  the wire) be added to schc_adaptation.json, or is registry-exclusion +
  generic unknown-ID coverage sufficient?

### F7 — R-03-064: fragmentation is hop-by-hop; routers reassemble and decompress before IPv6 forwarding
- **Classification:** divergent.
- **Evidence:** Python node.py:902-1059 reassembles then routes/forwards (no
  dedicated multi-hop test). Rust decompress-before-forward is wired
  (node.rs:497-501, routing/router.rs:379, gateway.rs:1248-1281) but the RX
  reassembly seam is explicitly unwired (stack.rs:225-229) — tracked as bead
  project-LICHEN-worker6-b7z9.5.2 (+ .5.2.2).
- **Question for Opus:** Confirm b7z9.5.2 fully covers the spec sentence (i.e.,
  once wired, Rust satisfies "routers reassemble ... before forwarding"), and
  whether a cross-implementation multi-hop fragment-forwarding vector/test
  should be mandated.

### F8 — R-03-013: Rule 4 does not match ULA/Yggdrasil/routable source addresses
- **Classification:** implemented+tested, low confidence.
- **Evidence:** Authoritative whole-packet codec enforces link-local-both in both
  languages (rust codec.rs:2339; python headers.py:694). Two soft spots: (a)
  Rust generic `RplDaoProfile::matches` (headers.rs:893) uses `is_routable` and
  would match routable sources — non-authoritative (SchcContext selection only)
  but a latent foot-gun; (b) no dedicated ULA (fd00::/8) or Yggdrasil
  (0200::/8)-source DAO non-match vector exists in either language; Python's
  `_is_ula`/`_is_routable` helpers (headers.py:254-259) are uncalled and
  untested.
- **Question for Opus:** Should the Rust RplDaoProfile be tightened to
  link-local-only for hygiene, and should a ULA-source DAO -> Rule 255 vector be
  added?

### F9 — R-03-045: 5.6 encoded-size clause contradicts 5.7 raw-packet ceiling
- **Classification:** divergent (spec-internal); all three implementations
  follow 5.7.
- **Evidence:** 5.6: "a compressible raw IPv6 packet may be larger when its
  final encoded SCHC Packet remains at most 22,554 bytes". 5.7: raw bound in
  both directions, "MUST NOT substitute the encoded size for the raw size".
  Implementations enforcing 5.7: python headers.py:889-900 +
  test_headers_rules.py:96-120; rust codec.rs:2253-2260 + test 2799; C
  schc_compress.c gates + schc_rule2_compress main.c:147-152. Bead b7z9.68.
- **Question for Opus:** Confirm the fix direction: delete/rewrite the 5.6
  clause to the raw-bound reading (rather than weakening 5.7).

### F10 — R-03-083: Rule 255 gives no fragmentation compatibility on version mismatch
- **Classification:** divergent (open bead).
- **Evidence:** Spec: >1 frame + version mismatch => packet cannot be sent.
  Vectors fragmentation-requires-match + rust
  rule_versioning_vectors.rs:111 cover the admission side; python
  test_fragment.py:2157 covers the reassembly-limit side. Known open bug:
  `compress_schc_for_peer` allow_fragmentation ignored on version-mismatch Rule
  255 — bead project-LICHEN-worker6-z4m8.
- **Question for Opus:** Confirm z4m8 is the complete residual for this
  requirement across all three implementations (C path not separately audited).

### F11 — R-03-005/R-03-074/R-03-081: C (Zephyr) coverage depth on Rule 255 structure validation
- **Classification:** implemented+untested (C half of the structural/RH3
  validation).
- **Evidence:** C implements the chain walk, RH3-only policy, fragment-header
  reject, exact UDP length + checksum with SRH upper-destination
  (validate_ipv6_header_chain / validate_ipv6_transport_lengths in
  lichen/subsys/lichen/schc/schc_helpers.c). C test suites (schc, schc_parity,
  schc_generic) exercise round-trips and ceilings; whether the malformed RH3 /
  dual-defect vectors from schc_compression.json reach the C validators via
  gen_vectors.py was not confirmed.
- **Question for Opus:** Verify whether schc_parity's generated vector set
  includes the malformed/rh3 categories; if not, recommend wiring
  rule255_rx_* malformed vectors into a C test so the C structural validators
  are vector-covered like Rust/Python.
