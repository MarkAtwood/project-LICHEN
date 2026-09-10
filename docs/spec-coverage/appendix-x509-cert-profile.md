## spec/appendix-x509-cert-profile.md — coverage (sweep 2026-09-09)

Step 0 note: no `spec/decisions.jsonl` decision lists this file in `specs`, so no
`verify.grep` checks apply. The appendix *encodes* the settled
`upstream-yggdrasil-addressing` decision (SAN = `AddrForKey`, `0200::/8`, IID not
embedded); its §4 worked encoding was verified against the pinned upstream oracle
(`test/vectors/reference_schnorr48.py:51 addr_for_key` → `020ffd fcfb faf9 f8f7
f6f5 f4f3 f2f1 f0`, byte-identical to the spec DER) — no spec fix required.
Cross-reference regression found: 06-security.md:1162-1164 (Key Binding check 3,
"SAN /128 IID == kid") contradicts this appendix §8 step 4 and the settled
decision → bead project-LICHEN-worker6-bedw.21 (filed from this sweep).

The whole X.509 attestation profile is unimplemented in all three stacks
(Python/Rust/C/Zephyr). The only X.509 code anywhere is the Python CA
*trust-anchor* store (`python/src/lichen/crypto/trust_anchors.py`), which parses
CA certs for key-pinning and explicitly defers chain validation. The
`AddrForKey` derivation primitive needed by §8 step 4 is implemented+tested in
all three stacks (pinned upstream oracle `test/vectors/yggdrasil_address.json`).
The 06-security sweep (R-06-331/333/348/349/350) already classified the x5chain
credential path as not-implemented; this sweep covers the certificate-profile
appendix itself. Gap beads filed under epic `project-LICHEN-worker6-bedw`
(COSE: Node Credentials, spec 8.13).

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-X509-001 | End-entity (leaf) cert in `x5chain` MUST conform to this profile (preamble) | not-implemented | No x5chain parsing or cert handling in any stack; grep: `x509/x5chain` hits only spec + docs/ca-lichen-tech-design.md. 06 sweep R-06-350 same verdict. Tracked: project-LICHEN-worker6-bedw.17 | high |
| R-X509-002 | CA MUST verify proof of possession before issuing (preamble) | not-implemented | No CA issuance tooling in repo; .lichen.tech CA is design-only (docs/ca-lichen-tech-design.md:6-16). Tracked: bedw.16 | high |
| R-X509-003 | PKCS#10: CA MUST verify self-signature over DER `certificationRequestInfo` with subject pubkey (preamble) | not-implemented | No CSR code anywhere (grep `pkcs10|CSR|certificationRequestInfo`: spec only). Tracked: bedw.16 | high |
| R-X509-004 | CA MUST reject request whose signature does not verify (preamble) | not-implemented | Same as R-X509-003. Tracked: bedw.16 | high |
| R-X509-005 | CA MUST NOT issue for a subject key whose PoP is unverified (preamble) | not-implemented | Same as R-X509-002. Tracked: bedw.16 | high |
| R-X509-006 | Cert MUST NOT include CRL Distribution Points, AIA, or OCSP no-check markers (§1) | not-implemented | No cert encoder/validator exists to enforce or violate this. Tracked: bedw.17 | high |
| R-X509-007 | Constrained verifiers MUST NOT be required to process CRL DP/AIA/OCSP (§1) | not-implemented | No verifier exists. Tracked: bedw.17 | high |
| R-X509-008 | extendedKeyUsage absent by default; `id-kp-clientAuth` if present (§1 table) | not-implemented | No cert code. Tracked: bedw.17 | high |
| R-X509-009 | SPKI MUST be Ed25519: id-Ed25519 1.3.101.112, params absent, 32-byte raw (§2) | not-implemented (leaf side) | No leaf-cert parser. Partial adjacent evidence: CA *anchor* certs already require Ed25519 subject keys — python/src/lichen/crypto/trust_anchors.py:104-105 (see R-X509-047 divergence). Tracked: bedw.17 | high |
| R-X509-010 | Cert subject key MUST be the node identity key from which addresses derive (§2) | not-implemented | No x5chain/leaf handling; consumer of bedw.8 x5chain parsing (06 sweep R-06-348 four Key Binding checks also unimplemented). Tracked: bedw.17 | high |
| R-X509-011 | Subject field SHOULD be empty (§3) | not-implemented (SHOULD — matrix note only) | No cert issuance code | high |
| R-X509-012 | If subject present it MUST be a single `serialNumber` attribute (13-char Crockford B32 short addr or 16-char uppercase hex IID) (§3) | not-implemented | No cert issuance code. Tracked (grouped): bedw.18 | high |
| R-X509-013 | Issuer DN MUST contain `CN` (§3) | not-implemented | No cert issuance code. Tracked: bedw.18 | high |
| R-X509-014 | Issuer DN SHOULD contain `O` (§3) | not-implemented (SHOULD — matrix note only) | No cert issuance code | high |
| R-X509-015 | Verifiers MUST NOT match on issuer DN for authorization; chain validation to anchor is the only issuer-based decision (§3) | not-implemented | No verifier exists; closest authz surfaces are trust-level labels only (rust/lichen-link/src/trust.rs:47, rust/lichen-gateway/src/trust.rs:111, lichen/subsys/lichen/gcp/include/lichen/gcp_trust.h:79). Tracked: bedw.12 | high |
| R-X509-016 | subjectAltName MUST be present (§4) | not-implemented | No SAN parsing in any stack (grep `subjectAltName|SAN`: spec only). Tracked: bedw.11 | high |
| R-X509-017 | SAN critical iff subject empty, non-critical otherwise (§4) | not-implemented | No SAN parsing. Tracked: bedw.11 | high |
| R-X509-018 | SAN MUST contain exactly one iPAddress `[7]` = 16-byte `0200::/8` /128 == `AddrForKey(subjectPublicKey)` (§4) | not-implemented (binding absent; primitive exists+tested) | No SAN/leaf code. Derivation primitive implemented+tested in all 3 stacks: rust/lichen-core/src/addr.rs:113 `ygg_addr_from_pubkey`, python/src/lichen/crypto/identity.py:209 `yggdrasil_address`, lichen/subsys/lichen/link/identity_addr.c:75; pinned oracle test/vectors/yggdrasil_address.json (`upstream_addr_for_key`). Tracked: bedw.11 | high |
| R-X509-019 | A second native `0200::/8` iPAddress MUST NOT appear (§4) | not-implemented | No SAN parsing. Tracked: bedw.11 | high |
| R-X509-020 | dNSName, rfc822Name, URI GeneralNames MUST NOT be used (§4) | not-implemented | No SAN parsing. Tracked: bedw.11 | high |
| R-X509-021 | Link-local `fe80::/10` with node IID MAY be included as one additional iPAddress (§4) | not-implemented (MAY — matrix note only) | No SAN parsing | high |
| R-X509-022 | Verifiers MUST ignore any iPAddress other than the single native entry (§4) | not-implemented | No SAN parsing / verifier. Tracked: bedw.11 | high |
| R-X509-023 | Mesh role extension MUST NOT be critical (§5) | not-implemented | Zero hits for mesh-role OID/UUID outside spec (grep `2.25.116347725289407359125616919235271862817|5787c1be|x509-mesh-role`). Tracked: bedw.14 | high |
| R-X509-024 | Unspecified role bits MUST be zero (§5) | not-implemented | No codec. Tracked: bedw.14 | high |
| R-X509-025 | Extension MUST be omitted (not empty BIT STRING) for a no-role cert (§5) | not-implemented | No codec. Tracked: bedw.14 | high |
| R-X509-026 | Empty BIT STRING if present → verifiers MUST treat as unasserted (§5) | not-implemented | No verifier. Tracked: bedw.14 | high |
| R-X509-027 | Verifiers not implementing the extension MUST ignore it (non-critical, RFC 5280 §4.2) (§5) | not-implemented | No verifier. Tracked: bedw.14 | high |
| R-X509-028 | Authorization MUST NOT treat absence as "leaf"; absence means "unasserted" (§5) | not-implemented | No role authorization exists (§8.13.1 `lichen:relay` local facts are python-side only, python/src/lichen/gateway/local_facts.py). Tracked: bedw.14 | high |
| R-X509-029 | `notBefore` MUST be truncated to 00:00:00 UTC of issuance day (§6) | not-implemented | No issuance code. Tracked: bedw.18 | high |
| R-X509-030 | `notAfter` MUST be finite (§6) | not-implemented | No issuance code. Tracked: bedw.18 | high |
| R-X509-031 | Validity longer than 825 days MUST NOT be issued (§6) | not-implemented | No issuance code. Tracked: bedw.18 | high |
| R-X509-032 | RECOMMENDED validity 200 days from notBefore (§6) | not-implemented (RECOMMENDED — matrix note only) | No issuance code | high |
| R-X509-033 | Freshness ordering: presented chain replaces cached only if leaf notBefore strictly later AND cached chain within validity window (§6) | not-implemented | No chain cache exists in any stack. Tracked: bedw.13 | high |
| R-X509-034 | Expired cached chain MUST be discarded and no longer suppresses replacement (§6) | not-implemented | No chain cache. Tracked: bedw.13 | high |
| R-X509-035 | Chain whose leaf is not newer MUST NOT displace a still-valid cached chain (§6) | not-implemented | No chain cache. Tracked: bedw.13 | high |
| R-X509-036 | Cached entry with future leaf notBefore MUST NOT suppress currently-valid presented chain (§6) | not-implemented | No chain cache. Tracked: bedw.13 | high |
| R-X509-037 | Same-day replacement MUST wait for next UTC day or use fresher out-of-band channel; accept-on-tie not permitted (§6) | not-implemented | Deployment/CA-op rule; no CA tooling. Tracked: bedw.18 | high |
| R-X509-038 | Chain outside validity window MUST NOT be honored and MUST NOT displace a valid cached chain (§6) | not-implemented | No chain cache / window checks. Tracked: bedw.13 | high |
| R-X509-039 | Verifier MUST NOT honor a cached chain whose leaf has expired (§6) | not-implemented | No chain cache. Tracked: bedw.13 | high |
| R-X509-040 | Freshness floor (greatest leaf notBefore ever cached per subject key) gates displacement; MUST NOT displace unless strictly later than floor (§6) | not-implemented | No floor anywhere. Tracked: bedw.13 | high |
| R-X509-041 | Floor SHOULD persist across restarts (§6) | not-implemented (SHOULD — noted in bead) | No floor; persistence analog exists (gateway trust-store MAC, rust/lichen-gateway/src/trust.rs:90-95). Tracked: bedw.13 | high |
| R-X509-042 | Floor entry MAY be discarded once every chain it could gate is expired (floor + 825d) (§6) | not-implemented (MAY — matrix note only) | No floor | high |
| R-X509-043 | Expired chain body MAY be dropped once floor recorded; current still-valid chain MUST NOT be dropped (§6) | not-implemented | No chain cache. Tracked: bedw.13 | high |
| R-X509-044 | Compromised key MUST be retired out-of-band (supersession cannot revoke a key) (§6) | not-implemented | Operational rule; no CA/verifier machinery exists. Tracked: bedw.18 | high |
| R-X509-045 | Signature alg MUST be SHA-256-class or stronger or `id-Ed25519`; MD5/SHA-1 MUST NOT be used (§7) | not-implemented | No cert signature handling. Tracked: bedw.17 | high |
| R-X509-046 | `tbsCertificate.signature` MUST equal outer `signatureAlgorithm` (§7) | not-implemented | No cert parsing. Tracked: bedw.17 | high |
| R-X509-047 | CA key need not be Ed25519; only subject SPKI is constrained (§7) | divergent | Only X.509 code rejects non-Ed25519 CA keys: python/src/lichen/crypto/trust_anchors.py:104-105 raises unless subject key is Ed25519PublicKey, so a conforming ECDSA CA cert cannot be an x509 anchor. Also no `keyUsage keyCertSign` check on CA anchors (profile preamble expects ordinary RFC 5280 CAs). Needs scope decision. Tracked: bedw.20 | low |
| R-X509-048 | Chain validation per RFC 5280 to a configured trust anchor (§8 step 1) | not-implemented (partial anchor-side primitive) | Python anchor store parses DER CA certs for key-pinning: python/src/lichen/crypto/trust_anchors.py:77-111 (`pubkey_from_der_cert`), tested in python/tests/coap/test_trust_anchors_resource.py (`test_x509_anchor_pubkey_extracted_from_cert`:216, `test_x509_anchor_rejects_key_mismatch`:224, `test_raw_anchor_kind_flips_to_x509_on_cross_signed_cert`:189, `test_post_x509_anchor`:407) — but docstring explicitly defers chain validation (and cites stale bead `viku.6`, which no longer exists). No path building/signature/validity processing anywhere. Tracked: bedw.12 | low |
| R-X509-049 | Validity-window check + Section 6 freshness-floor-gated displacement (§8 step 2) | not-implemented | Same absence as R-X509-033/040. Tracked: bedw.13 | high |
| R-X509-050 | Check `basicConstraints` CA=false and `keyUsage` digitalSignature on each end-entity cert (§8 step 3; §1 table rows 44-45) | not-implemented | No leaf validation. Adjacent: anchor store checks the *inverse* (CA certs must have basicConstraints CA=true, trust_anchors.py:98-102). Tracked: bedw.12 | high |
| R-X509-051 | Address binding: recompute `AddrForKey(subjectPublicKey)`; SAN exactly-one native `0200::/8` == recomputed byte-for-byte; reject zero/multiple/mismatch; SHA-512 IID MUST NOT be substituted (§8 step 4) | not-implemented (cert-side; derivation primitive implemented+tested) | Binding check absent everywhere. Primitive implemented+tested: rust/lichen-core/src/addr.rs:113, python/src/lichen/crypto/identity.py:209, lichen/subsys/lichen/link/identity_addr.c:75; oracle test/vectors/yggdrasil_address.json. Spec worked example (§4, key `000102…1f` → `020f:fdfc:…:f1f0`) re-verified against pinned oracle this sweep — matches. Tracked: bedw.11 | high |
| R-X509-052 | Role-based authorization reads mesh role ext; when asserted, check passes without contacting gateway (§8 step 5) | not-implemented | No role extension, no credential verifier. Tracked: bedw.15 | high |
| R-X509-053 | ≤1 cached chain per subject key; if cached valid and leaf notBefore ≥ presented, MUST base decisions on cached and MUST NOT honor presented (§8 step 6) | not-implemented | No chain cache. Tracked: bedw.13 | high |
| R-X509-054 | Role ext honored ONLY from chains to a trust anchor configured as role-granting authority; other anchors MUST NOT be read as asserting any role (§8 role-assertion trust scope) | not-implemented | No role/anchor-authorization config. Tracked: bedw.15 | high |
| R-X509-055 | Certificate version MUST be v3 (`2`) (§1 table) | not-implemented | No cert code. Tracked: bedw.17 | high |

### Notes

- **Worked encodings verified this sweep** (independent oracle, not
  implementation-derived): §4 SAN DER `87 10 02 0F FD FC … F1 F0` reproduces
  exactly from the pinned upstream `AddrForKey` oracle
  (`test/vectors/reference_schnorr48.py:51`, anchored by
  `test/vectors/yggdrasil_address.json`) for subject key
  `000102…1f`. §5 role-extnValue DER table is internally consistent
  (BIT STRING named bits 0x80/0x40/0x20, correct unused-bit counts).
- **Section 9 promise**: "Test vectors … will live in `test/vectors/`" —
  no X.509 corpus exists yet → bead project-LICHEN-worker6-bedw.19.
- **Partial evidence boundary**: the Python `TrustAnchorStore`
  (x509-kind anchors, key-pinning) is the trust-anchor substrate for
  06-security §8.13, not a leaf-profile implementation; `TrustLevel::Pkix`
  in Rust (lichen-link:47, lichen-gateway:111) and C (gcp_trust.h:79) are
  wire labels only. Both are cited as *adjacent* evidence, not conformance.
- **Cross-reference regression (filed, not a section gap)**:
  06-security.md:1162-1164 Key Binding check 3 ("SAN native /128 has an IID
  equal to that same kid") contradicts this appendix §4/§8 step 4 and the
  settled `upstream-yggdrasil-addressing` decision →
  project-LICHEN-worker6-bedw.21.

### Gap beads (10 filed; all 49 MUST-level gaps mapped, overflow: 0 individually unfiled)

Grouped beads (related MUSTs share an implementation site):

| Bead | Requirements covered | Priority |
|------|----------------------|----------|
| project-LICHEN-worker6-bedw.11 | R-X509-016, 017, 018, 019, 020, 022, 051 (SAN + address binding, verifier step 4) | 1 |
| project-LICHEN-worker6-bedw.12 | R-X509-048, 049 (chain validation, §8 steps 1-2), 050, 015 | 1 |
| project-LICHEN-worker6-bedw.13 | R-X509-033, 034, 035, 036, 038, 039, 040, 043, 053 (+ 041 SHOULD) | 2 |
| project-LICHEN-worker6-bedw.14 | R-X509-023, 024, 025, 026, 027, 028 | 2 |
| project-LICHEN-worker6-bedw.15 | R-X509-052, 054 | 2 |
| project-LICHEN-worker6-bedw.16 | R-X509-002, 003, 004, 005 | 2 |
| project-LICHEN-worker6-bedw.17 | R-X509-001, 006, 007, 008, 009, 010, 045, 046, 055 | 2 |
| project-LICHEN-worker6-bedw.18 | R-X509-011 (SHOULD), 012, 013, 014 (SHOULD), 029, 030, 031, 032 (RECOMMENDED), 037, 044 | 3 |
| project-LICHEN-worker6-bedw.19 | §9 vectors promise + §4/§5 worked-encoding pins | 2 |
| project-LICHEN-worker6-bedw.20 | R-X509-047 (divergent) | 2 |

Plus one discovered cross-reference spec bug (not one of the 10 section gap
beads): project-LICHEN-worker6-bedw.21 (06-security.md Key Binding check 3
IID-in-address regression).

MAYs (never filed per protocol): R-X509-021, R-X509-042. SHOULD/RECOMMENDED
without a documented feature break: R-X509-011, R-X509-014, R-X509-032
(noted in matrix; R-X509-041 noted inside bedw.13).

### Classification histogram

- implemented+tested: 0
- implemented+untested: 0
- divergent: 1 (R-X509-047)
- not-implemented: 54 (of which 6 are MAY/SHOULD/RECOMMENDED rows: R-X509-011, 014, 021, 032, 041, 042)
- ambiguous: 0
- Total: 55 requirements; 49 MUST-level gaps → 10 grouped gap beads
