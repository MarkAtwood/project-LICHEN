# appendix-x509-cert-profile — flagged for Opus verification

Sweep: 2026-09-09. Flag rule: low confidence, ambiguous/divergent
classification, or (n/a — this is not 06-security nor oscore/EDHOC).
Two requirements flagged + one cross-reference discovery.

## F1 — R-X509-047: CA key algorithm freedom (§7)

- **Requirement**: "The CA's key is not the node's identity key and need not
  be an Ed25519 key; only the subject SPKI is constrained (Section 2)."
  Signature algorithm MUST be SHA-256-class or stronger or `id-Ed25519`.
- **Classification**: divergent (confidence: low)
- **Evidence**: The only X.509-accepting code in the repo,
  `python/src/lichen/crypto/trust_anchors.py:104-105` (`pubkey_from_der_cert`),
  raises `ValueError("cert subject key is not Ed25519")` unless the
  certificate's subject key is an `Ed25519PublicKey`. A profile-conformant
  CA certificate signed with, e.g., `ecdsa-with-SHA256` (the spec's own
  RECOMMENDED algorithm) cannot be stored as an x509-kind trust anchor.
  Secondary: the store does not check `keyUsage keyCertSign` on CA certs
  (profile preamble describes ordinary RFC 5280 CAs as
  `basicConstraints CA=TRUE` + `keyCertSign`); its docstring cites stale
  bead `viku.6`, which no longer exists. Filed: project-LICHEN-worker6-bedw.20.
- **Question for Opus**: Is `pubkey_from_der_cert`'s Ed25519-only restriction
  a genuine divergence from §7 for the `x5chain` path, or is the anchor store
  deliberately scoped to the *issuer-key* (no-x5chain) trust model of 06-security
  §8.13 — where the anchor pubkey must be Ed25519 because it doubles as the COSE
  `kid` lookup key — leaving non-Ed25519 CAs exclusively to the future RFC 5280
  chain-validation path (bedw.12)? Decide: (a) relax the store for x509-kind
  anchors, or (b) keep Ed25519-only and document the scoping. Either answer
  should also decide whether `keyCertSign` must be checked on CA anchors and
  whether the stale `viku.6` docstring pointer should be updated.

## F2 — R-X509-048: RFC 5280 chain validation to a configured trust anchor (§8 step 1)

- **Requirement**: "Validates the chain per RFC 5280 to a configured trust
  anchor (06-security.md §8.13 'Trust Anchors')."
- **Classification**: not-implemented (partial adjacent evidence), confidence: low
- **Evidence**: The Python `TrustAnchorStore`
  (python/src/lichen/crypto/trust_anchors.py:77-111, tested in
  python/tests/coap/test_trust_anchors_resource.py: `test_x509_anchor_pubkey_extracted_from_cert`:216,
  `test_x509_anchor_rejects_key_mismatch`:224,
  `test_raw_anchor_kind_flips_to_x509_on_cross_signed_cert`:189,
  `test_post_x509_anchor`:407) parses DER CA certs but performs **key-pinning
  only** — its own docstring says "The cert's issuer signature and validity
  window are NOT checked here … chain validation is the X.509 path's job."
  No path building, CA-signature verification, or validity processing exists
  in any stack. `TrustLevel::Pkix` (rust/lichen-link/src/trust.rs:47,
  rust/lichen-gateway/src/trust.rs:111, lichen/subsys/lichen/gcp/include/lichen/gcp_trust.h:79)
  is a wire label with no processing behind it. Filed: bedw.12.
- **Question for Opus**: What is the intended relationship between the
  06-security §8.13 "Trust Anchors" model (key-pinned Ed25519 issuer keys,
  keyed by issuer IID for COSE `kid` lookup) and appendix §8 step 1 (RFC 5280
  path validation to a trust anchor)? Three readings to adjudicate:
  (a) key-pinning the root is sufficient conformance for step 1 and full path
  validation is optional hardening; (b) a real RFC 5280 path validator is
  required and the anchor store is only the *anchor config* substrate; or
  (c) the two models serve disjoint paths (no-x5chain vs x5chain) and step 1
  only applies to x5chain credentials. The answer sizes bedw.12 and determines
  whether the C/Zephyr stacks need a DER path walker (mbedTLS X.509) at all.

## Cross-reference discovery (filed, for Opus awareness)

- **06-security.md:1162-1164** — Key Binding check 3 states "The leaf
  certificate's SAN native `/128` has an IID equal to that same `kid`, per the
  verifier address-binding check (appendix-x509-cert-profile.md §8, step 4)."
  This is the **withdrawn** IID-embedded-in-address invariant: appendix §4
  (lines 102-107) and §8 step 4 (lines 280-283) state the native `AddrForKey`
  address does NOT embed the IID and MUST NOT have it substituted, per the
  settled `upstream-yggdrasil-addressing` decision in `spec/decisions.jsonl`
  (`test/vectors/gcp3_trust_models.json` already quarantines
  `ygg_addr[8:16]==IID` bindings as REJECTED-PROFILE REFERENCE). The 06-security
  text contradicts both the decision and the appendix clause it cites.
- Filed as project-LICHEN-worker6-bedw.21 (P1, spec bug, found during this
  sweep; not one of the section's 10 gap beads). Suggested fix is a reword of
  check 3 to require SAN `/128` == `AddrForKey(leaf public key)`. The address
  derivation itself is settled; only the 06 wording needs adjudication, so the
  fix is mechanical rather than `human-only`.
- **Question for Opus**: confirm the reword direction and check whether the
  06-security sweep's R-06-348 row (which quotes check 3 as spec text) needs a
  re-sweep once the wording lands.
