<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# .lichen.tech CA: Operational Design

This document is the operational design for the public LICHEN certificate
authority service, **.lichen.tech**. It is a design and policy document, not
an implementation. It defines the CA hierarchy, key protection, revocation
distribution, certificate lifetimes, identity-verification integration,
cross-signing policy, and the cost model.

The wire-format and cryptographic profile of the certificates this CA issues
are **out of scope here** — they are fixed by
`spec/appendix-x509-cert-profile.md` (the LICHEN node attestation profile) and
referenced by `spec/06-security.md` §8.13.2 (CA Credentials, Portable). This
document governs how the service that signs those certificates is operated.

The .lichen.tech CA is **optional**. Per `spec/06-security.md` §8.13 ("Default
CA"), deployments MAY use .lichen.tech, self-operate a CA, or use any PKI.
Nothing in the mesh protocol depends on this service existing; it is a
convenience and an adoption on-ramp, not a single point of failure.

## 1. CA Hierarchy

**Offline root, online intermediate.** Two levels of CA under a single
offline root.

```
LICHEN Community Root CA          (offline, air-gapped, Ed25519)
  └── .lichen.tech Issuing CA 1   (online, HSM-backed, Ed25519)
        └── node attestation certificates (per cert profile)
```

- **Root CA** — Ed25519, self-signed, `basicConstraints CA=TRUE`,
  `keyUsage keyCertSign, cRLSign`. Held **offline and air-gapped**. It signs
  only intermediate CA certificates and (rarely) cross-signing certificates
  (Section 6); `cRLSign` is present so the root can directly revoke an issuing
  or cross-signed CA if the normal issuer-signed CRL path is unavailable or
  untrusted. It never signs node certificates directly. Root operations are
  ceremony-driven (Section 2).
- **Issuing CA (intermediate)** — Ed25519, signed by the root, `CA=TRUE`,
  `keyUsage keyCertSign, cRLSign`. Held **online** in an HSM (Section 2) so it
  can issue node certificates and sign the CA CRL (Section 3) at API rate.

**Trust anchor model.** Verifiers pin the **root** as the trust anchor for the
.lichen.tech community trust domain; the issuing CA certificate is delivered
in the `x5chain` alongside the node certificate and validated to that root
per the cert profile (§8). The issuing CA is **not** itself the pinned anchor.
This is what makes the two-level hierarchy meaningful:

**Why two levels.** An offline root bounds the blast radius of an online-key
compromise: a compromised issuing CA can be revoked (via the CA CRL,
Section 3) and replaced by the root **without changing the root that
verifiers pin** for the *community* trust domain. Node certificates chain to
an issuing CA; verifiers that trust the root accept any issuing CA the root
has signed and not revoked.

**At least one spare issuing CA** is pre-provisioned so a compromised or
failed online issuer can be replaced in hours, not after a root ceremony. The
spare's **private key is generated and stored in a second, independent online
HSM** (or an offline HSM brought online only for activation), separate from
the active issuer's HSM, with the same non-exportable protection as the
active key (Section 2). The root signs the spare's certificate over that
spare key during a ceremony; the signed spare certificate and the key's
custody are logged. Because a stolen or misused spare is a fully capable
issuer chaining to the root, its HSM access is monitored and its certificate
is listed in the CA CRL's scope (Section 3) so it can be revoked independently
of the active issuer.

**Ed25519 throughout.** The cert profile mandates Ed25519 subject keys for
*node* certificates; CA key algorithm is CA-chosen per the profile (Section 7
allows any SHA-256-class-or-stronger algorithm, and `id-Ed25519` is allowed).
.lichen.tech uses Ed25519 for root and issuing CAs for algorithm uniformity
across the chain and to match the mesh's existing Ed25519 tooling. A
hybrid-PQC issuing CA (e.g. ML-DSA signing Ed25519 node certs) is a future
option and does not change this hierarchy.

## 2. Root Key Protection (HSM)

- **Root private key:** generated and stored in an **offline, air-gapped
  HSM** (FIPS 140-3 Level 3 target; e.g. a dedicated hardware token such as a
  YubiHSM 2 or Nitrokey HSM kept powered off in safe storage, never attached
  to a network-connected host). The root key never exists on a
  network-connected host; CSRs and signed outputs cross the air gap on
  removable media.
- **Root operations are ceremony-based:** issuing a new intermediate or a
  cross-signing certificate requires physical access, at least **two of three
  named key custodians**, and produces a signed audit record. No online path
  exists to the root key.
- **Issuing CA private key:** generated and stored in an **online HSM** (AWS
  CloudHSM, Azure Key Vault Managed HSM, or GCP Cloud HSM — see cost model,
  Section 7). The key is non-exportable; node-certificate signing happens
  inside the HSM. The issuing CA's certificate is signed by the root during a
  ceremony, then installed in the online service.
- **Backup:** root key material is backed up as **Shamir secret shares with a
  2-of-3 threshold**, each share held by a distinct custodian in a
  geographically separate offline store. No single custodian holds a complete
  copy of the root key, and reconstruction requires assembling the same 2-of-3
  quorum numerically as a live root ceremony. (The threshold scheme enforces
  the quorum *count*; it does not by itself enforce the ceremony's physical /
  audit controls — two colluding share-holders could reconstruct the key
  offline — so custodian selection and the ceremony audit trail remain the
  operative controls.) Issuing-CA keys are NOT backed up outside their HSM;
  on loss they are simply replaced from the root (they hold no irreplaceable
  state).
- **Issuance audit log.** Every node-certificate issuance by the online
  issuing CA is appended to a signed, append-only log (the CA's transparency
  record). Root ceremonies and cross-signing already produce signed audit
  records; routine node issuance — the online, API-rate operation most
  exposed to key misuse or issuance-API abuse — MUST be logged with the same
  rigor, so misissued certificates are detectable within their 30-day
  lifetimes rather than invisible. The log records the node IID and issuance
  timestamp only (no PII, consistent with Section 5).
- **Root compromise or loss.** Because verifiers pin the root (Section 1),
  root compromise is the catastrophic case: an attacker with the root key can
  sign arbitrary issuing CAs that every .lichen.tech-trusting verifier
  accepts. On suspected root compromise, all issuing CAs are revoked and the
  community migrates to a new root; this is a coordinated trust-anchor
  rollover distributed through the trust-store mechanism, and is expected to
  be rare and high-touch. On root key *loss* (no compromise), the 2-of-3
  Shamir backup reconstructs the key in a ceremony; if quorum cannot be
  assembled, the root is unrecoverable and a new root must be established and
  re-pinned. Neither path is automated; both are documented here so the
  failure mode is explicit rather than discovered during an incident.

## 3. Revocation: CRL / OCSP Distribution

The cert profile (§1) forbids CRL Distribution Points, AIA, and OCSP
no-check markers **in node certificates**, because offline meshes cannot
reach those services and constrained verifiers MUST NOT be required to
process them. Revocation for node certificates is therefore **by supersede +
short expiry**, exactly as in `spec/06-security.md` §8.13 ("Credentials are
superseded by issuing a new credential with higher seq. No explicit
revocation message. Short expiry (7-30 days) limits exposure."). This section
concerns the **CA-to-CA** and **backhaul-connected verifier** layers only.

- **Node certificates:** no per-cert revocation. Exposure is bounded by short
  validity (Section 4). A node key that must be "revoked" is handled by not
  renewing it and, where the deployment supports it, by the trust-store
  mechanism removing the corresponding trust.
- **CA-certificate CRL (the case that matters):** .lichen.tech publishes a
  **CRL covering only issued intermediate/cross-signing CA certificates**
  (never node certificates). It is signed by the **online issuing CA**, which
  is online and carries `cRLSign`, so a fresh CRL is issued on the 30-day
  `nextUpdate` cadence without an air-gapped root ceremony. The root retains
  `cRLSign` (Section 1) as a fallback revocation path for the case where an
  issuing CA must be revoked but cannot or should not sign its own
  revocation. Distribution channels, in priority order:
  1. **CoAP resource on gateways** — a `/.well-known/ca-crl` resource served
     by border routers, fetched over the backhaul when available and cached
     for offline use. This is the primary in-network distribution path.
  2. **HTTPS endpoint** (`https://ca.lichen.tech/crl/ca.crl`) for
     backhaul-connected verifiers, cloud bridges, and tooling.
  - Gateways MAY cache and redistribute the CRL (consistent with
    `spec/06-security.md` §8.13: "Gateways MAY cache and distribute CRLs").
- **OCSP:** **not provided for node certificates** (offline meshes cannot use
  it, and the profile omits the AIA marker). A minimal OCSP responder MAY be
  operated for the *issuing CA* certificate only, for the benefit of
  backhaul-connected verifiers and the cloud-bridge scenario; it is not on
  any node's critical path.
- **Stale-CRL tolerance:** CRLs carry a `nextUpdate` of 30 days. A verifier
  with an expired CRL falls back to the cert-profile behavior (trust anchored
  on the pinned root, bounded by cert expiry); it does not hard-fail closed —
  availability in an isolated mesh outranks CRL freshness.
- **Stated exposure bound.** Because of that fail-open fallback, the exposure
  bound for a compromised **online issuing key** is **not** the 30-day
  node-cert lifetime: an attacker holding the issuing key keeps minting fresh
  30-day node certificates, so the true bound for a verifier that cannot
  fetch a fresh CRL is the **remaining validity of the issuing-CA
  certificate** (up to 1 year, Section 4). Operators MUST treat online-issuer
  compromise as a page-the-root-ceremony event, and deployments that need a
  tighter bound SHOULD shorten the issuing-CA lifetime and/or require a
  maximum tolerable CRL age at their verifiers. A pre-revocation CRL replayed
  within its 30-day `nextUpdate` window is undetectable; this is accepted as
  the cost of offline tolerance and is bounded by the same issuing-CA
  lifetime.

## 4. Certificate Lifetime

Reconciling the cert profile's CA-certificate bounds with the credential
layer's short-expiry model:

- **Node attestation certificates:** issued with a validity of **30 days**
  (the long end of the spec's 7–30 day credential expiry range,
  `spec/06-security.md` §8.13). 30 days is chosen because the *certificate*
  is the portable attestation that must survive in caches and be presented
  across meshes; shorter-lived *credentials* derived from it carry the 7–30
  day expiry. Node certs are **auto-renewable** (Section 5): a node
  re-provisions via USB/BLE or, for backhaul-connected nodes, via a CoAP
  renewal endpoint, before expiry.
  - This is well inside the cert profile's hard bounds (`notAfter` finite,
    ≤825 days, 200 days recommended for CA-issued certs — §6). The 30-day
    node-cert lifetime is a *service policy* tighter than the profile's
    maximum, which the profile permits.
- **Issuing CA certificates:** validity **1 year**, re-issued from the root
  annually (or on compromise). The cert profile does not constrain CA
  certificates (its 825-day maximum applies only to end-entity node certs);
  1 year is a service policy chosen to bound online-issuer exposure (Section
  3) while keeping root ceremonies infrequent.
- **Root CA certificate:** validity **20 years**, self-signed. Root rollover
  is a long-lead, community-coordinated event and is out of scope for routine
  operation.
- **notBefore** is truncated to 00:00:00 UTC of the issuance day, per the
  cert profile (§6).

## 5. Identity-Verification Integration

The .lichen.tech CA optionally **verifies** a real-world identity as input to
its issuance decision, **without putting PII in the certificate** (per
`docs/speculation-and-futurism.md` §"Identity Verification"). The CA consumes
a third-party verification result; the certificate itself carries no identity
attributes (see the Flow bullet below).

- **Supported verification providers** (any may be enabled per deployment;
  none is required for a node to get a certificate):
  - **Stripe Identity** — government ID via photo + selfie; self-service API;
    pass/fail + metadata. Basic "a real human with a government ID."
  - **ID.me** — government ID **plus group affiliation** (military, first
    responder, nurse, teacher, student) verified against state/federal
    databases; OAuth flow. Best for professional/role trust.
  - **CLEAR Verified** — biometric + digital ID; enterprise partnership. High
    -assurance deployments.
- **Flow:** node owner completes the provider flow at a verification portal
  (e.g. `verify.lichen.tech`); the provider returns a signed verification
  result to the CA; the CA issues a node certificate conforming to the cert
  profile (Ed25519 subject key, SAN = native /128, optional mesh role
  extension). The certificate carries **no identity-verification attributes
  at all.**
- **Attestation outcome stays off the certificate.** The cert profile's
  extension set (its §1 field table) is deliberately exhaustive and minimal —
  there is no extension for "verified groups/level", and this design adds
  none. Two reasons: (a) group affiliation *is* personal data — in a small
  mesh "verified nurse via ID.me" is effectively identifying, so a "non-PII
  extension" is an assertion, not a property; and (b) the `x5chain` travels
  in the COSE_Sign1 **unprotected** header (`spec/06-security.md` §8.13), so
  any on-cert affiliation would be broadcast in cleartext on every credential
  presentation, to every verifier and any passive RF observer. Instead, the
  attestation outcome (service, date, verified groups/level) is recorded
  **only in the CA's own records**, keyed by the node IID, and is surfaced to
  relying parties that need it through a separate, authenticated channel
  (e.g. a gateway local-fact asserting `lichen:role`), never on the portable
  certificate. The certificate binds the Ed25519 mesh identity to the CA's
  willingness to sign it — nothing more.
- **The node never sees PII.** This preserves the mesh's cryptographic,
  self-sovereign identity model. Role-based trust (e.g. `lichen:role` /
  emergency-services authorization) is conveyed by the short-lived,
  mesh-local credential layer, which CAN carry claims under OSCORE, not by
  the portable cleartext certificate.
- **Renewal** (Section 4): a node renews by re-presenting its key. To keep
  any identity-derived role assertion current, the relying-party credential
  (not the certificate) is what carries the time-bounded claim; group
  affiliations are re-checked on the provider's cadence before a fresh
  role-bearing credential is issued. A deployment that requires
  re-verification on *certificate* renewal configures that as issuance
  policy; it is not silent-defaulted.

## 6. Cross-Signing Policy

Cross-signing lets an external PKI vouch for .lichen.tech, or lets
.lichen.tech vouch for a peer/fleet CA, without either side changing its
root.

- **Who may cross-sign with .lichen.tech:**
  - **Fleet/organizational CAs** operated by a deployment that wants its
    nodes accepted under the .lichen.tech community trust domain, and
  - **Peer community CAs** operated by other LICHEN communities.
  - The .lichen.tech **root** signs cross-certificates **only for CA
    entities** (never for individual node keys), and only after the
    operational review below.
- **What a cross-certificate attests:** a cross-certificate attests **only
  the CA-to-CA key binding** ("the subject CA's key is operated by the named
  organization"). It attests **nothing about the identity-verification
  rigor** the peer CA applies to its node certificates unless a separate
  policy agreement says so. A cross-signed chain is therefore **not**
  automatically equivalent to a .lichen.tech-issued credential for
  authorization decisions; verifiers decide per deployment.
- **Issuance requirements:** cross-signing is a **root ceremony** operation
  (Section 2), requires a signed cross-signing agreement naming the peer CA's
  DN, key, permitted `pathLenConstraint`, and intended use, and is recorded
  in the .lichen.tech CA's public log.
- **Constraints on cross-certificates:** `basicConstraints CA=TRUE` with
  `pathLenConstraint=0` (the peer CA may sign node certs but not sub-CAs
  under this cross-cert), **`keyUsage keyCertSign`** (mandatory, matching the
  requirement this design places on .lichen.tech's own root and issuing CAs —
  a cross-cert without keyUsage would be unrestricted), and a validity no
  longer than the root's remaining validity (cross-certificates are issued by
  the root, so their ceiling is the root's lifetime, not the issuing CA's).
- **Revocation:** cross-certificates are revocable via the CA CRL
  (Section 3).

## 7. Cost Model

Two tiers. The design goal (per `docs/speculation-and-futurism.md` §"The
ask") is that **basic node attestation is free**, following the Let's Encrypt
precedent that free CA service drives ecosystem adoption.

- **Individual / community tier — free.**
  - Node attestation certificates (30-day validity, auto-renewable).
  - Standard identity verification where the provider subsidizes it (e.g.
    ID.me group verification for first responders / military is free to the
    user). Where a provider charges (Stripe Identity ≈ $1.50/verification),
    that pass-through cost may be charged or subsidized by the project;
    the certificate itself remains free.
  - Rationale: zero-cost adoption for individuals, SAR teams, and community
    meshes generates the usage and credibility that sell organizational
    accounts.
- **Organizational tier — paid.**
  - Fleet/organizational CA cross-signing (Section 6) and the associated
    operational review.
  - High-assurance identity verification (CLEAR Verified, enhanced group
    verification).
  - SLA-backed issuance, dedicated issuing-CA isolation, and CRL/OCSP
    distribution guarantees.
  - Pricing is set by the operating organization and is out of scope for this
    document.
- **Operating-cost drivers:** online HSM (CloudHSM / Managed HSM / Cloud
  HSM), verification-provider per-call fees, CRL/OCSP hosting. Root ceremony
  and offline HSM storage are infrequent fixed costs. Marginal cost per
  issued node certificate is approximately zero at scale (the HSM and hosting
  are already provisioned), which is what makes the free tier sustainable.

## 8. Out of Scope / Non-Goals

- The certificate wire format and crypto profile (fixed by
  `spec/appendix-x509-cert-profile.md`).
- Node-certificate revocation semantics (supersede + expiry, per
  `spec/06-security.md` §8.13).
- The trust-store CoAP resource that distributes trust anchors to nodes
  (tracked separately under the CA-infrastructure epic).
- Any mandatory dependence of mesh operation on .lichen.tech — the mesh and
  its self-operated/TOFU trust models work without it.
- Cloud-provider IAM bridge internals (see
  `docs/speculation-and-futurism.md` §"Cloud IAM Bridge"); this CA can be
  *hosted* on a cloud HSM without the mesh protocol gaining any
  cloud-specific behavior.
