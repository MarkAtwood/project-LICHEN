<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Appendix: X.509v3 Certificate Profile for LICHEN Node Attestation

This appendix defines the X.509v3 certificate profile referenced by
06-security.md §8.13.2 (CA Credentials, Portable). When a CA-issued
credential is carried in the `x5chain` header parameter of a §8.13
COSE_Sign1 credential (per RFC 9360), the end-entity (leaf) certificate
in that chain MUST conform to this profile. Intermediate and root CA
certificates are ordinary RFC 5280 CA certificates (`basicConstraints`
CA=TRUE, `keyUsage` keyCertSign); this profile does not constrain them.

The profile is deliberately minimal: any conforming CA that can issue
RFC 5280 certificates with an Ed25519 subject key can issue an
interoperable LICHEN attestation certificate. No custom CSR format is
required; requests use PKCS#10 (RFC 2986).

**Proof of possession (REQUIRED at issuance).** Before issuing, the CA
MUST verify that the requester controls the private key corresponding to
the Ed25519 subject public key. For a PKCS#10 request this is the
`certificationRequestInfo` self-signature: the CA MUST verify the request
signature over the DER-encoded `certificationRequestInfo` using the
subject public key it carries (RFC 2986) and MUST reject a request whose
signature does not verify. A CA MUST NOT issue a LICHEN attestation
certificate for a subject public key whose proof of possession it has not
verified; without this check an attacker could obtain a certificate
binding the SAN address (Section 4) to a key it does not control,
undermining the key-to-address attestation of Section 8 step 4. No
proof-of-possession round trip beyond the CSR self-signature is required.

Key words MUST, MUST NOT, SHOULD, MAY are per RFC 2119.

## 1. Profile Summary

| Field | Requirement |
|-------|-------------|
| Version | v3 (`2`) |
| SubjectPublicKeyInfo | Ed25519 (Section 2) |
| subject | Empty (normative), or `serialNumber` only (Section 3) |
| issuer | CA-chosen DN; `CN` REQUIRED, `O` SHOULD be present |
| subjectAltName | Native `/128` as iPAddress; critical iff subject is empty (Section 4) |
| Mesh Role extension | Non-critical, `2.25.…` OID (Section 5) |
| basicConstraints | Critical, `CA=false` |
| keyUsage | Critical, `digitalSignature` only |
| extendedKeyUsage | Absent by default; `id-kp-clientAuth` if present |
| validity | Finite; NOTBEFORE/NOTAFTER conventions (Section 6) |
| signatureAlgorithm | CA-chosen; inner and outer MUST match (Section 7) |

A conforming certificate MUST NOT include CRL Distribution Points, AIA,
or OCSP no-check markers; offline meshes cannot reach such services and
constrained verifiers MUST NOT be required to process them.

## 2. SubjectPublicKeyInfo

The subject public key MUST be an Ed25519 public key:

| Component | Value |
|-----------|-------|
| algorithm | id-Ed25519 `1.3.101.112` (RFC 8410) |
| parameters | absent |
| subjectPublicKey | 32 bytes, raw encoding per RFC 8410 |

No other public key algorithms are defined by this profile. The Ed25519
public key in the certificate MUST be the node's LICHEN identity key —
the same key from which the node's addresses derive: the link-local IID
(SHA-512 profile) and the routable upstream Yggdrasil `AddrForKey`
`/128` (03-addressing.md §3.1, 04-network.md §6.2).

## 3. subject and issuer Distinguished Names

**subject:** The subject field SHOULD be empty. Identity is carried by
the SAN (Section 4) and bound to the key by the verifier address-binding
check (Section 8). If a subject is included, it MUST consist of a single
attribute:

- `serialNumber` = the node's 13-character Crockford Base32 short
  address (03-addressing.md §3.1), or the 16-character uppercase hex of
  the node IID.

**issuer:** The issuer DN is CA-defined. It MUST contain `CN`, and
SHOULD contain `O` naming the operating organization. No other
attributes are required. Verifiers MUST NOT match on issuer DN for
authorization decisions; chain validation to a configured trust anchor
is the only issuer-based decision.

## 4. subjectAltName: Native Address

The subjectAltName extension MUST be present, MUST be critical when
subject is empty and MUST be non-critical when subject is non-empty
(RFC 5280 §4.2.1.6), and MUST contain exactly one iPAddress GeneralName
(tag `[7]` primitive) encoding the node's key-derived native address:
the 16-byte `0200::/8` `/128` equal to upstream Yggdrasil
`AddrForKey(subjectPublicKey)` (04-network.md §6.2, 06-security.md §8.5,
and the `upstream-yggdrasil-addressing` decision in
`spec/decisions.jsonl`). A second native `0200::/8` iPAddress MUST NOT
appear.

dNSName, rfc822Name, and URI GeneralNames MUST NOT be used; LICHEN has
no DNS namespace and the profile does not bind email or web identity.

A link-local `fe80::/10` address with the node's IID MAY be included as
one additional iPAddress; it carries no additional identity information
(its IID is independently derived from the same key, and the native
`AddrForKey` address does not embed the IID) and verifiers MUST ignore
it for authorization. Verifiers MUST ignore any iPAddress other than the
single native `0200::/8` entry, including a link-local entry.

Worked encoding for subject public key
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
(upstream `AddrForKey` bit-packs the inverted key: byte 0 `0x02`, byte 1
= 15 leading 1-bits of the inverted key, then the remaining inverted-key
bits, giving `020f:fdfc:fbfa:f9f8:f7f6:f5f4:f3f2:f1f0`):

```
SEQUENCE (subjectAltName)        30 12
  [7] iPAddress (16 bytes)         87 10
      02 0F FD FC FB FA F9 F8 F7 F6 F5 F4 F3 F2 F1 F0
```

## 5. Mesh Role Extension

The mesh role extension asserts the node's operating role. It is a
custom extension whose OID lives in the registration-free UUID arc
(ITU-T X.667 / ISO/IEC 9834-8), derived from UUID
`5787c1be-467b-5e51-92c4-77bcaeb02a21`
(= UUIDv5, DNS namespace, name `x509-mesh-role.lichen.tech`):

| Item | Value |
|------|-------|
| extnID | `2.25.116347725289407359125616919235271862817` |
| critical | `false` (MUST NOT be critical) |
| extnValue | OCTET STRING wrapping a DER BIT STRING (below) |

The BIT STRING carries named bits; unspecified bits MUST be zero:

| Bit | Role | Meaning |
|-----|------|---------|
| 0 | leaf | Endpoint node; does not relay others' traffic |
| 1 | relay | May forward traffic on behalf of other nodes |
| 2 | gateway | Border router / DODAG root with backhaul |

Roles are cumulative: a gateway that relays sets both bits 1 and 2.
The extension MUST be omitted (not an empty bit string) for a
certificate asserting no role. If the extension is nonetheless present
with an empty BIT STRING (no named bits), verifiers MUST treat it as
unasserted, exactly as if the extension were absent. Verifiers that do
not implement this extension MUST ignore it (non-critical per RFC 5280
§4.2); authorization logic MUST NOT treat absence as "leaf" — absence
means "unasserted".

Worked extnValue encodings (OCTET STRING wrapper shown):

| Roles | DER |
|-------|-----|
| leaf | `04 04 03 02 07 80` |
| relay | `04 04 03 02 06 40` |
| gateway | `04 04 03 02 05 20` |
| leaf + relay | `04 04 03 02 06 C0` |
| all three | `04 04 03 02 05 E0` |

The role bits mirror the §8.13 `lichen:relay` claim semantics: a
certificate whose role extension asserts bit 1 (relay) presented by a
node satisfies a verifier's `lichen:relay=true` requirement, subject to
the role-assertion trust scope of Section 8 (the chain must validate to
a role-granting anchor), unless the deployment requires the short-lived
COSE local-fact form for that decision.

## 6. Validity and Revocation

Offline meshes cannot check revocation services, so certificate
lifetime is the primary exposure bound:

- `notBefore` MUST be truncated to 00:00:00 UTC of the issuance day.
- `notAfter` MUST be finite. The RECOMMENDED validity is 200 days from
  `notBefore` (the CA/Browser Forum SC-081 maximum for certificates
  issued on or after 2026-03-15). A validity period longer than 825
  days MUST NOT be issued.
- Renewal is by re-issuance through the provisioning flow
  (USB/BLE cert injection). Certificate replacement is signaled
  by presenting the new chain; verifiers have no notion of certificate
  sequence numbers and MUST apply freshness ordering instead: a
  presented chain replaces the cached one only if its leaf `notBefore`
  is strictly later than the cached leaf's. A chain whose leaf is not
  newer MUST NOT displace the cached chain. This prevents a replayed or
  re-fetched older-but-still-valid chain from rolling a node back to a
  prior (e.g. reduced-role or superseded) attestation.

  Because `notBefore` is truncated to the issuance day (above), two
  certificates issued on the same UTC day tie on `notBefore`, and the
  strict-later rule then keeps the first-cached chain. Same-day
  re-issuance therefore does NOT propagate to verifiers that already
  cached the earlier chain; a deployment that must replace a
  certificate within the same day (e.g. to revoke a role) MUST wait for
  the next UTC day or use a fresher out-of-band channel. Accept-on-tie
  is not permitted: it would reopen the same-day rollback this rule
  exists to close, and there are no sequence numbers to break ties.

**Revocation model.** There is no online revocation: no CRL, OCSP, or
equivalent service exists in an offline mesh, and certificates carry no
revocation pointers (Section 1). Revocation is by supersession — a
replacement chain issued through the provisioning flow displaces the
cached chain for the same subject key under the freshness-ordering rule
above, and the displaced chain is thereafter unhonored. Supersession
takes effect at a verifier only when the replacement chain reaches it;
until then the prior chain remains honored within its own validity
window, and a radio adversary that censors the replacement can prolong
that window at chosen verifiers. A chain outside its validity window
MUST NOT be honored and MUST NOT displace a valid cached chain. A
verifier MUST NOT honor a cached chain whose leaf has expired.

The verifier maintains a per-subject-key freshness floor: the greatest
leaf `notBefore` ever cached. A presented chain for that subject key
MUST NOT displace the cached chain unless its leaf `notBefore` is
strictly later than the floor; this generalizes the freshness-ordering
rule above so that a replayed older-but-still-valid chain cannot roll
the node back even after the newer chain has expired. The floor gates
displacement only: the currently cached chain is honored within its own
validity window regardless of the floor, and before the first
displacement the floor is the cached chain's own `notBefore`. The floor
SHOULD persist across restarts; a verifier without persistent storage
loses it on power loss and reopens the rollback window until the next
displacement. A floor entry MAY be discarded once every chain it could
gate is necessarily expired (floor date plus the 825-day maximum
validity). The body of an expired chain MAY be dropped for storage
reclamation once the floor is recorded; the current, still-valid chain
MUST NOT be dropped.

Revoking a compromised subject key is NOT achieved by supersession: a
re-keyed node is a new identity (its key-derived address changes), so
the compromised key's chain is not displaced and remains valid until
its own `notAfter`. The compromised key MUST be retired out-of-band
(e.g. operator notification to verifiers); short validity (RECOMMENDED
200 days) bounds the exposure of a key that cannot be retired this way.

## 7. Signature Algorithm

The CA is free to sign with any widely supported algorithm it keys for,
subject to a floor: the signature algorithm MUST be SHA-256 class or
stronger (e.g. `ecdsa-with-SHA256`, `ecdsa-with-SHA384`, RSASSA-PSS with
SHA-256 or better) or `id-Ed25519`; MD5- and SHA-1-based signature
algorithms MUST NOT be used.
The `signature` field of `tbsCertificate` and the outer
`signatureAlgorithm` MUST be identical (RFC 5280 §4.1.2.3).
RECOMMENDED: `ecdsa-with-SHA256` (`1.2.840.10045.4.3.2`).
`id-Ed25519` (`1.3.101.112`) is also allowed (RFC 8410).

The CA's key is not the node's identity key and need not be an Ed25519
key; only the subject SPKI is constrained (Section 2).

## 8. Verifier Behavior

A constrained verifier processing a profile-conformant chain:

1. Validates the chain per RFC 5280 to a configured trust anchor
   (06-security.md §8.13 "Trust Anchors").
2. Checks the validity window; a chain outside its window MUST NOT be
   honored and MUST NOT displace the cached chain. Displacement is
   gated by the Section 6 freshness floor: a presented chain displaces
   the cached chain only if its leaf `notBefore` is strictly later than
   the greatest leaf `notBefore` ever cached for the subject key; the
   cached chain is honored within its own window regardless of the
   floor.
3. Checks `basicConstraints` CA=false and `keyUsage` digitalSignature
   on each end-entity certificate.
4. **Address binding (the attestation payload):** recomputes the full
   native address from the subject public key as upstream Yggdrasil
   `AddrForKey(subjectPublicKey)` (04-network.md §6.2 — bit-invert the
   32-byte key, `addr[0]=0x02`, `addr[1]` = count of leading 1-bits of
   the inverted key, `addr[2:16]` = the remaining inverted-key bits
   after the leading 1s and first 0 separator, zero-padded tail; no
   hashing) and verifies that the SAN native `/128` equals this
   recomputed 128-bit address byte-for-byte. The SHA-512 IID is not
   embedded in the routable address and MUST NOT be substituted into its
   lower 64 bits. A certificate that fails this check MUST be rejected —
   it attests a key-to-address pairing that does not hold.
5. If role-based authorization applies, reads the mesh role extension
   (Section 5); when the certificate asserts the needed role, the check
   passes without contacting the gateway. Role assertions are honored
   only from chains terminating at a trust anchor the deployment has
   explicitly configured as a role-granting authority; see below.

Step 4 is what makes the certificate an *attestation*: the CA is
asserting "this Ed25519 key is the identity key for this mesh address".
Any CA can verify the same binding before issuing, using only the
public key from the CSR.

### Role-assertion trust scope

The mesh role extension (Section 5) MUST be honored only when the chain
validates to a trust anchor that the deployment has separately
configured as authorized to grant roles. A chain validating to any
other configured anchor (including the optional public default CA in
06-security.md §8.13) establishes key-to-address binding (step 4) but
MUST NOT be read as asserting any mesh role. This keeps role grants
gateway/mesh-scoped, consistent with the `lichen:relay` local-fact
model (06-security.md §8.13.1): an identity-only anchor must not become
a mesh-wide forwarding grantor. As in Section 5, absence of a role
assertion is "unasserted", never "leaf".

## 9. Interoperability Notes

- A CA that supports RFC 8410 Ed25519 CSRs, critical iPAddress SAN,
  and free-form extension OIDs can issue this profile without
  LICHEN-specific software. CAs that cannot add custom extensions may
  issue certificates lacking the role extension (Section 5); only
  role-based authorization is lost.
- The `2.25` UUID-arc OID requires no registration with any authority;
  implementations hard-code the arc value above.
- Test vectors for chain validation and cross-signing are tracked
  separately and will live in `test/vectors/`.
