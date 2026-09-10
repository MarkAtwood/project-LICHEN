<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# appendix-gatt-ipso — flagged set for Opus verification

Sweep: 2026-09-09. All 9 extracted requirements classified **not-implemented**
with high evidence confidence (absence established by exhaustive rg across
rust/, lichen/, python/src/, firmware/, c/). No row met the strict flag
criteria (low confidence / divergent / 06-security / oscore-EDHOC). Three
items are flagged anyway because the *classification or normativity* question
changes what the traceability matrix should claim, and one of them decides
whether 2 of the 3 filed gap beads should exist at all.

## 1. R-GATT-002 — is a keyword-less reservation "not-implemented" or vacuously satisfied?

- Requirement: "IPSO object IDs 26250-26299 are reserved for LICHEN BLE
  extensions not covered by the OMA registry" (spec/appendix-gatt-ipso.md K.4).
- Classification: not-implemented (no code defines or registers the 10
  extension objects; rg `\b2625[0-9]\b` → zero hits in all stacks).
- Evidence: docs/spec-coverage/appendix-gatt-ipso.md R-GATT-002 row.
- Question for Opus: a reservation statement imposes no positive behavior and
  nothing in the codebase violates the range. Should the status be
  "not-implemented" (the extension vocabulary the appendix defines does not
  exist), "implemented+untested" (trivially — nothing squats on the IDs), or
  n/a-informational with no row? The bead-filed umbrella treats it as part of
  the absent BLE-relay feature; confirm that framing or reclassify.

## 2. R-GATT-009 — is K.8's device-metadata statement normative enough to carry a row?

- Requirement: "Device metadata (manufacturer, model, serial, firmware version)
  maps to LwM2M Device Object (ID 3), not IPSO sensor objects" (K.8).
- Classification: not-implemented (no LwM2M Device object anywhere;
  `lwm2m` matches only docstrings of the two IPSO modules).
- Evidence: docs/spec-coverage/appendix-gatt-ipso.md R-GATT-009 row.
- Question for Opus: K.8 uses no RFC 2119 keyword ("maps to", declarative).
  The border-router sweep precedent dropped keyword-less design-consequence
  sentences from numbering. Should this row be kept (it defines a mapping
  decision a future implementer must honor) or demoted to a scope note? If
  dropped, the negative half ("do not map Device Name/Appearance/descriptors
  to IPSO objects") also has no enforcement site to verify against.

## 3. Section-wide — do the MUSTs inside an appendix that self-declares "informational" bind implementations?

- Requirements: R-GATT-003 ("Gateways MUST convert to SenML canonical units
  before transmission", K.5) and R-GATT-005 ("Gateway MUST add bt at
  reception", K.9.2).
- Classification: not-implemented; gap beads filed for both.
- Evidence: no conversion module or GATT notification receiver exists in any
  stack (see matrix headline note); bt field machinery itself is
  implemented+tested in all three stacks.
- Question for Opus: line 291 says "This mapping is informational." The sweep
  treated the two MUST sentences as binding gateway requirements (the
  informational disclaimer scopes the *mapping tables* vs primary registries,
  not the K.5/K.9 behavior clauses). Confirm that reading: if the MUSTs do not
  bind, gap beads project-LICHEN-worker6-b7z9.202 (unit conversion) and
  .203 (bt at reception) should be closed as no-behavior-defined, and the
  R-GATT-003/005 rows reclassified. Related sub-question: the K.9.2 second
  clause ("prefer device time" when CTS 0x1805 is advertised) has no keyword —
  it was folded into the MUST row as SHOULD-strength; confirm or split.

## Not flagged (explicitly cleared)

- R-GATT-001, R-GATT-004, R-GATT-006, R-GATT-007, R-GATT-008: plain
  absence-of-feature findings with grep-clean evidence and concrete
  partial-machinery citations; no classification ambiguity.
- No requirement in this section touches oscore/EDHOC semantics.
