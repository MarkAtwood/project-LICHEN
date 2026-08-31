## spec/appendix-border-router.md — coverage (sweep 2026-08-31)

2 requirements extracted. The rest of the appendix is non-normative hardware
guidance — "Hardware Recommendations" Tiers 1–3, "Power Budget Comparison",
"Backhaul Options", "Antenna Considerations" — with no RFC 2119 keywords and
no protocol behavior (procurement/installation advice; the antenna bullets use
imperative mood but regulate hardware selection, not implementations). Noted
here, not extracted as requirement rows, not beaded. Both normative statements
sit in the intro paragraph (lines 6–11); req IDs use prefix `R-ABR` (appendix
border router). Gap beads filed: 0 — the single MUST is ambiguous (see flagged
set `docs/spec-coverage-appendix-border-router-flagged.md`; if Opus rules it
divergent, file the gap bead from that set). Overflow: 0.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-ABR-001 | Gateway-owned Yggdrasil daemon MUST NOT spoof node source addresses (intro) | ambiguous | Compliant half: LICHEN-owned forwarding preserves node sources verbatim — Rs mesh→upstream TUN write of the decompressed original IPv6 (lichend.rs:939,947-951), no NAT/rewrite symbols in any stack (rg clean; cross-ref R-08N-003, R-04-010), src/dst byte-exact through the SCHC round-trip asserted in end_to_end.rs:283-323 (asserts :318-323); C: Zephyr forwarding hook does stats + MTU drop only, no address mutation (apps/gateway/src/forwarding.c:67-91). Undetermined half: the regulated artifact — the gateway-owned Yggdrasil daemon — is implemented/configured by no stack: `[yggdrasil]` config parsed and logged only (config.rs:197-212, lichend.rs:381-382; no spawn/Command anywhere in lichend.rs), daemon is operator-external per config.rs:150 ("gateway: external Yggdrasil daemon on Linux"). Whether the composed lichen0→yggdrasil deployment carries node sources into Yggdrasil (= spoofing under the strict reading of R-ABR-002) or upstream source filtering drops them is undetermined in-repo | low — flagged |
| R-ABR-002 | Native node `/128`s may enter Yggdrasil only through an identity-preserving transport for the owning node (intro; MAY + "only through" constraint) | not-implemented (conformant — MAY) | No owning-node Yggdrasil participation / identity-preserving transport exists in any stack; the mechanism is open research bead `project-LICHEN-zt3c.2.1` (delegated location agents). Adjacent plumbing that names the concept without providing the transport: Grounded-bit reachability gated on an owned TUN (set_ygg_reachable lichend.rs:439-442) with vector gateway_reachability.json consumed by rust/lichen-gateway/tests/end_to_end.rs and python/tests/rpl/test_gateway_reachability_vectors.py; classification vocabulary IDENTITY_PRESERVING_GLOBAL (Py rpl/address_classification.py:22 + vectors address_classification.json); C comment "identity-preserving BR path" (routing/router.c:655). MAY — never beaded; its interpretation decides R-ABR-001, so flagged | high |

### Histogram (rows)

- implemented+tested: 0
- implemented+untested: 0
- divergent: 0
- not-implemented: 1 (R-ABR-002 — explicit MAY, absence conformant, no bead)
- ambiguous: 1 (R-ABR-001 — the section's only MUST; flagged, no bead pending Opus ruling)

### Gap beads filed (0; cap 10; overflow 0)

None: no not-implemented or divergent MUST. R-ABR-001 is ambiguous — the
disposition question and the pre-authorized bead text live in
`docs/spec-coverage-appendix-border-router-flagged.md`.

Adjacent observation (not a requirement of this section, no bead filed):
deploy/lichend.toml.example:32-43 documents `[yggdrasil]` auto_peer/peers/
binary, but lichend only parses and logs them (config.rs:197-212,
lichend.rs:381-382) — config-schema only, no auto-peering behavior. Candidate
for the regular review loop; the appendix's normative text does not cover
auto-peering, so it is not a gap bead here.
