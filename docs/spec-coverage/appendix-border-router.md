<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

## spec/appendix-border-router.md — coverage (sweep 2026-09-09)

Scope note: this appendix ("Border Router Hardware Options") is predominantly
an informational hardware/backhaul/antenna selection guide. Lines 13–97
(Tier 1–3 hardware, power budgets, backhaul options table, antenna
considerations) contain **zero** RFC 2119 keywords and define no behavior —
no requirement rows are extracted from them. Line 10–11 ("Conventional
Internet and cloud integration therefore uses explicit application proxies
unless a separate routed service is configured") is a design-consequence
statement without a keyword — noted, not numbered. The only normative text is
the intro paragraph (lines 6–11). Requirement IDs use `R-BR-NNN`
(BR = appendix-border-router).

Step 0: `spec/decisions.jsonl` contains no decision whose `specs` array lists
`appendix-border-router.md` — no verify greps to run, no spec regression to
fix. The intro paragraph is consistent with the `upstream-yggdrasil-addressing`
decision (which covers 03/04/05/06/11, not this appendix): identity-preserving
backhaul, no address substitution.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-BR-001 | Native node /128s may enter Yggdrasil only through an identity-preserving transport for the owning node (intro ¶, line 8–9; lowercase "may … only" = restrictive permission) | implemented+tested | Rust GW: authenticated mesh ingress `ingest_mesh_frame` (lichend.rs:987-993, unauthenticated frames dropped); non-local dst → original IPv6 written verbatim to Yggdrasil TUN, source preserved (lichend.rs:1001-1024, `t.send_pkt(&ipv6)`; no NAT/rewrite code — rg clean); Yggdrasil-only 02xx dst routed to TUN via `is_local_mesh` RPL lookup (gateway.rs:1775-1804; tests `yggdrasil_cross_mesh_routing` gateway.rs:2783, `dao_route_makes_ygg_address_local` gateway.rs:2864); Grounded reachability advertised only while an upstream TUN path is owned (lichend.rs:501-504 `set_ygg_reachable(tun.is_some())`). Node side: gradient dst = `AddrForKey(pubkey)` (hybrid.rs:499; "identity-preserving" BR fallback hybrid.rs:281); root Grounded state = "identity-preserving global path" (router.rs:185, router.rs:912). Python: `IDENTITY_PRESERVING_GLOBAL` (rpl/address_classification.py:22), router.py:407, dodag.py:359. C: "Native identities fall back to the identity-preserving BR path" (lichen/subsys/lichen/routing/router.c:706). Tests: end_to_end.rs::mesh_node_pings_internet_host (:301, src/dst byte-preservation asserts :328-329), ::internet_host_pings_mesh_node (:341, asserts :359-360); vectors test/vectors/gateway_reachability.json (Grounded-bit advertisement, consumed by end_to_end.rs:411-413 and python/tests/rpl/test_gateway_reachability_vectors.py) and test/vectors/address_classification.json (`identity_preserving_global` class, python/tests/test_vectors.py). Cross-ref: prior sweeps R-08N-003 (docs/spec-coverage/08-nodes.md:17), R-04-009 (docs/spec-coverage/04-network.md:15) | low |
| R-BR-002 | A gateway-owned Yggdrasil daemon MUST NOT spoof node source addresses (intro ¶, line 9) | implemented+untested | Rust GW: verbatim forwarding both directions — mesh→TUN (lichend.rs:1019-1023) and TUN→mesh (gateway.rs:1737-1766); no source-rewrite/NAT path exists (rg clean). Daemon is an operator-run external binary; LICHEN only configures peer list + binary path (config.rs:196-207 YggdrasilConfig) and logs peer count (lichend.rs:443-444) — no code configures the daemon to originate node addresses. Adjacent anti-spoof guard: forwarded packet claiming src == root_addr MUST take IPv6-in-IPv6 tunnel per spec 8.9 (gateway.rs:1857-1867), tested `root_spoofed_source_on_forwarded_path_takes_tunnel_not_rh3` (gateway.rs:3055). Gap: no test pins "no spoof" at the TUN boundary itself — `forward_mesh_to_upstream`'s TUN write has no direct test, and the external daemon's behavior is unobservable from this repo. Prior sweep R-08N-003 recorded the same "no NAT code, rg clean" finding | low |

### Notes
- `forward_mesh_to_upstream` (lichend.rs:976-1028) has no direct unit test in
  lichend.rs (test module at :1766 covers provisioning/state security); the
  identity-preservation property is tested at the SCHC round-trip layer
  (end_to_end.rs) rather than at the TUN-write site.
- The stricter reading of R-BR-001 ("identity-preserving transport **for the
  owning node**" = node-owned/delegated location-agent transport) is open
  design work: bead project-LICHEN-zt3c.2.1 (delegated Yggdrasil location
  agents, yggdrasil-go #118). See flagged file for the question posed to Opus.
- No SHOULD/MAY requirements exist in this section. Gap beads filed: **0**
  (no not-implemented or divergent MUSTs). Flagged: **2**
  (appendix-border-router-flagged.md).
