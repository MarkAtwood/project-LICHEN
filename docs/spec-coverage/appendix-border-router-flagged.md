<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# spec/appendix-border-router.md — flagged for verification (sweep 2026-09-09)

Both normative requirements of this appendix are flagged. Neither is
section 06-security nor oscore/EDHOC; both are flagged because conformance
turns on interpretation of the spec's own term "identity-preserving" and on
an untestable external component, and the classifier wants a second opinion.

## R-BR-001 — "Native node /128s may enter Yggdrasil only through an identity-preserving transport for the owning node"

- **Classification:** implemented+tested (Confidence: low — see question)
- **Evidence:**
  - Mesh→TUN path preserves the original IPv6 verbatim: authenticated ingress
    `ingest_mesh_frame` (rust/lichen-gateway/src/bin/lichend.rs:987-993),
    TUN write `t.send_pkt(&ipv6)` (lichend.rs:1001-1024); no NAT/rewrite
    code exists (rg clean).
  - Grounded advertisement fail-closed without an owned upstream TUN
    (lichend.rs:501-504, `set_ygg_reachable(tun.is_some())`).
  - "Identity-preserving" is this codebase's term of art for exactly this
    mechanism: router.rs:185, router.rs:912 ("root has an identity-preserving
    global path"), hybrid.rs:281, Python `IDENTITY_PRESERVING_GLOBAL`
    (python/src/lichen/rpl/address_classification.py:22), C
    lichen/subsys/lichen/routing/router.c:706.
  - Tests: rust/lichen-gateway/tests/end_to_end.rs:301 and :341 (byte-level
    src/dst preservation asserts at :328-329 and :359-360); vectors
    test/vectors/gateway_reachability.json (consumed at end_to_end.rs:411-413
    and python/tests/rpl/test_gateway_reachability_vectors.py) and
    test/vectors/address_classification.json.
  - Prior sweeps covering the same mechanism: R-08N-003
    (docs/spec-coverage/08-nodes.md:17), R-04-009
    (docs/spec-coverage/04-network.md:15).
- **Question for Opus:** Does "an identity-preserving transport **for the
  owning node**" mean (a) what is implemented — verbatim byte-preserving
  forwarding through a gateway-owned TUN with the daemon never originating
  node sources (per R-BR-002), or (b) something stronger — a transport the
  owning node itself owns/authorizes (delegated location-agent design, open
  bead project-LICHEN-zt3c.2.1, yggdrasil-go issue #118)? If (b), the current
  gateway-TUN ingress should be re-classified divergent/incomplete and the
  appendix reworded or the migration tracked. Related sub-question: the TUN
  write site (lichend.rs:1019-1023) has no direct test — is the SCHC-layer
  round-trip coverage (end_to_end.rs:301/:341) acceptable conformance
  evidence, or should a direct test of `forward_mesh_to_upstream` be required?

## R-BR-002 — "a gateway-owned Yggdrasil daemon MUST NOT spoof node source addresses"

- **Classification:** implemented+untested (Confidence: low — see question)
- **Evidence:**
  - LICHEN-side forwarding never rewrites source addresses in either
    direction: mesh→TUN verbatim (lichend.rs:1019-1023), TUN→mesh verbatim
    (rust/lichen-gateway/src/gateway.rs:1737-1766); no NAT/spoof code path
    (rg clean).
  - The Yggdrasil daemon is an operator-run external binary; LICHEN only
    configures binary path + peers (rust/lichen-gateway/src/config.rs:196-207,
    YggdrasilConfig) and logs peer count (lichend.rs:443-444). No code
    configures the daemon to originate node addresses.
  - Adjacent anti-spoof guard: a forwarded packet claiming src == root_addr
    is a spoof and MUST take the IPv6-in-IPv6 tunnel (gateway.rs:1857-1867),
    tested `root_spoofed_source_on_forwarded_path_takes_tunnel_not_rh3`
    (gateway.rs:3055).
- **Gap:** no test pins the no-spoof property at the TUN boundary
  (`forward_mesh_to_upstream` TUN write untested directly), and the daemon's
  own behavior is outside this repository.
- **Question for Opus:** (1) Is the implemented+untested classification
  correct, or does "MUST NOT spoof" only become assessable once LICHEN owns/
  spawns the daemon (currently it does not — is that itself a gap against
  "gateway-owned")? (2) Does forwarding a verbatim node-sourced packet into
  the daemon's TUN constitute the daemon "spoofing node source addresses" on
  the wider Yggdrasil network (since yggdrasil-go routes by source tree), or
  is verbatim forwarding precisely the identity-preserving behavior R-BR-001
  permits? Answer (2) determines whether R-BR-001 and R-BR-002 are mutually
  consistent as written, or whether the appendix paragraph needs rewording.
