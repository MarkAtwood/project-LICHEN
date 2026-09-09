## spec/04-network.md — flagged for Opus verification (sweep 2026-09-09)

Flags: (a) low-confidence rows, (b) ambiguous/divergent classifications. No oscore/EDHOC semantics in this section (06-security is not swept here).

---

### F1. R-04-006 — Root election "lowest EUI-64" (divergent, low confidence)

- **Requirement:** "Isolated mesh: nodes derive primary 02xx address independently... Root election (lowest EUI-64 deterministic election) establishes RPL DODAG."
- **Classification:** divergent.
- **Evidence:** All three stacks implement the 2a.5.2 multi-factor ordering — DODAG preference > stratum > RSSI+SNR score > IID-lowest as tiebreak only (rust/lichen-rpl/src/multi_instance.rs:976-1015; python link/slot_coordination.py:289; C tdma_root_select.c:94). Tests: rust multi_instance.rs:2452-2503, lichen/tests/{root_selection,tdma_root_select,multi_root}, python tests/link/test_slot_coordination.py:239-287.
- **Question for Opus:** Is §6.1's "lowest EUI-64 deterministic election" a stale summary that should be amended to reference the 2a.5.2 ordering (making the implementation conformant), or is lowest-EUI64-only election the intended normative behavior that the stacks diverge from? Related: the paragraph's "as documented above" points at demotion text that no longer exists in the file — what should it reference?

### F2. R-04-007 — Schnorr-signed DEMOTION_REQUEST demotion (not-implemented, low confidence)

- **Requirement:** ">50% vote demotion with Schnorr-signed DEMOTION_REQUEST" (retained mechanics, §6.1).
- **Classification:** not-implemented (gap bead project-LICHEN-worker6-b7z9.132).
- **Evidence:** `DEMOTION_REQUEST` has zero occurrences in rust/, lichen/, python/src/. Root signing infrastructure (root_sig.rs, rpl_root_sig.c, test/vectors/root_signature.json) exists and could host it; rust dodag.rs:826 has only a role-transition table test.
- **Question for Opus:** Is the vote-based demotion protocol still normative for the 04-network layer (vs. owned by 09-rpl-profile / 2a.5.2), and if so, is P3 the right priority given root compromise is already partially mitigated by DODAGID==AddrForKey binding (root_signature.json)?

### F3. R-04-018 — Hop-limited broadcast relay (divergent)

- **Requirement:** Relay MUST preserve original source, decrement HL, rebroadcast while HL>0, consume at 0.
- **Classification:** C implemented+tested (router.c:627-655 + routing_dispatch test:245-283); Python divergent (ff02/ff03 classified EXTERNAL → unicast to parent, routing/router.py:499-509); Rust not-implemented (no generic IPv6 multicast relay).
- **Question for Opus:** Python's EXTERNAL routing of mesh-local multicast may be intentional for gateway backhaul (multicast to a BR parent) — confirm whether spec 6.3.2 relay semantics are meant to apply to the Python Router class or whether a separate relay path (outside routing/router.py) exists that I missed. Filed as b7z9.130.

### F4. R-04-019/020/023 — §6.3.3 relay limiter (divergent; beads b7z9.129, cross b7z9.124)

- **Requirement:** Full relay-decision pseudocode: per-hop-bucket counters, full-/128 keying, SOS counter, hl 8..255 clamp, yellow-zone 50% drop, wired into relay.
- **Classification:** divergent. Python broadcast_limit.py has correct budgets/2h-expiry/yellow-zone but: single shared window per sender (not per-bucket), no SOS counter, ValueError on hl outside [1,7] instead of clamp, keyed on IID string, referenced only by tests — never wired into a relay path. Rust/C: no limiter.
- **Question for Opus:** (1) Should the Python single-window behavior be treated as an intentional simplification to be spec-amended, or must per-hop_bucket counters be implemented (my read: spec MUST wins, implement buckets)? (2) Is wiring the limiter into the C router.c multicast relay + Rust receive path the right placement?

### F5. R-04-021 — hl=0 consume-only, never budgeted (ambiguous, low confidence)

- **Requirement:** hl=0 packets are consume-only at the node; the relay decision returns before any bucket lookup.
- **Classification:** ambiguous. Python limiter raises ValueError for hl<1 (so hl=0 never reaches a bucket) but there is no explicit consume gate; C router drops relays at hop_limit<=1 (router.c:664-668) and delivers multicast locally at hl<=1 (router.c:643) — drop vs consume-local differs.
- **Question for Opus:** Does C's "relay drops at hop_limit<=1" satisfy "consume locally" (local delivery may still have happened for multicast), or is a distinct consume-then-no-relay behavior required at hl==0 specifically?

### F6. R-04-025 — C gateway mesh→internet multicast egress (divergent; bead b7z9.131)

- **Requirement:** BRs MUST NOT forward mesh multicasts to the internet.
- **Classification:** divergent (C only). lichen/apps/gateway/src/forwarding.c:155-226 egress gate checks tunnel auth + MTU only; router.c:627-640 handles backbone→mesh but mesh→internet multicast egress is unfiltered. Python (router.py:491-497 + br_multicast_filter.json) and Rust (gateway.rs:1770 + end_to_end.rs:567) conform.
- **Question for Opus:** Confirm my reading that Zephyr's IP forwarder can emit a mesh-originated multicast to the backhaul iface through the NPF egress gate in forwarding.c:82-107 (i.e., the drop must be added there or in router.c:641-645). If the gateway app never installs a route for multicast onto the backhaul, the gap may be theoretical — verify against the Zephyr forwarding config.

### F7. R-04-028 — Forwarding-plane martian filter: encode-time vs explicit forwarding decision (medium confidence)

- **Requirement:** "the forwarding decision, which every router MUST apply before relaying a packet whose destination is not this node... dropped at the forwarding decision and reported locally."
- **Classification:** implemented via a transitive route: relays re-encode every forwarded packet, and the emission policy (full martian table incl. dst scope 2-14) rejects at encode in all three stacks (C schc_helpers.c:462-488; python headers.py:102-108,234-243; rust codec.rs:243-253, test :3148). Explicit forward-time checks are partial: C router.c:634-635 (multicast scope 0/15), python survey_source_route (routing.py:450, unspecified/multicast source only).
- **Question for Opus:** Does encode-time enforcement at relay TX satisfy the "MUST apply before relaying" forwarding-decision requirement (observable behavior identical: no forward, no ICMP error), or does the spec demand a distinct pre-relay check (e.g., so a relay that never re-encodes, such as a pure L2 forwarder, is still conformant)? If the latter, C link-layer relay paths (lichen/tests/link_relay) bypass the IPv6 policy check entirely.

### F8. R-04-016 — ff03::1 group absent (medium confidence)

- **Requirement:** Standard multicast groups table lists ff03::1 (mesh-local all nodes) and ff03::fc (all LICHEN nodes).
- **Classification:** implemented with gap: ff03::fc is the only mesh-local group with a constant anywhere (rust multicast.rs:15-17, python addr.py:27); ff03::1 appears in no implementation (only python test prose, tests/routing/test_router.py:537).
- **Question for Opus:** Is ff03::1 vestigial in the spec (superseded by ff03::fc) and should the table be amended, or does some stack need to join/serve ff03::1?

### F9. R-04-033 — C SubnetForKey absent (low confidence, conditional MUST)

- **Requirement:** Routed /64s, when used, MUST equal upstream SubnetForKey (0300::/8).
- **Classification:** implemented+tested in Rust (addr.rs:160, tests:195) and Python (identity.py:270, test:141,193); C has no SubnetForKey and no routed-/64 use.
- **Question for Opus:** Confirm "when used" scopes this as conditional so C's absence is not a conformance failure today (spec 12.1 wording), or whether the C stack plans routed /64s (e.g., for BR subnet advertisement) that would make this a gap.

### F10. R-04-036 — Addr Mode value 1 cross-reference (ambiguous, low confidence)

- **Requirement:** Short-address mode selected by link-layer `Addr Mode` value 1 (02-physical-link.md:215).
- **Classification:** ambiguous — owned by the 02-physical-link.md sweep; I did not re-verify the frame addr-mode encoding here.
- **Question for Opus:** Confirm the 02 matrix already covers Addr Mode 1 ↔ 16-bit short address, so no duplicate requirement tracking is needed.

### F11. (housekeeping, not a requirement) Stale QUARANTINED comment in C test

- lichen/tests/pubkey_to_iid/main.c:44-49 still says the `.native` literals "encode the rejected SHA-512 LICHEN-native address profile... until the C derivation migrates (bead q6ko)", while lines 38-42 and 87 say the same literals are upstream AddrForKey outputs cross-checked against the upstream anchor — and identity_addr.c has already migrated. Comment drift only (memcmp at :197-199 validates against upstream-anchor values). Suggest deleting the stale block; no bead filed (comment-only).