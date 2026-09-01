# spec/06-security.md part 3 — flagged for Opus verification (sweep 2026-09-01)

Condition (c) of the sweep protocol applies (this IS 06-security), so the whole
section is in scope. Detailed entries below are the divergent / not-implemented /
low-confidence rows; the high-confidence implemented+tested rows follow in a
compact spot-check table. Companion matrix: `docs/spec-coverage/06-security-part3.md`.

## A. Divergent / not-implemented / low-confidence (detailed)

### A1. R-06-305 / R-06-310 — Root DIO signature: receiver wired only in Rust; no TX producer anywhere (divergent)
- **Requirement:** Receiver validation of the COSE_Sign1 root-signature DIO option (kid, alg, trust store, payload↔DIO cross-checks, expiry, root_seq cache keyed (dodag_id,instance)) — spec 8.10.1 L659-669; root SHOULD sign when CONFIG_LICHEN_RPL_ROOT_SIG=y (L693-696).
- **Classification:** divergent. Rust is fully wired in the production RX path (rust/lichen-node/src/rpl_stack/receive.rs:522→657-747, RootSeqCache rust/lichen-rpl/src/root_seq_cache.rs:45-97, TOFU pin store announce.rs:287). C has the complete decode/structural/replay library (lichen/subsys/lichen/rpl/root_dio_sig.c, root_dio_replay.c) but **zero production call sites** — dodag.c RX never consumes the option; only lichen/tests/rpl_root_sig calls it. Python's module (crypto/root_dio_signature.py) is an unwired oracle, and includes the **only root-side signing** implementation. No stack appends the option to outgoing DIOs; CONFIG_LICHEN_RPL_ROOT_SIG exists nowhere.
- **Bead:** project-LICHEN-worker6-b7z9.88 (filed this sweep; residual of closed b7z9.37, which predates the Rust RX wiring).
- **Question for Opus:** Is "Rust normative receiver, C/Python library-only" an acceptable steady state for a MAY defense-in-depth feature, or should C receiver wiring (one call site in dodag.c) be prioritized? Also: should the root-side signer be ported to Rust/C before the CONFIG switch exists, so the option can actually appear on the wire?

### A2. R-06-307 — expired root signature → Baseline: implemented, untested in RX path (low confidence)
- **Requirement:** Expired signature treated as unsigned; accepted with link-layer auth only (spec 8.10.1 L689).
- **Classification:** implemented+untested. Rust maps expired → Baseline (receive.rs:713-715); the only expiry test (root_sig.rs:489) is at the structural layer, not the RX outcome layer.
- **Bead:** none (single-line test gap; fold into the A1 bead's acceptance criteria if Opus agrees).
- **Question for Opus:** Should the A1 bead's acceptance criteria include an RX-path test pinning "expired ⇒ Baseline, not Reject" (the vector set currently has valid_far_expiry but no expired case)?

### A3. R-06-309 — root re-election must clear cached root_seq: no explicit clear anywhere (low confidence)
- **Requirement:** Root re-election ⇒ clear cached root_seq; new root starts fresh (spec 8.10.1 L686).
- **Classification:** implemented+untested (transitive). No stack clears the cache on re-election. Mitigation: the cache is keyed (dodag_id, instance) and DODAGID is cryptographically bound to the root's key (structural check root_dio_sig.c:419-423), so a genuinely new root necessarily produces a new dodag_id and a fresh cache key — the spec's intent (stale root's seq floor must not veto the new root) appears satisfied by construction. But a same-dodag_id re-election (root re-formation under the same DODAGID) has no path to reset the floor.
- **Bead:** none (flagged; may be spec-text clarification rather than code).
- **Question for Opus:** (a) Can a re-elected root reuse the same DODAGID in LICHEN's key-derived-address model? If not, propose amending the L686 table cell to note the dodag_id keying rationale. If yes, a clear-on-new-root hook is a real gap.

### A4. R-06-341 — §15.2 key storage MUST vs plain-flash implementations (divergent; threat-model tension)
- **Requirement:** Private keys MUST be stored in a hardware secure element (preferred) or flash with readout protection; never transmitted over the air (spec 15.2 L1211-1216).
- **Classification:** divergent. Never-over-the-air holds in all stacks (no private-key TX path). Storage is plain flash with integrity (C LIKY record + CRC + settings rollback authority; Rust Zeroizing + abort-on-fail; Python 0600 two-slot store citing spec 15.2 verbatim). No secure element, no flash readout protection (RDP) support anywhere.
- **Bead:** project-LICHEN-worker6-b7z9.87, filed this sweep, human-labeled — the project threat model (AGENTS.md) explicitly excludes physical/cold-boot attackers, which is the only adversary RDP/SE defends against. This is a spec-text vs threat-model adjudication, not a code fix.
- **Question for Opus (human decision):** Amend §15.2 to match the threat model ("stored in flash; never transmitted; secure element preferred where hardware provides it"), or keep the MUST and treat it as hardware-deployment guidance? Recommend the former (mirrors the GUARD_PPM-style align-spec-to-reality precedent).

### A5. R-06-342 — §15.3 "epoch increments on wrap" vs implemented never-wrap exhaustion (divergent, spec-text candidate)
- **Requirement:** Link-layer replay epoch persisted to flash; increments on wrap or reboot (spec 15.3 L1229-1230).
- **Classification:** implemented+tested with one wording divergence: all three stacks deliberately never wrap — epoch 255 is exhausted → fail closed / identity rotation (C replay.h "Epochs … never wrap"; Rust lichend.rs:211-236 fails at 255; Python EpochExhaustedError). Wrapping would reopen the replay window, so the implementations are safer than the spec sentence.
- **Bead:** project-LICHEN-worker6-b7z9.86 (filed this sweep; spec-text alignment; mirrors adjudicated-decision practice, e.g. trickle Imax).
- **Question for Opus:** Confirm the spec should read "epoch increments on reboot; epoch space is never wrapped — exhaustion at 255 fails closed and requires identity rotation" (or similar), matching all three implementations and epoch_rollover.json.

### A6. R-06-302 — RPL preinstalled secure mode (CONFIG_LICHEN_RPL_SECURE_MODE / RPL_PSK) absent everywhere (not-implemented, MAY)
- **Requirement:** Optional RPL preinstalled mode adds a network-wide control-plane PSK (spec 8.10 L555-582); §15.6 item 3 recommends enabling it in adversarial environments.
- **Classification:** not-implemented (no Kconfig, no code, no PSK MAC over RPL control in any stack). MAY-level ⇒ no bead per protocol; noted because §15.6's recommendation is currently unactionable.
- **Question for Opus:** Confirm the feature stays optional/deferred (docs/spec-chapter-breakdowns.md:937 lists it as planned P2), and whether §15.6 item 3 should be reworded until it exists.

### A7. R-06-318 — C authorization table bound 8 (max 32) vs recommended 256 LRU (divergent detail)
- **Requirement:** Authorization table MUST be bounded; recommended 256 entries LRU (spec 8.11 L809-812).
- **Classification:** implemented+tested — the MUST (bounded) is met in all stacks; C's default 8 / max 32 is below the *recommendation* only, and C compensates with fail-closed replay-floor history. STM32WL RAM constraints may justify the smaller bound.
- **Question for Opus:** Bless C's 8/32 bound (STM32WL memory budget) or require a Kconfig default closer to 256 for non-constrained gateway builds?

### A8. R-06-326 / R-06-327 — Python capability-announce resource quirks (divergent details)
- **Requirement:** Root validates capability announcements and bounds the capability table, MAY reserving 25% for egress-bit entries (spec 8.12 L949-984).
- **Classification:** implemented+tested overall, with two Python-only quirks: (a) verify re-encodes the protected header instead of hashing received bytes (capability_announcements.py:316) — equivalent for canonical messages, differs on exotic headers; (b) resource calls record() without egress= (:172-177), so the 25% egress reservation never engages (the MAY feature is inert; the MUST bound still holds at 256).
- **Bead:** none — (b) is a MAY-feature omission and (a) is equivalence-preserving on canonical input.
- **Question for Opus:** Is (a) worth a fail-closed tightening (hash received bytes like Rust), or document canonical-only?

### A9. R-06-315 — route_hash hops are caller-supplied; no SRH extraction at this site (low confidence)
- **Requirement:** route_hash computed from hop IIDs "in source-route order … matches the order in the IPv6 Source-Route Header" (spec 8.11 L758-767).
- **Classification:** implemented+tested at the library level (vector route_hops_hex pins the order); but no stack parses the hops out of an actual IPv6 Source-Route Header at this site — that is part of the unwired data path (R-06-311, b7z9.35).
- **Question for Opus:** Confirm b7z9.35's acceptance criteria include "hops extracted from the received SRH, order verified against the route_hash" so the spec sentence gets a live-wire test.

## B. Compact spot-check table (implemented+tested, high confidence)

| Req | Topic | Key evidence |
|-----|-------|--------------|
| R-06-301 | Unsigned RPL control rejected; no permissive mode | link_layer.rs:1092-1096; authenticated_dio.py:291-326; test_rpl_control_link_signatures.py:249 |
| R-06-303 | Root-sig option 0x17 + COSE_Sign1 format | message.rs:85; messages.c:176-223; root_dio_signature.json (14 vectors) |
| R-06-304 | Payload keys 1-7 + Sig_structure/SHA-256/Schnorr48 | root_sig.rs:146-347; root_dio_sig.c:226-392; cross-stack byte parity |
| R-06-306 | Graceful degradation (MUST NOT reject for missing root sig) | receive.rs:638-648, 681-712; rpl_root_sig main.c:200 |
| R-06-308 | root_seq MUST NOT wrap | root_seq_cache.rs:131-138; root_dio_replay.c:31-33; vector valid_seq_max |
| R-06-312/314/315 | tunnel-auth COSE envelope, payload keys 1-6, route_hash | tunnel_auth.rs:11-17/526-607/470-480; tunnel_authorization.json all-stack byte parity |
| R-06-316 | Egress 10-step validation, 2.04/4.03 | tunnel_auth.rs:282-372; tunnel_auth.c:327-367; tunnel_auth.py:438-494; 26 post_cases |
| R-06-317 | Decap policy checks (as library) | decapsulation_cases (13) driven by all three stacks |
| R-06-320/321 | Root-change table clear API; restart clears by design | set_root/change_root + root_rotation vectors |
| R-06-322 | COSE_Sign1 -65537 as standard envelope | root-sig, capability, slot-claim, delegation tokens all use it |
| R-06-323/325 | Capability bits + payload keys 1-6 (Rust/Py) | capability_announcements.json; reserved-bits vectors |
| R-06-342 | 32-entry replay window + epoch persistence | replay.h:59-64; replay.rs:39-75; replay.py:40; lichen/tests/replay*; epoch_rollover.json |
| R-06-343 | Key-derived stable addresses; no privacy extensions | addr.rs:86; short_addr.rs:23; identity_addr.c:28; ipv6-addresses.json |

## C. Already-tracked divergences (no new beads; verify owners still active)

- Tunnel-auth production wiring (CoAP endpoint C/Rust, data-path decap gate, root triggers, DIO root-change detection): `project-LICHEN-worker6-b7z9.35` + children `m9i4`, `utw0`; Rust sub-bugs `4j1y`, `tpbv`, `b3le`, `t6sj`.
- Capability-announce system layer (spec-path dispatch, C resource, re-announce on root change): `b7z9.36` + children `7nnl`, `7nnl.3`, `99sg`, `p7mv`.
- Node credentials + local facts (§8.13/§8.13.1, rows R-06-331…340): epic `project-LICHEN-worker6-bedw` + children `.1`-`.10`.
