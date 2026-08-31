# Flagged set — spec/11-lci.md (sweep 2026-08-31)

Requirements flagged for verification: low confidence, ambiguous/divergent
classification, or section 06-security/OSCORE-semantics sensitive. Each entry:
requirement, classification, evidence, and the specific question to answer.
Section is not 06-security and no row requires editing oscore/EDHOC internals;
R-11-041/R-11-047 concern OSCORE *usage policy* at the CoAP application layer
(C app gating / context bootstrap), not protocol-internal semantics — flagged
under criterion (c) for completeness, not under the human-only edit bar.

## R-11-001 — MUST NOT use legacy 0xC1 framing/integer codes/keys, raw_tx/raw_rx, /messages as LCI (17.1.1, 17.5)

- Classification: implemented+tested (confidence low).
- Evidence: Py/Rs clients clean (no 0xC1, no integer type codes; contract
  tests test_lci_contract_docs.py:38-110; Rs doc note
  rust/lichen-client/src/paths.rs:8-9). C: legacy LICHEN Native (0xC1 sync,
  LN_TYPE_RAW_TX/RX native.h:34-49) is still compiled into four puck boards
  (CONFIG_LICHEN_NATIVE=y, t1000_e_nrf52840.conf:42) and wired live
  (apps/puck/src/main.c:431), banner-marked "not the current LCI app contract"
  (native.c:5-17).
- Question: The MUST binds *clients using it as LCI*, and no client does. Does
  shipping a live co-resident legacy protocol on the same USB CDC port as LCI
  violate the deprecation, or is quarantine-plus-banner sufficient? (Related:
  bead `project-LICHEN-worker6-b7z9.41` touches the same boards.)

## R-11-006 — (no kw) Node routes client traffic to mesh addresses over LoRa; default router (17.2, 17.4)

- Classification: divergent (confidence high). Keyword-less — noted, not
  beaded, per matrix preamble.
- Evidence: C gateway forwards between interfaces
  (apps/gateway/src/forwarding.c:67 + CONFIG_NET_ROUTE); node/puck has no
  default-router injection; Rust has no local-client ingress at all
  (lichend serial peer carries mesh frames, lichend.rs:823-928); Py models
  client routing tables only (client/addressing.py:86-96).
- Question: Is gateway-only routing acceptable for this MUST-equivalent, or
  does 17.2's "the node acts as a router" require every LCI node (i.e. puck)
  to forward local-client IPv6 into the mesh? If the latter, this needs a gap
  bead despite being keyword-less.

## R-11-007 — (no kw) Node IID always key-derived SHA-512(pk)[0:8], U/L cleared (17.4)

- Classification: divergent (confidence high). Keyword-less — noted, not
  beaded.
- Evidence: Identity derivation is correct in all stacks (C
  app_identity.c:46-62; Py identity.py:138-151), but the C *LCI interface*
  address is literal fe80::1 (SLIP_LCI_NODE_IID slip_transport.h:43,
  slip_transport.c:118-121; BLE LCI fixed link addr ble_lci_netif.c:38-48),
  while 11:172-174 says fe80::1 is "illustrative shorthand".
- Question: Is a fixed fe80::1 LCI address a conformant instantiation of the
  "illustrative shorthand" sentence, or must the LCI interface carry the
  node's key-derived link-local (as the mesh interface does)? Clients that
  hard-code fe80::1 would interop; clients that resolve the node IID would not.

## R-11-011 — (no kw) /.well-known/core lists the contract resource set (17.5.1)

- Classification: divergent (confidence high). Keyword-less — noted, not
  beaded.
- Evidence: C gateway WKC lists registered resources but the option is off on
  puck; Py default site advertises 7 resources (opt-in for
  keys/diag/msg/deaddrop/confessions) pinned by core_link_format.json; Rust
  stub lists 4 paths (lichen-node/src/dispatch.rs:301-303).
- Question: Does 17.5.1's example response define a minimum advertised set
  that default sites must include (Py omits /keys, /diag, /msg/*, /deaddrop,
  /confessions by default), or is advertising-what-exists conformant?

## R-11-016 — (no kw) time object semantics: source_class tokens (17.5.3)

- Classification: divergent (confidence high). Keyword-less — noted, not
  beaded.
- Evidence: C emits capitalized class strings "GNSS"/"Network"/"Local-client"/
  "Manual/static"/"Internal RTC" (link/time_sync.c:206-224); spec 11:333 lists
  lowercase tokens (gnss, network, local-client, manual, internal-rtc); Py
  emits lowercase (timing/status_time.py:17-47). unix_time omission-when-
  invalid conforms in both.
- Question: Which spelling is canonical? A client matching on source_class
  values breaks against C today. (Also: C has two coexisting capitalizations —
  hal_bridge.c:13-15 uses lowercase as *source names*.)

## R-11-025 — Raw RX MUST NOT divert frames from the normal IPv6 stack (17.5.4)

- Classification: ambiguous (confidence low).
- Evidence: No stack implements real-radio raw RX (Py republishes host-pushed
  events only; C/Rs omit /diag/raw entirely, MAY-sanctioned). The MUST is
  vacuously satisfied everywhere; only the spec-text pin
  (test_lci_contract_docs.py:26) exists.
- Question: For coverage purposes, does vacuous satisfaction of a conditional
  MUST count as "implemented", or should this row stay open until a real
  tap-not-consume implementation + test exists?

## R-11-031 — BLE transports MUST require LE Secure Connections for raw-diag resources (17.5.4)

- Classification: implemented+tested (confidence low).
- Evidence: Py client enforces LESC per-path (packet_coap.py:296-370 + tests
  test_packet_coap.py:924-1250). C enforces transport-wide BT_SECURITY_L4 when
  CONFIG_LICHEN_BLE_TRANSPORT_DIAG_REQUIRE_SECURE=y (transport/Kconfig:148-156;
  ble_ipsp_transport.c:654) — stronger than per-resource, but C has no diag
  resources to bind.
- Question: Does whole-link L4 satisfy a per-resource MUST, or must the gate
  be tied to the resources when /diag/raw lands in C? (Whole-link L4 also
  restricts non-diag LCI traffic the spec leaves to weaker security.)

## R-11-032 — Beyond-local raw-diag exposure MUST use OSCORE or equivalent (17.5.4)

- Classification: ambiguous (confidence low). Folded into gap bead
  `project-LICHEN-worker6-b7z9.40` with R-11-030.
- Evidence: No guard exists: Py raw-diag resources carry no OSCORE gate and no
  mount restriction (raw_rx.py/raw_tx.py have zero auth checks); C/Rs omit the
  resources (vacuous).
- Question: Is "mountable-without-guard on the Python reference site" a real
  divergence (bead) or N/A because no Python deployment exposes raw diag
  remotely? Confirm the bead's suggested fix (Admin gate + beyond-local
  guard) matches the intended enforcement point.

## R-11-040 — Legacy /messages MUST NOT be advertised as a native messaging resource (17.5.7)

- Classification: implemented+tested (confidence low).
- Evidence: Py mounts LegacyMessagesAliasResource with rt="legacy.messages"
  title="legacy demo alias" (messaging.py:603-618) only when messaging is
  enabled; default site excludes it; test_lci_contract_docs.py:50-72 pins the
  spec sentence.
- Question: Does advertising the alias in /.well-known/core (with a legacy rt)
  violate "MUST NOT be advertised as a native messaging resource"? My reading:
  no (it is explicitly not native), but a stricter reading would remove it
  from discovery entirely.

## R-11-041 — Deaddrop: All writes (POST) MUST use OSCORE; unauthenticated → 4.01 (17.5.8)

- Classification: divergent (confidence low). Gap bead
  `project-LICHEN-worker6-b7z9.42` (P2).
- Evidence: Py/Rs enforce OSCORE-only POST with 4.01 (deaddrop.py:586-594;
  deaddrop.rs:1088-1090). C gates via coap_oscore_authorize_mutating
  (coap_dtn.c:146-152) but falls through to cleartext for local admins
  (coap_oscore.c:482-487), documented "OSCORE or local admin"
  (coap/include/lichen/coap_dtn.h:9).
- Question: Does 17.5.8's unqualified "All writes MUST use OSCORE" admit the
  C local-admin carve-out (per 17.6.3 access levels), or must the fallthrough
  be removed for /deaddrop? Deaddrop holds asynchronous third-party content,
  unlike /config — the carve-out rationale may not transfer.

## R-11-042 / R-11-045 — C deaddrop read ACL absent (17.5.8); C confessions rate limit 60s single-tier, last-IID-byte key, no hourly cap (17.5.9)

- Classification: divergent (confidence high). Both already captured by
  existing bead `project-LICHEN-worker6-l1qw.30` (filed by the 12-apps sweep
  against 18.9/18.10, which 17.5.8/17.5.9 declare authoritative); no new bead
  filed to avoid duplication.
- Evidence: C no read privacy ACL (coap_dtn.c:211-241); C confessions single
  window default 60 s via LICHEN_COAP_DEADDROP_RATE_LIMIT_MS (coap/Kconfig:320-
  328; coap_dtn.c:300-313), 256-bucket last-IID-byte key, no 12/hour tier. Py
  and Rs conform and are vector-tested (confessions.json, confessions_rate.json).
- Question: Confirm l1qw.30 fully covers these two rows so no separate LCI
  bead is needed (my check: yes — its description names the ACL gap and the
  cooldown-only/no-hourly-cap rate limiting).

## R-11-047 — (no kw) OSCORE over the local link, same mechanism as mesh traffic (17.6.2)

- Classification: implemented+tested (confidence high), included under
  criterion (c).
- Evidence: Same coap_oscore.c path serves local links (C, tests oscore/*);
  Py SecureDatagramChannel + per-resource gates; Rs SecureStack.
- Question: 17.6.2 says "OSCORE context established via pairing" — no stack
  has an automated pairing flow (contexts are provisioned manually,
  lichen-oscore/src/provisioning.rs:27). Is manual provisioning an acceptable
  reading of "pairing", or is a pairing protocol a missing requirement here?

## R-11-048 / R-11-049 — Access restriction SHOULD; 3-level transport-determined access matrix (17.6.3)

- Classification: R-11-048 implemented+tested (low); R-11-049 divergent
  (low). Keyword-less — noted, not beaded.
- Evidence: The full 3-level model (read-only/standard/admin, USB=admin,
  BLE=standard, /diag/raw/* admin-only) exists as a *tested oracle* — Py
  coap/access.py + access_levels.json vectors — and as an *unwired primitive*
  — Rs lichen-core/src/access_level.rs:15-47 (zero callers). The live
  enforcement paths are weaker/different: C 2-tier (local-admin vs OSCORE,
  coap_keys.c:51-98) and Py per-resource ad-hoc gates; the Py site never
  consults access.py.
- Question: Which artifact is the reference implementation of 17.6.3 — the
  tested access.py/access_levels.json model (in which case the gap is
  "wire it into dispatch"), or the C 2-tier model (in which case access.py
  over-specifies)? This determines whether R-11-049 needs a bead despite
  being keyword-less.

## R-11-050 / R-11-051 — Constrained node MUST implement SLIP framing; /.well-known/core (17.7)

- Classification: implemented+tested (confidence low). Covered by gap bead
  `project-LICHEN-worker6-b7z9.41` (P1).
- Evidence: Subsystems implemented+tested (tests/slip_transport 20 tests;
  gateway WKC), but t1000_e (primary target) enables CONFIG_LICHEN_NATIVE=y
  instead of SLIP, and puck prj.conf lacks CONFIG_COAP_SERVER_WELL_KNOWN_CORE.
- Question: Confirm the MUST is satisfiable by "available in the subsystem,
  enabled on some boards" vs requiring enablement on the constrained product
  (my reading: the product must serve it — hence the bead). Also confirm the
  intended disposition of CONFIG_LICHEN_NATIVE on those boards (R-11-001
  overlap).

## R-11-052 / R-11-053 — Constrained node MUST implement /config; /status (17.7)

- Classification: divergent (confidence high). Covered by gap bead
  `project-LICHEN-worker6-b7z9.41` (P1).
- Evidence: puck calls lichen_coap_server_init(NULL)
  (apps/puck/src/main.c:522) — handlers/providers are NULL, so /config and
  /status answer 4.04 on the constrained product; both are fully implemented
  and tested at subsystem level (tests/coap_config, tests/coap_status_get).
- Question: Verify there is no puck config path that registers providers
  (e.g. a CONFIG_LICHEN_COAP_PROVIDER variant) that the sweep missed; if
  truly NULL, the bead's fix is provider registration, not new code.

## R-11-054 — Capable node SHOULD implement all transports/resources/Observe/OSCORE local (17.7)

- Classification: ambiguous (confidence high). SHOULD — no bead.
- Evidence: C gateway is closest (WKC, config, status+Observe, keys, msg,
  deaddrop, confessions, SLIP+BLE+IPSP, OSCORE) but lacks /diag/raw and
  /proxy; Py has resources but opt-in mounting; Rust serves nothing.
- Question: Does "capable node" mean the C gateway, and is /diag/raw + /proxy
  required for it to meet this SHOULD? (Both are optional resources per 17.5.4
  / 17.5.6, which would make the SHOULD self-satisfying without them.)

## Gap beads filed (for cross-check against this set)

| Bead | Rows | Priority |
|------|------|----------|
| `project-LICHEN-worker6-b7z9.40` | R-11-028, R-11-030 (+R-11-032) | P2 |
| `project-LICHEN-worker6-b7z9.41` | R-11-050..R-11-053 | P1 |
| `project-LICHEN-worker6-b7z9.42` | R-11-041 | P2 |
