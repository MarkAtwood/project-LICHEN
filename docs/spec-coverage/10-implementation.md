# spec/10-implementation.md — coverage (sweep 2026-09-09)

Step 0 note: `spec/decisions.jsonl` contains no decision whose `specs` array
includes `10-implementation.md` — no verify-greps to run, no spec fixes needed.
The `upstream-yggdrasil-addressing` and `custody-best-effort` decisions were
checked for conflicts with this section's text; none found.

Status vocabulary: `i+t` = implemented+tested, `i` = implemented+untested,
`div` = divergent, `n-i` = not-implemented, `amb` = ambiguous.
Per-stack qualifiers used where stacks differ (convention of prior sections).

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|-----|---------------------|--------|----------|------------|
| R-10-001 | Non-Neo R1 display variants and LR1121 radio variants are not implied by the MVP; require separate board files, driver work, and validation evidence before advertised as supported (§16.2) | i | Recommended target present: `lichen/boards/muzi/r1_neo/r1_neo_nrf52840.{dts,yaml,defconfig}` + Kconfig.r1_neo; `boards/muzi/` contains only `r1_neo/`; repo-wide glob `**/*lr1121*` → no files (no non-Neo/LR1121 board files exist to be advertised). Scoping claim — no code behavior to test | high |
| R-10-002 | STM32WL constraints: "May disable store-and-forward" (§16.4, MAY) | i | C: `lichen/subsys/lichen/routing/Kconfig:167-171` `LICHEN_DTN_BUFFER` bool + `:102-106` `LICHEN_DTN_MAX_BYTES` "Set to 0 to disable"; Rust `rust/lichen-node/src/routing/dtn.rs` module. MAY — never filed | high |
| R-10-003 | Rust crates are "(GPL-3.0 compatible)" (§16.5 heading) | i+t | Workspace `license = "GPL-3.0-or-later"` (rust/Cargo.toml:53); all locked deps permissive (Cargo.lock). License compliance is asserted by reuse tooling/CI packaging, not a dedicated unit test — graded i+t on repo policy evidence | high |
| R-10-004 | Nine `draft-lichen-*` I-Ds listed as project documents (§16.6; deliverables table, no RFC2119 keyword) | div | Only 3/9 exist, in `spec/drafts/` (not `docs/` as §16.1 tree claims): draft-lichen-link-01.md, draft-lichen-schc-lora-00.md, draft-lichen-rpl-lora-00.md; missing: addr, security, lci, senml, apps, border; 2 unlisted drafts exist (schnorr-00, ota-00). Flagged F-1 | high |
| R-10-005 | TX stores public-key identity, last reserved Origin Sequence, and complete last signed DAO bytes in a crash-safe record (§16.7) | i+t | Rust: `DaoTxState{public_key, last_reserved, last_signed_dao}` rust/lichen-rpl/src/persistence.rs:139-147, commit path :305-344; C: identical layout documented `rpl_dao_tx_persist.h:10-17` + `struct lichen_rpl_dao_tx_state` :78-87, wired via `reserve_origin_sequence` rpl_dao_build.c:161-180; tests `lichen/tests/rpl_dao_tx_persist/` + `rpl_dao_sequence` (bead project-LICHEN-worker6-b7z9.11 closed with suites green); Python: `TxState(sequence, dao_bytes)` python/src/lichen/rpl/dao_persistence.py:73-78 + tests `python/tests/rpl/test_dao_persistence.py`. Python nuance: TxState does not carry the pubkey explicitly — binding is indirect via restore-time origin validation (dao_manager.py:382) vs Rust/C explicit key binding. Flagged F-9 (Python sub-detail) | high |
| R-10-006 | On reboot the API exposes those exact stored bytes for retransmission; it does not reconstruct or re-sign them (§16.7) | i+t | Rust: `DaoTxState::last_signed_dao()` returns stored slice verbatim (persistence.rs:264-266); no re-sign code path exists. C: `lichen_rpl_dao_tx_open` copies exact signed bytes into state (rpl_dao_tx_persist.h:107-117); tests `lichen/tests/rpl_dao_tx_persist/`. Python: `last_dao_bytes()` retransmission API (dao_manager.py:401) fed by `load_tx_state()` restore (:316-351); tests `python/tests/rpl/test_dao_tx_scheduler.py` | high |
| R-10-007 | RX stores only the public key, accepted high-water sequence, and digest of the complete signed DAO; does not persist the complete received DAO or route table (§16.7) | div (C) | Rust: per-pubkey map `(pubkey → (sha256, seq))` persisted via `encode_high_water` + `update_redundant` — rust/lichen-rpl/src/routing.rs:710-730; record carries no route table; test dao_origin_vectors.rs:262-310. Python: `RxFloor(sequence, digest)` keyed by pubkey + checksummed RX catalog (dao_persistence.py:81-86, 148-238); tests `test_dao_persistence.py`. C: no RX-side floor persistence anywhere — `rg rx_floor\|dao_rx\|origin_high_water` over `lichen/subsys/lichen/rpl/` → 0 hits; RX floor lives in volatile `root_state` (rpl_dao_process.c); only TX state is NV (rpl_dao_tx_persist.c). Prior sweep row R-06-010 (06-security-part1) reached the same conclusion but pointed at bead b7z9.11, which has since CLOSED claiming implementation — its close reason covers TX machinery only. New bead filed (see gaps) | high |
| R-10-008 | For a fresh receive, persist the RX floor before exposing the route or returning success; then apply the fully validated route proposal atomically in memory (§16.7) | div (C) | Rust: persist-then-apply — `update_redundant` (routing.rs:722-730) precedes `*self = proposed` (:731); storage failure → `DaoHandlingOutcome::Persistence`, route absent, snapshot unchanged (test `unavailable_replay_storage_leaves_dao_state_unchanged`, dao_origin_vectors.rs:262-310). Python: `store_rx_floor` before in-memory update (dao_manager.py:1103-1145, "Update in-memory state only after successful persistence" :1143). C: RX path keeps floor volatile (rpl_dao_process.c — no hal_storage calls on RX path), so the ordering requirement is unmet in C | high |
| R-10-009 | Equal-sequence/equal-digest retransmission does not rewrite persistence; may repeat semantic parsing and exact self-Target validation to idempotently reconstruct the missing route (§16.7) | i+t | Rust: equal-seq exact retransmission is idempotent, no state change (dao_origin.rs:291-306); duplicate path returns before persistence write (routing.rs:705-708); 52-vector matrix re-drives prior signed DAO → `Duplicate` (dao_origin_vectors.rs:239-255). C: equal-seq exact → success without floor rewrite, comment cites spec + "Matches Rust" (rpl_dao_process.c:258-261). Python: fresh-only floor commit — "a fresh DAO ... MUST NOT rewrite the replay floor. Only commit for fresh DAOs" (dao_manager.py:1091-1128) | high |
| R-10-010 | MUST: implementations MUST snapshot the complete route, replay-floor, and storage state around rejected DAOs to test that no partial mutation occurs (§16.7) | i+t (Rust, Py) | Rust: storage/route snapshots around rejected DAOs across 52 vectors + storage-snapshot equality on rejection (dao_origin_vectors.rs:200-258) and injected write failure (:278-295). Python: no-mutation comment + fail-closed persistence gating (dao_manager.py:941, 852-868); test_dao_origin.py rejection matrix. **C: test-side route/storage snapshot assertions around rejected DAOs not located** (rpl_dao_auth/rpl_routing suites assert accept/reject outcomes, not snapshots) — flagged F-5 | low (C half unverified) |
| R-10-011 | MUST: all implementations MUST emit diagnostic log lines in logfmt (space-separated key=value; strings with spaces quoted) on the packet processing path (§16.8) | n-i (all) | Repo-wide grep `logfmt` → only spec/10 itself. No stack emits key=value logfmt baseline: Rust gateway/cli use `tracing_subscriber::fmt()` default human format (lichend.rs:48-49, cli/main.rs:151); C uses freeform `LOG_*` (e.g. coap_msg.c:433 "Applied receipt id=%..."); Python packet path uses stdlib `logging` prose messages (node.py:104, 915). Flagged F-2; gap bead filed | high |
| R-10-012 | Implementations MAY additionally emit JSON Lines to structured sinks (§16.8, MAY) | i | Python sim components configure structlog (sim/batch.py:383-384, sim/server.py:442-443); Rust tracing-subscriber json feature available but not wired. MAY — never filed | high |
| R-10-013 | MUST: every log line includes `ts`, `level`, `layer`, `event` (§16.8.1) | n-i (all) | No `layer=`/`event=` fields emitted anywhere: grep `event=` over lichen/ → 0 code hits; python messages are prose with occasional `pkt_id=%d` embedded (node.py:915); rust tracing macros carry no layer/event fields. Gap bead (with R-10-011) | high |
| R-10-014 | MUST: `pkt_id` present on all lines in the packet processing path (§16.8.1) | div (Py only) | Python: pkt_id threaded through packet-path logs (node.py:915, 931, 1047-1163, 1419-1428; tx_queue.py:419-621; link_layer.py:1770). Rust: repo-wide grep `pkt_id` in rust/ → 0 matches. C: 0 matches in lichen/. Gap bead | high |
| R-10-015 | Standard field names/types per 16.8.1 table (ts float epoch ms, level, layer enum, pkt_id uint, event verbs, sender_iid, peer_iid, errno, reason, len, rssi) (§16.8.1) | n-i (all) | Table fields not emitted as structured keys in any stack (same evidence as R-10-011/013; python `len=%d` fragments inside prose are closest). Covered by the logfmt gap bead | high |
| R-10-016 | C/Zephyr: emit logfmt fields via LOG_DBG/LOG_INF/LOG_WRN/LOG_ERR; gate verbose pipeline logging behind CONFIG_LICHEN_DIAG_VERBOSE (§16.8.2) | div | LOG_* usage confirmed (drivers/lora/lr1110.c:76, subsys LOG_MODULE_REGISTER pattern) but format strings are freeform, not key=value; `CONFIG_LICHEN_DIAG_VERBOSE` does not exist anywhere (grep → spec only). Gap bead | high |
| R-10-017 | Rust: use tracing with structured spans (info_span!) on packet path; tracing-subscriber emits JSONL or logfmt; no_std lichen-node uses defmt with logfmt conventions (§16.8.2) | div | tracing + tracing-subscriber present in lichen-gateway/lichen-cli (Cargo.toml:53-54) but no `info_span!` anywhere (grep → 0); subscriber is default `fmt()` (lichend.rs:49), not logfmt/JSONL; defmt plumbing exists (lichen-node/Cargo.toml:37-47, scheduler.rs:29-31) but format strings carry no logfmt convention. Gap bead | high |
| R-10-018 | Python: structlog with bound loggers carrying pkt_id and layer; JSONL to sinks, logfmt to console (§16.8.2) | div | structlog confined to sim/radio components (sim/batch.py:21,383-384; sim/server.py:119,441-443; radio/sim_client.py:54); the packet path (node.py:104, link_layer.py:114, tx_queue.py:31, router.py:30) uses stdlib `logging.getLogger(__name__)` with pkt_id interpolated into message text — no bound context, no layer field. Gap bead | high |
| R-10-019 | Each node maintains a monotonic u32 counter (wrapping); new pkt_id assigned at link RX entry for received frames and at TX queue push for locally originated packets (§16.8.3) | i+t (Py); n-i (Rs, C) | Python: shared node-wide counter (link_layer.py:334-336, 1551-1554), RX assignment before auth stamping (link_layer.py:1701, 1730), TX push assignment incl. shared source (tx_queue.py:258-296, 412); test python/tests/link/test_tx_queue.py:209. Rust: 0 pkt_id matches; C: 0 matches. Gap bead | high |
| R-10-020 | pkt_id is local to the node and NOT transmitted on the wire (§16.8.3, MUST NOT) | i (Py; n/a Rs/C) | Python: pkt_id stamped post-authentication as local metadata via `object.__setattr__(received, "_authenticated_pkt_id", pkt_id)` (link_layer.py:1730) with `repr=False` and accessor property (frames.py:64, 136-138) — not part of frame serialization. Rust/C have no pkt_id at all (vacuously satisfied). No dedicated negative test — noted | high |
| R-10-021 | Forwarded packets receive a new pkt_id at the forwarding node; relationship SHOULD be logged as `event=forward in_pkt_id=<rx> pkt_id=<tx>` (§16.8.3, SHOULD) | div (Py partial) | Python logs `in_pkt_id=%d` on forward/relay (node.py:1104, 1163) and forwarded TX gets a fresh pkt_id at TX push (tx_queue.py:412), but not in the exact `event=forward in_pkt_id=<rx> pkt_id=<tx>` format; Rust/C none. SHOULD-gap folded into pkt_id gap bead (correlation is the documented feature it serves) | high |

## Descriptive content observations (non-normative; no MUST/SHOULD/MAY in these subsections)

- **§16.1 Repository tree** — largely stale vs. reality: rust/ contains all 9 listed
  crates (lichen-core/-link/-schc/-coap/-senml/-apps/-node/-gateway/-sim all exist in
  rust/Cargo.toml members) plus 12 unlisted ones; Zephyr code lives in `lichen/`
  (subsys/lichen/{link,coap,rpl,routing,oscore,schc,...}, NOT `zephyr/subsys/lichen_link/...`
  as the tree shows; root `zephyr/` is the upstream west checkout); no `riot/` dir;
  `test/` holds only `vectors/` (no interop/, hardware/ — interop tests live in
  lichen/tests/ + python/tests/); `tools/` has `wireshark/` not `wireshark-dissector/`,
  and no lichen-craft/ or lichen-keygen/ anywhere; `apps/` tree lives under rust/
  (lichen-cli, lichen-tui exist; no lichen-web found); samples/ has only `lora_ping`
  (not basic_node/sensor_node/border_router). Flagged F-7.
- **§16.2 hardware tables** — board support exists for seeed/heltec/lilygo/muzi/elecrow
  (`lichen/boards/`); RAK4631 + nucleo_wl55jc board confs present in samples. Descriptive.
- **§16.3 tier table** — Rust/Embassy tier exists (lichen-embassy, lichen-firmware/wio-e5
  built on Embassy); Zephyr tier exists; RIOT tier absent (matches §16.1 drift).
  Zephyr stack-usage table verified in use: CONFIG_NET_IPV6 (lichen/apps/gateway/prj.conf:12),
  CONFIG_COAP (:23-26), CONFIG_LORA (:8), CONFIG_BT (subsys/lichen/hal/hal_device.c:225),
  CONFIG_MBEDTLS (coap/coap_slot_coord.c:333); OSCORE is a custom C subsystem
  (lichen/subsys/lichen/oscore/) matching "Custom or port".
- **§16.4 memory budgets** — "~" estimates; verifying them requires real STM32WL builds;
  not graded. Flagged as out of scope for this sweep (no normative text beyond R-10-002).
- **§16.5 C libraries** — monocypher vendored and used pervasively
  (lichen/subsys/lichen/crypto/monocypher.c + includes across subsys). **libschc row is
  stale**: evaluated and rejected 2026-06-30 (RECONCILIATION.md `c0b` closed;
  `.beads/config_kv.json` records the evaluation — GPL dual-license OK but experimental,
  41.9 KiB text vs 6.2 KiB in-house schc.c). RIOT table: n/a (no riot/).
- **§16.5 Rust crate table** — heapless used ✓ (7 crates); **ed25519-dalek not used**
  (curve25519-dalek + in-repo `schnorr48` crate, Cargo.lock:687,3266); **aes-gcm not in
  the lock** (OSCORE via oscore-fork); **coap-lite not used** (hand-rolled lichen-coap);
  **smoltcp explicitly rejected** (lichen-ipv6/Cargo.toml:12 "ponytail: no smoltcp, no
  full IP stack"). License claims themselves are accurate. Flagged F-6.
- **Stale tracking references** — `bd show python-wdr`, `python-dqc`, `python-ypk`,
  `python-oae` (§16.2/§16.3) all resolve to "no issue found". Flagged F-8.

## Gap beads filed (2 of 3 are MUST-gaps; under the 10-bead cap)

1. `project-LICHEN-worker6-b7z9.133` — `[spec-gap][R-10-011]` logfmt structured-logging
   baseline absent in all three stacks (R-10-011, R-10-013, R-10-015, R-10-016,
   R-10-017, R-10-018).
2. `project-LICHEN-worker6-b7z9.134` — `[spec-gap][R-10-014]` pkt_id correlation IDs
   absent in Rust and C stacks (R-10-014, R-10-019, R-10-021).
3. `project-LICHEN-worker6-b7z9.135` — `[spec-gap][R-10-007]` C DAO RX replay floor
   not persisted before route exposure (R-10-007, R-10-008) — divergent.

Overflow: none (3 filed, cap 10). No MAY or SHOULD-only gaps filed; SHOULD R-10-021
omission folded into gap bead 2 (correlation feature), R-10-012 trivially available.
