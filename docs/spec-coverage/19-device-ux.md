# spec/19-device-ux.md — coverage (sweep 2026-09-09)

Extraction of normative requirements from spec/19-device-ux.md (Device HMI
Design Language, "the Face"). Statuses: IT=implemented+tested,
IUT=implemented+untested, DIV=divergent, NI=not-implemented, AMB=ambiguous.
Evidence: file:line for code, test names for tests.

Step 0 result: no entry in `spec/decisions.jsonl` lists `19-device-ux.md`
in its `specs` array (rg over all 19 decisions: zero hits), so no
adjudicated-decision verify checks apply to this section.

Primary implementation site: `lichen/subsys/lichen/ux/` (button grammar +
LED language, pure engines + Zephyr backends, host tests
`lichen/tests/ux_button`, `lichen/tests/ux_led`, `lichen/tests/hmi_led` —
all three pass on this host, 2026-09-09). No Rust or Python device-UX code
exists; `python/src/lichen/dashboard/` is the LCI GUI (phone side, §1),
not the device surface.

| Req | Spec text (trimmed) | Status | Evidence | Confidence |
|---|---|---|---|---|
| R-19-001 | Escalation rule: unanswered questions resolved via §12 tiebreaker, choice recorded in a `ux-default` bead; never ask a human for aesthetic decisions; only SOS/safety (§8) may block | AMB | Process rule for implementers; no runtime artifact possible. `bd list`: zero beads labeled `ux-default` exist, i.e. the mechanism has never been exercised | high |
| R-19-002 | Device surface is status/fallback/emergency only; phone is the GUI (spec 17); default answer to "should the device do X" is no; every addition must justify against that bar | AMB | Design-gate policy, enforced by review not code. CoAP datafeed it gates on exists (R-19-042) | high |
| R-19-003 | Hardware tiers: E=T-Echo 200×200 e-ink, O=Heltec SSD1306 128×64, H=RAK4631/T1000-E/R1 Neo; feature appears per tier only if worth its power/pixels/blink | IUT | Board plumbing per tier: t_echo led0+button0 aliases + `CONFIG_LICHEN_HAS_DISPLAY=y` (lichen/boards/lilygo/t_echo/t_echo_nrf52840.dts:35,51,59; lichen/apps/puck/boards/t_echo_nrf52840.conf:6); r1_neo button0+led0 (lichen/boards/muzi/r1_neo/r1_neo_nrf52840.dts:44,52); heltec_v3 target exists but its puck conf enables no display; T1000-E dts has NO led0/button0 alias (lichen/boards/seeed/t1000_e/t1000_e_nrf52840.dts — zero led/button nodes) so §10 LED language is undriveable via HAL on that H-tier board. Build-time config, no test | high |
| R-19-004 | Each screen displays one primary fact; secondary facts only in the fixed status bar | NI | No screen rendering exists anywhere (rg display/SSD1306/eink/screen across lichen/, rust/, python/src: only HAL capability plumbing and dashboard LCI GUI) | high |
| R-19-005 | No scrolling text. Ever. On any tier | AMB | Vacuously conformant: no display layer exists to scroll; becomes checkable only when R-19-004 lands | high |
| R-19-006 | Buttons change which fact is displayed; device is a ring of screens, no menu/select/cursor/list navigation | NI | Engine emits `ADVANCE` (lichen/subsys/lichen/ux/ux_button_core.c:107) but zero consumers: `lichen_ux_button_start` is called only by its own backend and tests (rg across lichen/, rust/, python/src/) | high |
| R-19-007 | Normal use never requires a hold; all everyday interaction is single short presses; holds reserved for SOS arming and factory reset | IT | Engine: release <500ms → `ADVANCE` (ux_button_core.c:100-108); thresholds only at SOS 2000ms / reset 5000ms (ux_button.h:33-37); tests `test_short_press_advances_ring`, `test_very_short_press_is_advance`, `test_release_before_sos_cancels_hold` (lichen/tests/ux_button/main.c) | high |
| R-19-008 | Dedicated SOS button arms immediately, no hold; multi-press "Vulcan" combos forbidden | IT | `lichen_ux_button_sos_dedicated()` (ux_button_core.c:159-164); test `test_dedicated_sos_is_immediate`. Note: no second-button GPIO backend — `lichen_hal_button_get` exposes one button (lichen/subsys/lichen/hal/include/lichen/hal.h:322), no board defines a second SOS button, so the dedicated path is currently unreachable on real hardware | high |
| R-19-009 | Universal event table: short-press=next screen; dedicated SOS=immediate arming; hold ≥2s=SOS arming (single-button only); hold ≥5s=factory-reset path | IT | Thresholds pinned: `LICHEN_UX_BUTTON_SOS_HOLD_MS 2000`, `RESET_HOLD_MS 5000`, `FEEDBACK_MS 500` (lichen/subsys/lichen/ux/include/lichen/ux_button.h:31-37); tests `test_hold_2s_arms_sos_and_led_takes_over`, `test_hold_5s_opens_reset_path`, `test_dedicated_sos_is_immediate`. "next screen" consumer absent (R-19-006) | high |
| R-19-010 | Hold feedback mandatory: E tier partial-refresh filling indicator at ~250ms cadence during hold (exempt from §6 event-only rule); invert-clear on early release | NI | No E-tier display driver exists (HAL exposes capability probe + device-get only, lichen/subsys/lichen/hal/include/lichen/hal.h:309-316; no rendering code) | high |
| R-19-011 | O tier hold feedback: same indicator, no cadence limit | NI | Same as R-19-010 — no display layer | high |
| R-19-012 | H tier hold feedback: LED fast blink 4Hz/50% at hold start; SOS pattern takes over if threshold reached | IT | `HOLD_START` at 500ms → `LED_HOLD` → backend maps to `LICHEN_UX_LED_HOLD_IN_PROGRESS` (ux_button_core.c:132-136; ux_button_zephyr.c:50-57); 4Hz table row = 250ms period/125ms on (ux_led_core.c:36); tests `test_hold_feedback_within_500ms`, `test_hold_2s_arms_sos_and_led_takes_over`, ux_led measurement tests pin exact period/on-times. Zephyr GPIO backend itself untested (host tests cover the pure engines only) | high |
| R-19-013 | A hold showing no progress within 500ms of button-down is a priority-2 bug | IT | Guarantee enforced by engine: `LICHEN_UX_BUTTON_FEEDBACK_MS 500` + poll cadence 50ms (ux_button_zephyr.c:30); test `test_hold_feedback_within_500ms` pins none-before/exists-at boundary. Triage priority is process | high |
| R-19-014 | Double-press reserved and unused in v0.1; do not invent overload gestures | AMB | Vacuously conformant: no double-press handling exists in any tier's code; nothing to violate until features are added | high |
| R-19-015 | Screens advance on press only — never on timers; timers are for display decay, not navigation | AMB | Vacuously conformant: no screens/timers exist. Negative constraint; enforce when R-19-004 lands | high |
| R-19-016 | Status bar (fixed, top): battery, GPS state, message-waiting count; same fields on every screen | NI | No status-bar or screen rendering exists; data sources for its fields do exist (battery/GNSS caps via HAL, `/msg/inbox` unread count per spec 17 coverage) | high |
| R-19-017 | Body = the one fact, in the largest readable weight the tier allows | NI | No rendering layer | high |
| R-19-018 | No chrome: borders, titles, scroll indicators are not used | AMB | Vacuous — no rendering layer to violate | high |
| R-19-019 | Every screen update has a stated cost and trigger; event-triggered only, never periodic refresh | NI | No screen updates exist; policy gate for R-19-004 work | high |
| R-19-020 | E tier update policy: partial refresh per state change; full refresh only at boot and every N partials (per-display constant, spec in driver) | NI | No e-ink driver; T-Echo display capability flag only (t_echo conf:31,127) | high |
| R-19-021 | O tier update policy: redraw on change; screensaver to logo/blank after 60s unchanged | NI | No OLED driver; no 60s screensaver timer anywhere (rg screensaver: zero code hits) | high |
| R-19-022 | H tier: LED changes are events, not heartbeats | DIV | State *transitions* are event-driven (`lichen_ux_led_state_set`, callers: only ux_button_zephyr.c:56,62,66). But the Zephyr backend wakes every 16ms to re-evaluate the pattern even when steady (joined-idle off included): `UX_LED_TICK_MS 16` + unconditional `k_work_reschedule` (lichen/subsys/lichen/ux/ux_led_zephyr.c:25,36-42) — a permanent 62.5Hz system-workqueue heartbeat with battery cost, not edge-aligned. Also nothing drives state from device state (R-19-026) | low |
| R-19-023 | Three styling tokens only (normal/inverse/dim); semantic roles map only to these; a fourth token gets simplified per §12 | NI | No rendering layer; no token vocabulary anywhere | high |
| R-19-024 | SOS reachable in ≤1 interaction from every screen, from every tier (H: hold ≥2s on the existing user button) | IT | Arming gesture engine-side: hold≥2s → `SOS_ARM` (ux_button_core.c:146-153), dedicated button immediate (ux_button_core.c:159-164); tests `test_hold_2s_arms_sos_and_led_takes_over`, `test_dedicated_sos_is_immediate`. "From every screen" vacuous (no screens); end-to-end arm→alert NI (R-19-025) | high |
| R-19-025 | SOS arming rides the normal send path with priority — no special radio mode exists (matches spec 18) | DIV | Two halves. Send-path priority: IT — `TX_PRIORITY_SOS=0` highest with preemption (lichen/subsys/lichen/link/include/lichen/tx_queue.h:61; lichen/tests/tx_queue/main.c:156,469-474 pins vs test/vectors/tx_queue_priority.json; python/src/lichen/link/tx_queue.py:64 + python/tests/link/test_tx_queue.py). Arming→send: NI — nothing consumes `SOS_ARM`/`SOS_DEDICATED` to enqueue an SOS alert (consumers rg: zero); spec-18 sender pieces exist (sos_alert.c CBOR, sos_origin.c Schnorr48, vectors sos_cbor.json/sos_signature.json) but are unwired to the button. Rust link layer has no TX queue at all (precedence.rs is time-source policy) | high |
| R-19-026 | SOS state overrides all screens immediately (E/O) — inverse full-frame | NI | No screens, no SOS device-state machine; only wire-level SOS exists (coap/sos_alert.c encodes `cancel` type per spec 18.4.2) | high |
| R-19-027 | SOS state indicated on H by a distinct fixed blink (§10: 2Hz, 50%, continuous) | IT | `LICHEN_UX_LED_SOS_ACTIVE` = 500ms period/250ms on (ux_led_core.c:35), asserted by hold threshold and dedicated press (ux_button_zephyr.c:58-63); tests pin pattern exactness (lichen/tests/ux_led/main.c measure/count helpers; lichen/tests/hmi_led/main.c test_table_matches_spec). Caveat: nothing ever *clears* or re-asserts the state from the SOS lifecycle — the LED stays on SOS until reboot; see R-19-028/029 | high |
| R-19-028 | SOS never auto-cancels; explicit cancel = same hold again + confirm screen (E/O only) | NI | No cancel flow: SOS_ARM re-entry, confirm screen, and `cancel`-type device linkage all absent (rg sos in lichen/: wire-format modules only); Zephyr backend intentionally keeps LED ownership across presses (ux_button_zephyr.c:58-63) but no second-hold handler exists | high |
| R-19-029 | H tier has no SOS cancel — only timeout | AMB | Timeout value unspecified in spec (§8 gives no number); no timeout implemented anywhere. Per §8, SOS semantics may block on human — filed as flagged, not auto-resolved | low |
| R-19-031 | SOS semantics are the only questions that may block on a human | AMB | Process rule; consistent with R-19-029 being the sole human-blocking item. (R-19-030 numbering retired: folded into R-19-024/R-19-025) | high |
| R-19-032 | ≥5s hold opens the reset screen (E/O), which requires an additional hold-to-confirm (≥3s) — never a press | DIV | `RESET_PATH` event at 5000ms IT (ux_button_core.c:140-144, release-confirm :84-87; tests `test_hold_5s_opens_reset_path`, `test_reset_outranks_sos`). Reset screen and the ≥3s hold-to-confirm (vs a plain press) are NI — no consumer of `RESET_PATH` exists, no reset screen exists | high |
| R-19-033 | H tier has no reset gesture; the reset path is the LCI or physical reflash | AMB | Engine emits `RESET_PATH` tier-agnostically (single code path, no tier/capability gate, ux_button_core.c:140-153); nothing consumes it today so no H reset gesture is user-visible, but a future consumer MUST gate on tier or H silently gains a reset gesture the spec forbids. LCI reset resource: none found (rg factory-reset|/reset in coap server + gateway: zero) — LCI reset path itself absent | low |
| R-19-034 | LED language: fixed 6-state table, rates in Hz, duty in %, exactly as §10 table | IT | `patterns[]` = spec exact: 2000/200, 4000/200, 500/250, 250/125, 1000/500 ms (lichen/subsys/lichen/ux/ux_led_core.c:31-38); test measures first-on window and period per state (lichen/tests/ux_led/main.c); hmi_led conformance test restates table from Hz+duty (lichen/tests/hmi_led/main.c). NOTE duplicate engine: `lichen/subsys/lichen/hmi/hmi_led.c` implements the identical table as `ux_led_core.c` — see DIV row R-19-035b | high |
| R-19-035 | Closed table: no other patterns exist; new patterns require amending the table, not inventing at the driver | IT | Enum closed at `LICHEN_UX_LED_STATE_COUNT=6`; out-of-range states ignored (ux_led_core.c:40-44,55-63); test pins the six-state set (lichen/tests/ux_led/main.c) | high |
| R-19-035b | — (duplication finding, not a spec req): two independent §10 table implementations | DIV | `lichen/subsys/lichen/hmi/hmi_led.c` (`LICHEN_HMI_LED_*`, Kconfig `LICHEN_HMI_LED`) duplicates `ux_led_core.c` (`LICHEN_UX_LED_*`, Kconfig `LICHEN_UX_LED`) with identical tables, both cited to spec 19 §10, both tested; hmi has no GPIO backend and no consumer, ux has the Zephyr backend used only by the button hold path. Drift risk against the closed-table rule (R-19-035) | high |
| R-19-036 | LED reflects device state: joined-idle off, joining 0.5Hz/10%, message-waiting 0.25Hz/5%, fault 1Hz/50% until cleared | NI | States exist and are tested in isolation, but nothing maps device state to LED state: `lichen_ux_led_state_set` is called only from ux_button_zephyr.c (hold/SOS); zero callers set JOINING/MESSAGE_WAITING/FAULT (rg: only tests + engine internals). JOINING (RPL join status), MESSAGE_WAITING (msg store unread), FAULT (diag) integrations absent | high |
| R-19-037 | Match Meshtastic conventions where no conflict (screen order, battery icon shapes, button feel); conflicts recorded in a `ux-default` bead | AMB | No device UI exists to match conventions against; zero `ux-default` beads; meshtastic_adapter is protocol-compat (gateway), not UI muscle memory | low |
| R-19-038 | Tiebreaker order when language is silent: fewer states → less power → Meshtastic → fail toward less information; record choice in a `ux-default` bead; proceed, don't block (except §8) | AMB | Process rule; never exercised (zero ux-default beads) | high |
| R-19-039 | All display text from a single string table keyed by IDs; v0.1 English only; table is the localization seam; no on-device string construction beyond fixed formats | NI | No string table, no display text anywhere (rg string_table/STR_: only wire-format key arrays in coap CBOR encoders, unrelated) | high |
| R-19-040 | v0.1 screen inventory (initial ring, E and O): Boot → Status → Position → Last message → screensaver; each screen's data source is a CoAP resource from spec 17/18 | NI | Screen layer NI (no display code). Data sources IT: /status (lichen/apps/gateway/src/status_cbor.c; covered in 11-lci matrix), position (/sensors/location SenML — 12-apps matrix R-12-037 IT), message presence (/msg/inbox unread — R-12-006 IT) | high |
| R-19-041 | Anything beyond the v0.1 inventory is a `ux-default` bead and a later version | AMB | Process rule; nothing beyond inventory exists (vacuous) | high |
| R-19-042 | Corollary: device exposes state as CoAP resources; connect phone/tablet/desktop over BLE or USB, read resources, build anything; datafeed stable, documented, observable (CoAP Observe); device screen is not the canvas | IT | LCI implemented per spec 17 coverage (docs/spec-coverage/11-lci.md): BLE LCI ingress (lichen/apps/gateway/src/ble_lci_netif.c), CoAP Observe across resources (e.g. coap_msg observe tests R-12-006), SLIP/BLE transports (lichen/subsys/lichen/transport/) | high |

## Classification histogram

| Status | Count |
|---|---|
| IT (implemented+tested) | 10 (R-19-007, 008, 009, 012, 013, 024, 027, 034, 035, 042) |
| IUT (implemented+untested) | 1 (R-19-003) |
| DIV (divergent) | 4 (R-19-022, 025, 032, 035b) |
| NI (not-implemented) | 15 (R-19-004, 006, 010, 011, 016, 017, 019, 020, 021, 023, 026, 028, 036, 039, 040) |
| AMB (ambiguous/vacuous/process) | 12 (R-19-001, 002, 005, 014, 015, 018, 029, 031, 033, 037, 038, 041) |
| Total rows | 42 (R-19-030 numbering retired — folded into R-19-024/R-19-025) |

Note: R-19-040 splits — screens NI, but its data sources are all IT under
spec 17/18 coverage (11-lci.md, 12-apps.md). R-19-025 is DIV because the
priority send path (spec 18) is implemented+tested while the arming→send
wiring is absent.

## Gap beads

8 filed under epic project-LICHEN-worker6-b7z9, labels `ux`+`spec-gap`
(see `19-device-ux-flagged.md` for the cross-listing). Overflow count: 0
(MUST-gaps fit under the 10 cap by grouping shared work items:
screen-ring/display policies and §13 strings are separate deliverables;
the remaining MUST-gaps each got a bead).

## Notes for Opus / reviewers

- The two duplicate LED engines (R-19-035b) are the section's only
  structural divergence risk: both claim spec 19 §10 and both are tested;
  any §10 amendment must land in both or one must go.
- T1000-E (§2 H tier) lacks a `led0` DTS alias, so the §10 language cannot
  drive it via `lichen_hal_led_get` — its only LED work today is the raw
  P0.24 boot blink in `lichen/lib/native/native.c`. This is silent (the
  backend degrades to a no-op by design).
- `lichen/apps/puck/prj.conf` and all app prj.confs select neither
  `LICHEN_UX_*` nor `LICHEN_HMI_LED` explicitly; both default y via Kconfig,
  so the engines compile into puck/gateway but are never started or
  consumed there (dead at runtime despite compiling).