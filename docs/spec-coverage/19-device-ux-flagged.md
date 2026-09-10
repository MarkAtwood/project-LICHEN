# spec/19-device-ux.md — flagged set (sweep 2026-09-09)

Flagged per protocol: (a) low confidence, (b) ambiguous or divergent
classification, or (c) oscore/EDHOC semantics (none in this section).
Full matrix: `docs/spec-coverage/19-device-ux.md`.
Gap beads: project-LICHEN-worker6-b7z9.165–172.

## Divergent classifications

### R-19-022 — H tier: LED changes are events, not heartbeats (§6/§2)
- Classification: **DIV** (confidence low)
- Evidence: state transitions are event-driven (`lichen_ux_led_state_set`,
  callers only in ux_button_zephyr.c:56,62,66), but the Zephyr backend
  unconditionally reschedules a 16ms evaluation tick forever
  (lichen/subsys/lichen/ux/ux_led_zephyr.c:25,36-42) — 62.5 system-workqueue
  wakeups/sec even in joined-idle off, on battery mesh hardware whose tier-H
  truth is "~0 cost". Filed as b7z9.170 (edge-aligned tick upgrade).
- Question for Opus: is a fixed evaluation tick acceptable as "pattern
  rendering" (the blink itself is inherently periodic), or does the spec's
  event-only rule require edge-aligned scheduling? Is the 16ms constant vs
  ~15ms worst-case edge error the right granularity either way?

### R-19-025 — SOS rides the normal send path with priority, no special radio mode (§8)
- Classification: **DIV** (confidence high)
- Evidence: send-path priority is implemented+tested (`TX_PRIORITY_SOS=0`,
  lichen/subsys/lichen/link/include/lichen/tx_queue.h:61;
  lichen/tests/tx_queue/main.c:156,469-474 vs test/vectors/tx_queue_priority.json;
  python tx_queue.py + tests), but arming→send is not wired: zero consumers of
  `SOS_ARM`/`SOS_DEDICATED`. Spec-18 sender pieces (sos_alert.c, sos_origin.c,
  sos_ratelimit.c, vectors) exist unwired. Filed as b7z9.168.
- Question for Opus: confirm the split classification (priority send path IT,
  arm→send NI) rather than treating the whole requirement as one gap; and
  whether the Rust link layer (no TX queue at all) needs a spec-19-driven
  SOS send path or the C path is the sole conformance reference.

### R-19-032 — ≥5s hold opens reset screen with ≥3s hold-to-confirm (§9)
- Classification: **DIV** (confidence high)
- Evidence: `RESET_PATH` event at 5000ms implemented+tested
  (ux_button_core.c:140-153, release-confirm :84-87; tests
  test_hold_5s_opens_reset_path, test_reset_outranks_sos) — but no reset
  screen, no ≥3s hold-to-confirm, no consumer of the event. Filed as
  b7z9.172 (reset bead).
- Question for Opus: confirm the event/engine half satisfies the MUST only
  together with the confirm screen (i.e. the requirement is still open), and
  that the ≥3s confirm hold should reuse the button engine's hold machinery
  (a second hold on the same button, per "never a press").

### R-19-035b — duplicate §10 LED table implementations (structural finding)
- Classification: **DIV** (confidence high)
- Evidence: `lichen/subsys/lichen/hmi/hmi_led.c` (LICHEN_HMI_LED_*) and
  `lichen/subsys/lichen/ux/ux_led_core.c` (LICHEN_UX_LED_*) implement the
  identical closed table, both citing spec 19 §10, both tested
  (lichen/tests/hmi_led, lichen/tests/ux_led). hmi has no backend/consumer;
  ux has the GPIO backend used by the button hold path. Tables verified
  identical at sweep time. Filed as b7z9.171.
- Question for Opus: which engine is canonical? Recommendation in the bead is
  consolidate on ux (has backend + integration) and retire hmi; verify no
  external consumer of LICHEN_HMI_LED_* exists before deprecation.

## Ambiguous classifications

### R-19-029 — H tier SOS has no cancel, only timeout (§8)
- Classification: **AMB** (confidence low)
- Evidence: no timeout implemented anywhere; the spec gives no timeout value.
  Per §8, SOS semantics may block on a human — this is the one flagged item
  where human input is spec-sanctioned. Filed inside b7z9.169.
- Question for Opus: what is the H-tier SOS timeout value (and does expiry
  restore the pre-SOS LED state or go to joined-idle off)? Needs a human or a
  §12-recorded ux-default bead — Opus should say which.

### R-19-033 — H tier has no reset gesture; reset path is LCI or physical reflash (§9)
- Classification: **AMB** (confidence low)
- Evidence: engine emits `RESET_PATH` tier-agnostically (ux_button_core.c
  single code path, no capability gate); no consumer today so no user-visible
  H reset gesture exists, but nothing *prevents* one. Additionally the LCI
  reset resource the spec names is absent (rg factory-reset|/reset across coap
  server + gateway: zero hits).
- Question for Opus: should the tier gate live in the engine (e.g. a
  capability flag suppressing RESET_PATH on headless targets) or is
  consumer-side gating sufficient? And should the LCI reset resource be filed
  under spec 17 coverage instead?

### R-19-037 — match Meshtastic conventions where no conflict (§11)
- Classification: **AMB** (confidence low)
- Evidence: no device UI exists to match conventions against; zero
  `ux-default` beads filed repo-wide; meshtastic_adapter is protocol
  compatibility, not UI muscle memory.
- Question for Opus: should the Meshtastic-conformance check be a deferred
  acceptance criterion on the screen-ring bead (b7z9.165), or is §11 purely a
  per-decision rule exercised via ux-default beads at design time?

### R-19-001, R-19-002, R-19-031, R-19-038 — process directives (§header, §1, §8, §12)
- Classification: **AMB** (confidence high that they are process rules)
- Evidence: implementer-facing rules (tiebreakers, ux-default beads, no-human
  aesthetic escalation); no runtime artifact can implement them. Zero
  `ux-default` beads exist, so the mechanism has never been exercised.
- Question for Opus: confirm these belong in the coverage matrix as AMB
  process rows (no code conformance possible) rather than being excluded from
  requirement extraction entirely.

### R-19-005, R-19-014, R-19-015, R-19-018, R-19-041 — vacuous negative constraints (§3, §4, §5, §14)
- Classification: **AMB** (confidence high)
- Evidence: "no scrolling text", "double-press reserved", "advance on press
  only", "no chrome", "nothing beyond inventory" — all true today only
  because no display layer exists (R-19-004 gap, b7z9.165). They become
  checkable only when screens land.
- Question for Opus: confirm vacuous conformance is acceptable now, and that
  these should be re-swept as acceptance criteria against the screen-ring
  implementation when it lands.

### R-19-029 companion — R-19-026/028 SOS screen-override and cancel (§8)
- Classification: NI (confidence high), listed here because the confirm-screen
  cancel flow is E/O-only and §8 is the human-blocking carve-out.
- Question for Opus: none beyond the R-19-029 timeout decision above; the
  override/cancel flows are unambiguous NI tracked in b7z9.169.