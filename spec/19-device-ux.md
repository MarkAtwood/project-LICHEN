<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# 19. Device HMI Design Language ("the Face")

Status: NORMATIVE. This document is the arbiter of all on-device user
experience decisions for LICHEN hardware. Where it conflicts with older
prose, this document wins. Workers implement against it the same way they
implement against `spec/decisions.jsonl`.

**Escalation rule (the point of this document):** if this language does
not answer a question, apply the tiebreaker order in §12, choose, and
proceed. File a bead labeled `ux-default` recording the choice. Do not
ask a human for an aesthetic decision. Only SOS/safety semantics (§8)
may block on human input.

## 1. Position in the architecture

The phone is the GUI (spec 17, LCI). The device surface is the
**status, fallback, and emergency** interface — what a user gets when
there is no phone, or when the mesh itself is the emergency. Every
addition to the device UI must justify itself against that bar. The
default answer to "should the device do X?" is **no**.

## 2. Hardware tiers

| Tier | Hardware | Surface | Truth |
|------|----------|---------|-------|
| E (e-ink) | T-Echo 200×200 mono, 1 button, LEDs | Fixed screens, event-refreshed | Readable with power off |
| O (OLED) | Heltec SSD1306 128×64, 1 button | Fixed screens, cheap redraw | Glanceable in dark |
| H (headless) | RAK4631, T1000-E, R1 Neo | LED language only | ~0 cost |

A feature appears on tier E and O only if it is worth its power and its
pixels. A feature appears on tier H only if it is worth a blink.

## 3. Prime directive: one glance, one fact

Each screen displays **one primary fact**. Secondary facts may occupy a
fixed status bar (§5). If a design finds itself showing two competing
facts, it is two screens.

**No scrolling text. Ever.** On any tier. If it doesn't fit, it doesn't
belong on the device.

## 4. Interaction grammar

Buttons change *which fact is displayed*, not *selection among items*.
The device is a ring of screens plus an emergency path — not a menu
system. There is no select, no cursor, no list navigation.

**Normal use never requires a hold.** All everyday interaction is
single short presses. Holds are reserved for rare, consequential paths
only (SOS arming, factory reset) — if a design needs a hold for
anything else, it is wrong (§12 order 1).

**Dedicated buttons beat gestures.** Where hardware provides more than
one button, each gets one plain function — e.g. a second button is
SOS-dedicated and requires no hold at all. Multi-press "Vulcan" combos
(two buttons, simultaneous press, press-while-holding) are forbidden.

| Event | Meaning (universal, all screens) |
|-------|----------------------------------|
| short-press | next screen (ring advance) |
| dedicated SOS button (if present) | immediate SOS arming, no hold |
| press-and-hold ≥2s | SOS arming (§8), single-button hardware only |
| press-and-hold ≥5s | factory-reset path (guarded, §9) |

**Hold feedback is mandatory.** A hold longer than 500ms with no visible
response is a defect. All holds show immediate progress feedback:
- E tier: partial-refresh a filling indicator (corner box or bar) at
  ~250ms cadence during the hold — user-initiated redraw, exempt from
  the §6 event-only rule; on release before threshold, invert-clear
- O tier: same indicator, no cadence limit
- H tier: LED switches to a fast blink (4 Hz, 50%) at hold start;
  SOS pattern takes over if threshold reached

A hold that fails to show progress within 500ms of button-down is a bug
against this spec, priority 2.

Double-press is reserved and unused in v0.1. Do not invent overload
gestures; if Meshtastic already uses a gesture for a thing, stealing it
is permitted (§11).

Screens advance on press only — never on timers. Timers are for display
decay (screensaver, §6), not navigation.

## 5. Screen anatomy

- **Status bar** (fixed, top): battery, GPS state, message-waiting
  count. Same fields on every screen; a field that would not change
  across screens belongs here, not in screen bodies.
- **Body**: the one fact, in the largest readable weight the tier
  allows.
- No chrome: borders, titles, and scroll indicators are not used. The
  e-ink frame is already the border.

## 6. Power is a budget line item

Every screen update has a stated cost and a stated trigger. Event
triggers only — never periodic refresh.

| Tier | Update policy |
|------|---------------|
| E | Partial refresh per state change; full refresh only at boot and every N partials (per-display constant, spec in driver) |
| O | Redraw on change; screensaver to logo/blank after 60s unchanged |
| H | LED changes are events, not heartbeats |

A design that requires periodic redraw to feel alive is wrong at this
layer.

## 7. Mono styling tokens

The entire vocabulary is three tokens:

| Token | E-ink | OLED | Use |
|-------|-------|------|-----|
| `normal` | black-on-white | lit | body text |
| `inverse` | white-on-black | dark | the current fact's emphasis, alerts |
| `dim` | sparse dither | off pixels | status bar |

Semantic roles map only to these: `alert`→inverse, `header`→inverse,
`quiet`→dim. Any design needing a fourth token needs human eyes —
but per §12 it will not get them; it will get simplified.

## 8. SOS semantics (the exception to everything)

SOS is reachable in ≤1 interaction from every screen, from every tier
(including H: hold ≥2s on the button; the headless button is the
existing user button). SOS state:

- overrides all screens immediately (E/O) — inverse full-frame
- is indicated on H by a distinct fixed blink (§10)
- never auto-cancels; explicit cancel = same hold again + confirm screen
  (E/O only; H has no cancel, only timeout)
- rides the normal send path with priority — no special radio mode
  exists (matches spec 18)

**SOS semantics are the only questions that may block on a human.**

## 9. Reset and destructive paths

≥5s hold opens the reset screen (E/O), which requires an additional
hold-to-confirm (≥3s) — never a press. H tier has no reset gesture; the
reset path is the LCI or physical reflash.

## 10. LED language (tier H, and the LEDs on E/O)

Fixed table, rates in Hz, duty in %:

| State | Pattern |
|-------|---------|
| joined, idle | off (LEDs are not decorations) |
| joining | 0.5 Hz, 10% duty |
| message waiting | 0.25 Hz, 5% duty (subtle) |
| SOS active | 2 Hz, 50% duty, continuous |
| hold in progress | 4 Hz, 50% duty, until threshold reached |
| fault (any) | 1 Hz, 50% duty until cleared |

No other patterns exist. New patterns require amending this table, not
inventing at the driver.

## 11. Meshtastic compatibility rule

Our users are Meshtastic users (reflash population). Where a Meshtastic
convention exists and does not conflict with this language, **match it**
(§12 order 3): screen order, battery icon shapes, the feel of the
button. Where they conflict, this document wins and the divergence is
recorded in a `ux-default` bead.

## 12. Tiebreaker order (the "don't ask me" mechanism)

When this language is silent, choose by this order and record the choice
in a `ux-default` bead:

1. **Fewer states** — the option with fewer screens/steps/branches
2. **Less power** — the cheaper update path
3. **Meshtastic** — the option matching user muscle memory
4. **Fail toward less information** — ambiguity resolves to showing
   nothing, not something

If two options tie through all four, pick either and say so in the
bead. Proceeding is always correct; blocking is only correct for §8.

## 13. Strings

All display text comes from a single string table keyed by IDs. v0.1
ships English only; the table is the localization seam. No string
construction on-device beyond fixed formats (count, coordinates).

## 14. v0.1 screen inventory (initial ring, E and O)

Boot → Status → Position → Last message → (screensaver). Each screen's
data source is a CoAP resource already defined by spec 17/18 (status,
position, message presence). Anything beyond this inventory is a
`ux-default` bead and a later version.

## 15. Design traditions

Nothing in this language is novel at the component level. Each element
is borrowed from a context where it has been validated by millions of
users or decades of industrial practice:

| Element | Tradition | Source |
|---------|-----------|--------|
| Ring of screens, not a menu (§4) | Casio digital watch mode cycling | G-Shock, 1983–present; every digital watch since |
| Phone is GUI, device is status/fallback/emergency (§1) | Apple Watch design philosophy | WatchOS HIG: "glanceable, actionable, responsive" |
| One glance, one fact (§3) | Cockpit instrument design, Tufte | One gauge = one reading; Tufte, *Visual Display of Quantitative Information* |
| Holds for consequential actions only (§4) | Industrial safety HMI | IEC 60447: emergency stop requires sustained action |
| LEDs are not decorations / fixed state table (§10) | Embedded systems orthodoxy | Medical devices (IEC 62366), networking equipment, industrial controllers |
| Three styling tokens (§7) | Mono display design | Kindle, e-ink signage: black, white, gray — no fourth state |
| Event-driven, no periodic refresh (§6) | Embedded power management | Standard practice for battery-powered embedded since MSP430 era |
| Match existing muscle memory (§11) | Platform convention inheritance | Apple HIG, Material Design: don't surprise users who learned elsewhere |

**Corollary:** If you want a sophisticated app or UX — maps,
conversation threads, contact management, sensor dashboards, custom
alerts — the device is not your canvas. The device exposes its state
as CoAP resources (spec 11 LCI, spec 17 border router, spec 18
application). Connect a phone, tablet, or desktop over BLE or USB,
read the resources, and build whatever you want. The datafeed is
stable, documented, and observable (CoAP Observe). The device screen
is not.

**What is original to this document:**

1. **The tiebreaker order as an agent directive (§12).** "Don't ask a
   human for an aesthetic decision" is not found in conventional UX
   specs. The four-level decision procedure (fewer states → less power →
   Meshtastic → fail toward less info) is written specifically for AI
   agent implementors who would otherwise escalate every visual choice.

2. **The assembly.** No prior work combines watch interaction + glance
   philosophy + industrial LED tables + embedded power rules + incumbent
   muscle memory compatibility + agent-facing tiebreakers into a single
   document for a mesh radio. Each piece is boring and proven. The
   combination is specific to this problem.
