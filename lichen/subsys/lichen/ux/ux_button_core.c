/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ux_button_core.c
 * @brief Spec 19 §4/§8/§9 button interaction engine — pure, host-testable.
 *
 * All normative thresholds and the hold/SOS/reset grammar live here. The
 * caller feeds debounced edges (feed) and ticks (poll); the engine emits
 * events and the H-tier LED override. No GPIO, no side effects.
 *
 * Invariants:
 *  - Each press produces at most one HOLD_START, and each threshold (SOS at
 *    2 s, reset at 5 s) emits at most once during the hold; release confirms
 *    the highest armed outcome exactly once (a long hold can therefore emit
 *    both SOS_ARM at the 2 s poll and RESET_PATH at the 5 s poll, with the
 *    release confirming the reset).
 *  - A threshold crossed during the hold emits the event and switches the
 *    LED in the same step (§4: "SOS pattern takes over if threshold
 *    reached").
 *  - RESET outranks SOS: once the reset path is open, SOS cannot arm.
 */

#include <lichen/ux_button.h>

#include <stddef.h>

static struct lichen_ux_button_step step(enum lichen_ux_button_event event,
					 enum lichen_ux_button_led led)
{
	struct lichen_ux_button_step s;

	s.event = event;
	s.led = led;
	return s;
}

void lichen_ux_button_init(struct lichen_ux_button *btn)
{
	if (btn == NULL) {
		return;
	}
	btn->pressed = false;
	btn->down_since_ms = 0U;
	btn->feedback_sent = false;
	btn->sos_armed = false;
	btn->reset_path = false;
}

struct lichen_ux_button_step lichen_ux_button_feed(
	struct lichen_ux_button *btn, bool pressed, uint64_t now_ms)
{
	if (btn == NULL) {
		return step(LICHEN_UX_BUTTON_EVT_NONE, LICHEN_UX_BUTTON_LED_NONE);
	}

	if (pressed && !btn->pressed) {
		/* Button-down edge: begin the hold window. */
		btn->pressed = true;
		btn->down_since_ms = now_ms;
		btn->feedback_sent = false;
		btn->sos_armed = false;
		btn->reset_path = false;
		return step(LICHEN_UX_BUTTON_EVT_NONE, LICHEN_UX_BUTTON_LED_NONE);
	}

	if (!pressed && btn->pressed) {
		/* Release edge: classify the completed press. A threshold
		 * crossed during the hold already emitted its event and armed
		 * the flag; the release confirms that outcome exactly once
		 * (consuming the flag) so the consumer's commit/arm happens on
		 * release. A release that crosses a threshold without a prior
		 * poll (no tick between button-down and release) emits the
		 * event here for the first time. */
		uint64_t held_ms = 0U;

		if (now_ms >= btn->down_since_ms) {
			held_ms = now_ms - btn->down_since_ms;
		} /* else clock skew: treat elapsed as 0, never a spurious reset */
		enum lichen_ux_button_event evt;
		enum lichen_ux_button_led led;

		btn->pressed = false;
		if (btn->reset_path) {
			evt = LICHEN_UX_BUTTON_EVT_RESET_PATH;
			led = LICHEN_UX_BUTTON_LED_RESTORE;
			btn->reset_path = false;
		} else if (btn->sos_armed) {
			/* §4/§8: SOS consumes the press; the LED stays on the
			 * SOS pattern (§10), which the §8 cancel flow owns. */
			evt = LICHEN_UX_BUTTON_EVT_SOS_ARM;
			led = LICHEN_UX_BUTTON_LED_SOS;
			btn->sos_armed = false;
		} else if (held_ms >= LICHEN_UX_BUTTON_RESET_HOLD_MS) {
			evt = LICHEN_UX_BUTTON_EVT_RESET_PATH;
			led = LICHEN_UX_BUTTON_LED_RESTORE;
		} else if (held_ms >= LICHEN_UX_BUTTON_SOS_HOLD_MS) {
			evt = LICHEN_UX_BUTTON_EVT_SOS_ARM;
			led = LICHEN_UX_BUTTON_LED_SOS;
		} else if (btn->feedback_sent) {
			/* Released after feedback but before SOS: cancel the
			 * hold indicator and hand the LED back. */
			evt = LICHEN_UX_BUTTON_EVT_HOLD_CANCEL;
			led = LICHEN_UX_BUTTON_LED_RESTORE;
		} else {
			/* Short press: advance the ring (§4). */
			evt = LICHEN_UX_BUTTON_EVT_ADVANCE;
			led = LICHEN_UX_BUTTON_LED_NONE;
		}
		btn->feedback_sent = false;
		return step(evt, led);
	}

	/* No edge: nothing to do. */
	return step(LICHEN_UX_BUTTON_EVT_NONE, LICHEN_UX_BUTTON_LED_NONE);
}

struct lichen_ux_button_step lichen_ux_button_poll(
	struct lichen_ux_button *btn, uint64_t now_ms)
{
	if (btn == NULL || !btn->pressed) {
		return step(LICHEN_UX_BUTTON_EVT_NONE, LICHEN_UX_BUTTON_LED_NONE);
	}

	uint64_t held_ms = 0U;

	if (now_ms >= btn->down_since_ms) {
		held_ms = now_ms - btn->down_since_ms;
	} /* else clock skew: treat elapsed as 0, never a spurious threshold */

	/* §4: hold feedback must be visible within 500 ms of button-down. */
	if (!btn->feedback_sent && held_ms >= LICHEN_UX_BUTTON_FEEDBACK_MS) {
		btn->feedback_sent = true;
		return step(LICHEN_UX_BUTTON_EVT_HOLD_START,
			    LICHEN_UX_BUTTON_LED_HOLD);
	}

	/* §9: ≥5 s opens the factory-reset path. Reset outranks SOS, so once
	 * the reset path opens the SOS arm is closed off for this press. */
	if (!btn->reset_path && held_ms >= LICHEN_UX_BUTTON_RESET_HOLD_MS) {
		btn->reset_path = true;
		return step(LICHEN_UX_BUTTON_EVT_RESET_PATH,
			    LICHEN_UX_BUTTON_LED_HOLD);
	}

	/* §4/§8: ≥2 s arms SOS (single-button hardware) — and the SOS LED
	 * pattern takes over from the hold pattern in the same step (§4). */
	if (!btn->sos_armed && !btn->reset_path &&
	    held_ms >= LICHEN_UX_BUTTON_SOS_HOLD_MS) {
		btn->sos_armed = true;
		return step(LICHEN_UX_BUTTON_EVT_SOS_ARM,
			    LICHEN_UX_BUTTON_LED_SOS);
	}

	/* Steady state: no new event; the LED was set at the transition. */
	return step(LICHEN_UX_BUTTON_EVT_NONE, LICHEN_UX_BUTTON_LED_NONE);
}

struct lichen_ux_button_step lichen_ux_button_sos_dedicated(void)
{
	/* §4: a dedicated SOS button arms immediately, no hold. */
	return step(LICHEN_UX_BUTTON_EVT_SOS_DEDICATED,
		    LICHEN_UX_BUTTON_LED_SOS);
}
