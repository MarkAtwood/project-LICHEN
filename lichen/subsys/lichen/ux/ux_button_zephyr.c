/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ux_button_zephyr.c
 * @brief Spec 19 §4/§8/§9 button interaction — Zephyr GPIO/ISR backend.
 *
 * Feeds the pure engine (ux_button_core.c) from the user button GPIO via
 * lichen_hal_button_get(). The ISR only disables the edge interrupt and
 * submits the debounce work; the work handler reads the settled level,
 * feeds the engine, and dispatches the resulting event. During a hold a
 * periodic poll drives the 500 ms feedback deadline and the 2 s / 5 s
 * thresholds without waiting for release.
 *
 * Consumers register one event handler; the default (NULL) drives only the
 * H-tier LED hold feedback via the §10 LED language.
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>

#include <lichen/ux_button.h>
#include <lichen/ux_led.h>
#include <lichen/hal.h>

/* Debounce: re-sample the level this long after an edge (§4 bounce window). */
#define UX_BUTTON_DEBOUNCE_MS LICHEN_UX_BUTTON_DEBOUNCE_MS
/* Hold poll cadence: fine enough to hit the 500 ms feedback deadline and
 * the 2 s/5 s thresholds well within tolerance. */
#define UX_BUTTON_POLL_MS 50U

static struct lichen_ux_button s_btn;
static struct gpio_dt_spec s_button;
static struct gpio_callback s_button_cb;
static bool s_button_valid;
static struct k_work_delayable s_debounce;
static struct k_work_delayable s_poll;

static lichen_ux_button_handler_t s_handler;
static enum lichen_ux_led_state s_led_prev = LICHEN_UX_LED_JOINED_IDLE;
static bool s_led_owned; /* true while this press owns the LED (hold/SOS) */

static void ux_button_dispatch(const struct lichen_ux_button_step *step)
{
	/* Drive the LED only on an explicit engine override (a hold feedback
	 * transition or SOS), never on a bare event — a short-press ADVANCE
	 * must not stomp a JOINING/MESSAGE_WAITING/FAULT blink owned by
	 * another writer. RESTORE hands the LED back to the pre-hold state. */
	switch (step->led) {
	case LICHEN_UX_BUTTON_LED_HOLD:
		if (!s_led_owned) {
			/* Entering the hold: snapshot the pre-hold state once. */
			s_led_prev = lichen_ux_led_state_peek();
			s_led_owned = true;
		}
		lichen_ux_led_state_set(LICHEN_UX_LED_HOLD_IN_PROGRESS);
		break;
	case LICHEN_UX_BUTTON_LED_SOS:
		/* SOS keeps LED ownership across presses (§8 cancel flow); do
		 * NOT release s_led_owned — a later hold must not overwrite the
		 * pre-SOS restore target. */
		lichen_ux_led_state_set(LICHEN_UX_LED_SOS_ACTIVE);
		break;
	case LICHEN_UX_BUTTON_LED_RESTORE:
		if (s_led_owned) {
			lichen_ux_led_state_set(s_led_prev);
			s_led_owned = false;
		}
		break;
	case LICHEN_UX_BUTTON_LED_NONE:
	default:
		break;
	}

	if (step->event != LICHEN_UX_BUTTON_EVT_NONE && s_handler != NULL) {
		s_handler(step->event);
	}
}

static void ux_button_debounce(struct k_work *work)
{
	ARG_UNUSED(work);

	if (!s_button_valid) {
		return;
	}
	bool pressed = gpio_pin_get_dt(&s_button) == 1;

	struct lichen_ux_button_step step =
		lichen_ux_button_feed(&s_btn, pressed, k_uptime_get());
	ux_button_dispatch(&step);

	if (pressed) {
		/* Track the hold: poll for feedback/threshold deadlines. */
		k_work_reschedule(&s_poll, K_MSEC(UX_BUTTON_POLL_MS));
	}

	/* Re-arm the edge interrupt (ISR disabled it to avoid re-fire). */
	(void)gpio_pin_interrupt_configure_dt(&s_button, GPIO_INT_EDGE_BOTH);
}

static void ux_button_poll(struct k_work *work)
{
	ARG_UNUSED(work);

	struct lichen_ux_button_step step =
		lichen_ux_button_poll(&s_btn, k_uptime_get());
	ux_button_dispatch(&step);

	if (s_btn.pressed) {
		k_work_reschedule(&s_poll, K_MSEC(UX_BUTTON_POLL_MS));
	}
}

static void ux_button_isr(const struct device *port, struct gpio_callback *cb,
			  uint32_t pins)
{
	ARG_UNUSED(port);
	ARG_UNUSED(pins);

	/* Disable the edge until the debounce work settles the level (same
	 * re-arm discipline as the LR1110 DIO handler). */
	(void)gpio_pin_interrupt_configure_dt(&s_button, GPIO_INT_DISABLE);
	k_work_reschedule(&s_debounce, K_MSEC(UX_BUTTON_DEBOUNCE_MS));
}

int lichen_ux_button_start(lichen_ux_button_handler_t handler)
{
	if (s_button_valid) {
		/* Idempotent: the GPIO is already configured and the callback
		 * already linked; just (re)point the event handler. */
		s_handler = handler;
		return 0;
	}

	s_handler = handler;
	lichen_ux_button_init(&s_btn);

	s_button_valid = lichen_hal_button_get(&s_button) == 0;
	if (!s_button_valid) {
		/* No user button: quiet no-op (headless-SDK / simulator). */
		return 0;
	}

	int ret = gpio_pin_configure_dt(&s_button, GPIO_INPUT);
	if (ret < 0) {
		s_button_valid = false;
		return ret;
	}
	gpio_init_callback(&s_button_cb, ux_button_isr, BIT(s_button.pin));
	ret = gpio_add_callback(s_button.port, &s_button_cb);
	if (ret < 0) {
		s_button_valid = false;
		return ret;
	}

	/* Init the work items BEFORE arming the edge interrupt: the ISR
	 * reschedules both, so they must be valid before any edge can fire. */
	k_work_init_delayable(&s_debounce, ux_button_debounce);
	k_work_init_delayable(&s_poll, ux_button_poll);

	ret = gpio_pin_interrupt_configure_dt(&s_button, GPIO_INT_EDGE_BOTH);
	if (ret < 0) {
		s_button_valid = false;
		return ret;
	}

	/* A button already held at boot produces no edge: sample the settled
	 * level now so a power-on hold (e.g. the factory-reset idiom) starts
	 * its timer. */
	if (gpio_pin_get_dt(&s_button) == 1) {
		struct lichen_ux_button_step step =
			lichen_ux_button_feed(&s_btn, true, k_uptime_get());
		ux_button_dispatch(&step);
		k_work_schedule(&s_poll, K_MSEC(UX_BUTTON_POLL_MS));
	}

	return 0;
}
