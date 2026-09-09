/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ux_led_core.c
 * @brief Spec 19 §10 LED timing engine — pure, no GPIO dependency.
 *
 * Host-testable core: maps (state, elapsed ms) to an on/off verdict using
 * the fixed table. The Zephyr backend drives the GPIO from this verdict.
 */

#include <lichen/ux_led.h>

#include <stddef.h>

/* Spec 19 §10 table, expressed as period_ms and on_ms (duty% of period).
 * Periods are exact from the rate; on-times rounded to the nearest ms so
 * integer-ms evaluation is exact and deterministic on both host and target:
 *   joining          0.5 Hz -> 2000 ms period, 10% -> 200 ms on
 *   message waiting  0.25 Hz -> 4000 ms period, 5% -> 200 ms on
 *   SOS active       2 Hz -> 500 ms period, 50% -> 250 ms on
 *   hold in progress 4 Hz -> 250 ms period, 50% -> 125 ms on
 *   fault            1 Hz -> 1000 ms period, 50% -> 500 ms on
 * joined-idle is a fixed off and needs no timing entry.
 */
struct led_pattern {
	uint32_t period_ms;
	uint32_t on_ms;
};

static const struct led_pattern patterns[LICHEN_UX_LED_STATE_COUNT] = {
	[LICHEN_UX_LED_JOINED_IDLE] = { 0U, 0U },
	[LICHEN_UX_LED_JOINING] = { 2000U, 200U },
	[LICHEN_UX_LED_MESSAGE_WAITING] = { 4000U, 200U },
	[LICHEN_UX_LED_SOS_ACTIVE] = { 500U, 250U },
	[LICHEN_UX_LED_HOLD_IN_PROGRESS] = { 250U, 125U },
	[LICHEN_UX_LED_FAULT] = { 1000U, 500U },
};

static bool state_valid(enum lichen_ux_led_state state)
{
	return state >= LICHEN_UX_LED_JOINED_IDLE &&
	       state < LICHEN_UX_LED_STATE_COUNT;
}

void lichen_ux_led_init(struct lichen_ux_led *led)
{
	if (led == NULL) {
		return;
	}
	led->state = LICHEN_UX_LED_JOINED_IDLE;
	led->phase_start_ms = 0U;
}

void lichen_ux_led_set(struct lichen_ux_led *led, enum lichen_ux_led_state state,
		       uint64_t now_ms)
{
	if (led == NULL || !state_valid(state)) {
		return;
	}
	led->state = state;
	led->phase_start_ms = now_ms;
}

bool lichen_ux_led_eval(const struct lichen_ux_led *led, uint64_t now_ms)
{
	if (led == NULL || !state_valid(led->state)) {
		return false;
	}
	if (led->state == LICHEN_UX_LED_JOINED_IDLE) {
		return false;
	}

	const struct led_pattern *p = &patterns[led->state];
	if (p->period_ms == 0U) {
		return false;
	}

	uint64_t elapsed = now_ms - led->phase_start_ms;
	uint32_t phase = (uint32_t)(elapsed % p->period_ms);
	return phase < p->on_ms;
}

enum lichen_ux_led_state lichen_ux_led_state_get(const struct lichen_ux_led *led)
{
	return led == NULL ? LICHEN_UX_LED_JOINED_IDLE : led->state;
}
