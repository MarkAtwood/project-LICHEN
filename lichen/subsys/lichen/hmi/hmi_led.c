/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Fixed LED state table, spec/19-device-ux.md §10:
 *
 * | state           | Hz   | duty | period | on  |
 * |-----------------|------|------|--------|-----|
 * | joined, idle    | off  | —    | 0      | 0   |
 * | joining         | 0.5  | 10%  | 2000   | 200 |
 * | message waiting | 0.25 | 5%   | 4000   | 200 |
 * | SOS active      | 2    | 50%  | 500    | 250 |
 * | hold in progress| 4    | 50%  | 250    | 125 |
 * | fault (any)     | 1    | 50%  | 1000   | 500 |
 *
 * No other patterns exist. New patterns require amending this table
 * (and the spec table), not inventing at the call site.
 */

#include <lichen/hmi_led.h>

static const struct lichen_hmi_led_pattern table[] = {
	[LICHEN_HMI_LED_JOINED_IDLE] = { .period_ms = 0u, .on_ms = 0u },
	[LICHEN_HMI_LED_JOINING] = { .period_ms = 2000u, .on_ms = 200u },
	[LICHEN_HMI_LED_MESSAGE_WAITING] = { .period_ms = 4000u, .on_ms = 200u },
	[LICHEN_HMI_LED_SOS_ACTIVE] = { .period_ms = 500u, .on_ms = 250u },
	[LICHEN_HMI_LED_HOLD_IN_PROGRESS] = { .period_ms = 250u, .on_ms = 125u },
	[LICHEN_HMI_LED_FAULT] = { .period_ms = 1000u, .on_ms = 500u },
};

struct lichen_hmi_led_pattern lichen_hmi_led_pattern(
	enum lichen_hmi_led_state state)
{
	if ((size_t)state >= sizeof(table) / sizeof(table[0])) {
		/* Fail toward less information (spec 19 §12 order 4). */
		return (struct lichen_hmi_led_pattern){ .period_ms = 0u,
							.on_ms = 0u };
	}
	return table[state];
}

bool lichen_hmi_led_is_on(enum lichen_hmi_led_state state, uint32_t tick_ms)
{
	const struct lichen_hmi_led_pattern p = lichen_hmi_led_pattern(state);

	if (p.period_ms == 0u || p.on_ms == 0u) {
		return false;
	}
	if (p.on_ms >= p.period_ms) {
		return true;
	}
	return (tick_ms % (uint32_t)p.period_ms) < (uint32_t)p.on_ms;
}
