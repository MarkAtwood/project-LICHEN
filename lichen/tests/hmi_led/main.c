/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* LED language driver conformance (spec/19-device-ux.md §10).
 * Oracle: the spec's fixed table, restated as Hz + duty and evaluated by
 * hand — period_ms = 1000/Hz, on_ms = duty% * period. The driver must
 * produce exactly these six patterns and nothing else. */

#include <lichen/hmi_led.h>

#include <assert.h>

static void test_table_matches_spec(void)
{
	/* joined, idle: off (LEDs are not decorations). */
	const struct lichen_hmi_led_pattern idle =
		lichen_hmi_led_pattern(LICHEN_HMI_LED_JOINED_IDLE);
	assert(idle.period_ms == 0);
	assert(idle.on_ms == 0);

	/* joining: 0.5 Hz, 10% duty -> period 2000 ms, on 200 ms. */
	const struct lichen_hmi_led_pattern joining =
		lichen_hmi_led_pattern(LICHEN_HMI_LED_JOINING);
	assert(joining.period_ms == 2000);
	assert(joining.on_ms == 200);

	/* message waiting: 0.25 Hz, 5% duty -> period 4000 ms, on 200 ms. */
	const struct lichen_hmi_led_pattern waiting =
		lichen_hmi_led_pattern(LICHEN_HMI_LED_MESSAGE_WAITING);
	assert(waiting.period_ms == 4000);
	assert(waiting.on_ms == 200);

	/* SOS active: 2 Hz, 50% duty -> period 500 ms, on 250 ms. */
	const struct lichen_hmi_led_pattern sos =
		lichen_hmi_led_pattern(LICHEN_HMI_LED_SOS_ACTIVE);
	assert(sos.period_ms == 500);
	assert(sos.on_ms == 250);

	/* hold in progress: 4 Hz, 50% duty -> period 250 ms, on 125 ms. */
	const struct lichen_hmi_led_pattern hold =
		lichen_hmi_led_pattern(LICHEN_HMI_LED_HOLD_IN_PROGRESS);
	assert(hold.period_ms == 250);
	assert(hold.on_ms == 125);

	/* fault: 1 Hz, 50% duty -> period 1000 ms, on 500 ms. */
	const struct lichen_hmi_led_pattern fault =
		lichen_hmi_led_pattern(LICHEN_HMI_LED_FAULT);
	assert(fault.period_ms == 1000);
	assert(fault.on_ms == 500);
}

static void test_phase_evaluation(void)
{
	/* On during the first on_ms of each period, off after. */
	assert(lichen_hmi_led_is_on(LICHEN_HMI_LED_JOINING, 0));
	assert(lichen_hmi_led_is_on(LICHEN_HMI_LED_JOINING, 199));
	assert(!lichen_hmi_led_is_on(LICHEN_HMI_LED_JOINING, 200));
	assert(!lichen_hmi_led_is_on(LICHEN_HMI_LED_JOINING, 1999));

	/* Phase wraps: period + phase behaves like phase. */
	assert(lichen_hmi_led_is_on(LICHEN_HMI_LED_JOINING, 2000 + 199));
	assert(!lichen_hmi_led_is_on(LICHEN_HMI_LED_JOINING, 2000 + 200));

	/* SOS: 2 Hz, 50% — on [0,250), off [250,500). */
	assert(lichen_hmi_led_is_on(LICHEN_HMI_LED_SOS_ACTIVE, 249));
	assert(!lichen_hmi_led_is_on(LICHEN_HMI_LED_SOS_ACTIVE, 250));
	assert(lichen_hmi_led_is_on(LICHEN_HMI_LED_SOS_ACTIVE, 500 + 249));

	/* Hold: 4 Hz, 50% — on [0,125), off [125,250). */
	assert(lichen_hmi_led_is_on(LICHEN_HMI_LED_HOLD_IN_PROGRESS, 124));
	assert(!lichen_hmi_led_is_on(LICHEN_HMI_LED_HOLD_IN_PROGRESS, 125));

	/* Fault: 1 Hz, 50% — on [0,500), off [500,1000). */
	assert(lichen_hmi_led_is_on(LICHEN_HMI_LED_FAULT, 0));
	assert(!lichen_hmi_led_is_on(LICHEN_HMI_LED_FAULT, 500));

	/* Message waiting: 5% subtle — on [0,200) of 4000. */
	assert(lichen_hmi_led_is_on(LICHEN_HMI_LED_MESSAGE_WAITING, 100));
	assert(!lichen_hmi_led_is_on(LICHEN_HMI_LED_MESSAGE_WAITING, 3999));
}

static void test_steady_off_and_fail_closed(void)
{
	/* joined-idle is off at every phase. */
	assert(!lichen_hmi_led_is_on(LICHEN_HMI_LED_JOINED_IDLE, 0));
	assert(!lichen_hmi_led_is_on(LICHEN_HMI_LED_JOINED_IDLE, 12345u));

	/* Any value outside the six defined states is off (spec 19 §12
	 * order 4: fail toward less information). */
	assert(lichen_hmi_led_pattern((enum lichen_hmi_led_state)99).period_ms ==
	       0);
	assert(!lichen_hmi_led_is_on((enum lichen_hmi_led_state)99, 7u));
}

int main(void)
{
	test_table_matches_spec();
	test_phase_evaluation();
	test_steady_off_and_fail_closed();
	return 0;
}
