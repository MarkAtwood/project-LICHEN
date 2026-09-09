/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Host conformance tests for the spec 19 §10 LED timing engine.
 *
 * These pin the normative table exactly (rates, duties, closed state set)
 * against the pure engine — no GPIO, no Zephyr.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lichen/ux_led.h>

static int failures;

#define CHECK(cond, ...)                                                   \
	do {                                                               \
		if (!(cond)) {                                             \
			failures++;                                        \
			fprintf(stderr, "FAIL %s:%d: ", __func__,          \
				__LINE__);                                 \
			fprintf(stderr, __VA_ARGS__);                      \
			fputc('\n', stderr);                               \
		}                                                          \
	} while (0)

/* Count on-windows in [t0, t1) for a state entered at t0. */
static unsigned count_on(const struct lichen_ux_led *led, uint64_t t0,
			 uint64_t t1)
{
	unsigned n = 0;

	for (uint64_t t = t0; t < t1; t++) {
		if (lichen_ux_led_eval(led, t)) {
			n++;
		}
	}
	return n;
}

/* Measure the first on-window length and the period between on-window
 * starts for a state entered at t0. */
static void measure(const struct lichen_ux_led *led, uint64_t t0,
		    uint32_t *on_ms, uint32_t *period_ms)
{
	uint64_t first_on = UINT64_MAX, second_on = UINT64_MAX;
	uint64_t off = UINT64_MAX;

	/* Scan generously (up to 3 periods' worth) */
	for (uint64_t t = t0; t < t0 + 20000; t++) {
		bool on = lichen_ux_led_eval(led, t);

		if (on && first_on == UINT64_MAX) {
			first_on = t;
		}
		if (!on && first_on != UINT64_MAX && off == UINT64_MAX) {
			off = t; /* first falling edge after first on-window */
		}
		if (on && off != UINT64_MAX && second_on == UINT64_MAX) {
			second_on = t;
			break;
		}
	}
	*on_ms = (first_on != UINT64_MAX && off != UINT64_MAX)
			 ? (uint32_t)(off - first_on)
			 : 0;
	*period_ms = (second_on != UINT64_MAX && first_on != UINT64_MAX)
			     ? (uint32_t)(second_on - first_on)
			     : 0;
}

static void test_joined_idle_is_off(void)
{
	struct lichen_ux_led led;

	lichen_ux_led_init(&led);
	/* joined-idle must be off across any window */
	CHECK(count_on(&led, 0, 5000) == 0, "joined-idle produced on-time");
	CHECK(lichen_ux_led_state_get(&led) == LICHEN_UX_LED_JOINED_IDLE,
	      "init state != joined-idle");
}

static void test_exactly_six_states(void)
{
	/* §10: "No other patterns exist." The closed enum is the table. */
	CHECK(LICHEN_UX_LED_STATE_COUNT == 6,
	      "table has %d states, spec says exactly 6",
	      LICHEN_UX_LED_STATE_COUNT);
}

static void test_joining_pattern(void)
{
	struct lichen_ux_led led;
	uint32_t on, period;

	lichen_ux_led_init(&led);
	lichen_ux_led_set(&led, LICHEN_UX_LED_JOINING, 0);
	measure(&led, 0, &on, &period);
	/* 0.5 Hz = 2000 ms period, 10% duty = 200 ms on */
	CHECK(period == 2000, "joining period %u ms, want 2000", period);
	CHECK(on == 200, "joining on %u ms, want 200 (10%%)", on);
}

static void test_message_waiting_pattern(void)
{
	struct lichen_ux_led led;
	uint32_t on, period;

	lichen_ux_led_init(&led);
	lichen_ux_led_set(&led, LICHEN_UX_LED_MESSAGE_WAITING, 0);
	measure(&led, 0, &on, &period);
	/* 0.25 Hz = 4000 ms period, 5% duty = 200 ms on */
	CHECK(period == 4000, "message-waiting period %u ms, want 4000", period);
	CHECK(on == 200, "message-waiting on %u ms, want 200 (5%%)", on);
}

static void test_sos_pattern(void)
{
	struct lichen_ux_led led;
	uint32_t on, period;

	lichen_ux_led_init(&led);
	lichen_ux_led_set(&led, LICHEN_UX_LED_SOS_ACTIVE, 0);
	measure(&led, 0, &on, &period);
	/* 2 Hz = 500 ms period, 50% duty = 250 ms on */
	CHECK(period == 500, "SOS period %u ms, want 500", period);
	CHECK(on == 250, "SOS on %u ms, want 250 (50%%)", on);
	/* "continuous": on-window at the very start of the phase */
	CHECK(lichen_ux_led_eval(&led, 0), "SOS not on at phase start");
}

static void test_hold_pattern(void)
{
	struct lichen_ux_led led;
	uint32_t on, period;

	lichen_ux_led_init(&led);
	lichen_ux_led_set(&led, LICHEN_UX_LED_HOLD_IN_PROGRESS, 0);
	measure(&led, 0, &on, &period);
	/* 4 Hz = 250 ms period, 50% duty = 125 ms on */
	CHECK(period == 250, "hold period %u ms, want 250", period);
	CHECK(on == 125, "hold on %u ms, want 125 (50%%)", on);
}

static void test_fault_pattern(void)
{
	struct lichen_ux_led led;
	uint32_t on, period;

	lichen_ux_led_init(&led);
	lichen_ux_led_set(&led, LICHEN_UX_LED_FAULT, 0);
	measure(&led, 0, &on, &period);
	/* 1 Hz = 1000 ms period, 50% duty = 500 ms on */
	CHECK(period == 1000, "fault period %u ms, want 1000", period);
	CHECK(on == 500, "fault on %u ms, want 500 (50%%)", on);
}

static void test_state_switch_resets_phase(void)
{
	struct lichen_ux_led led;

	lichen_ux_led_init(&led);
	lichen_ux_led_set(&led, LICHEN_UX_LED_FAULT, 0);
	/* 600 ms into fault (off portion: 500..1000) */
	CHECK(!lichen_ux_led_eval(&led, 600), "fault on at 600 ms (expect off)");
	/* Switch to SOS at t=600: phase resets, SOS is on at its start */
	lichen_ux_led_set(&led, LICHEN_UX_LED_SOS_ACTIVE, 600);
	CHECK(lichen_ux_led_eval(&led, 600), "SOS not on at switch instant");
	CHECK(!lichen_ux_led_eval(&led, 600 + 250),
	      "SOS still on past its 250 ms window");
}

static void test_invalid_state_ignored(void)
{
	struct lichen_ux_led led;

	lichen_ux_led_init(&led);
	/* The closed table admits no other states; out-of-range is ignored. */
	lichen_ux_led_set(&led, (enum lichen_ux_led_state)6, 100);
	CHECK(lichen_ux_led_state_get(&led) == LICHEN_UX_LED_JOINED_IDLE,
	      "out-of-range state changed the table");
	CHECK(count_on(&led, 100, 2000) == 0, "invalid state produced on-time");
}

static void test_null_safety(void)
{
	lichen_ux_led_init(NULL);
	lichen_ux_led_set(NULL, LICHEN_UX_LED_FAULT, 0);
	CHECK(!lichen_ux_led_eval(NULL, 0), "NULL engine evaluated on");
	CHECK(lichen_ux_led_state_get(NULL) == LICHEN_UX_LED_JOINED_IDLE,
	      "NULL state_get not joined-idle");
}

static void test_long_run_no_wrap_drift(void)
{
	struct lichen_ux_led led;

	lichen_ux_led_init(&led);
	lichen_ux_led_set(&led, LICHEN_UX_LED_HOLD_IN_PROGRESS, 0);
	/* At exactly 1000 periods (250 s), phase must be back to on-start. */
	CHECK(lichen_ux_led_eval(&led, 250000),
	      "hold pattern not periodic at 1000 periods");
	CHECK(!lichen_ux_led_eval(&led, 250000 + 125),
	      "hold on past window at 1000 periods");
}

int main(void)
{
	test_joined_idle_is_off();
	test_exactly_six_states();
	test_joining_pattern();
	test_message_waiting_pattern();
	test_sos_pattern();
	test_hold_pattern();
	test_fault_pattern();
	test_state_switch_resets_phase();
	test_invalid_state_ignored();
	test_null_safety();
	test_long_run_no_wrap_drift();

	if (failures != 0) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return EXIT_FAILURE;
	}
	puts("ux_led: all spec 19 §10 checks passed");
	return EXIT_SUCCESS;
}
