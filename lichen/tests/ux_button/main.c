/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Host conformance tests for the spec 19 §4/§8/§9 button grammar.
 *
 * Pins the normative interaction grammar against the pure engine — no GPIO,
 * no Zephyr: short-press ring advance, hold-feedback deadline, SOS arming at
 * 2 s, factory-reset path at 5 s, and the dedicated SOS button.
 */

#include <stdio.h>
#include <stdlib.h>

#include <lichen/ux_button.h>

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

static struct lichen_ux_button_step step_of(struct lichen_ux_button *b,
					    bool pressed, uint64_t t)
{
	return lichen_ux_button_feed(b, pressed, t);
}

static void test_short_press_advances_ring(void)
{
	struct lichen_ux_button b;

	lichen_ux_button_init(&b);
	/* §4: short-press = next screen (ring advance). A 100 ms tap. */
	CHECK(step_of(&b, true, 0).event == LICHEN_UX_BUTTON_EVT_NONE,
	      "press edge emitted an event");
	CHECK(step_of(&b, false, 100).event == LICHEN_UX_BUTTON_EVT_ADVANCE,
	      "short press did not advance the ring");
}

static void test_hold_feedback_within_500ms(void)
{
	struct lichen_ux_button b;

	lichen_ux_button_init(&b);
	(void)step_of(&b, true, 1000);
	/* §4: feedback is mandatory within 500 ms of button-down. */
	CHECK(lichen_ux_button_poll(&b, 1499).event == LICHEN_UX_BUTTON_EVT_NONE,
	      "feedback before 500 ms");
	struct lichen_ux_button_step s = lichen_ux_button_poll(&b, 1500);
	CHECK(s.event == LICHEN_UX_BUTTON_EVT_HOLD_START,
	      "no hold feedback at 500 ms");
	CHECK(s.led == LICHEN_UX_BUTTON_LED_HOLD,
	      "hold feedback did not assert the hold LED override");
	/* It fires once per press, not repeatedly. */
	CHECK(lichen_ux_button_poll(&b, 1600).event == LICHEN_UX_BUTTON_EVT_NONE,
	      "hold feedback repeated");
}

static void test_release_before_sos_cancels_hold(void)
{
	struct lichen_ux_button b;

	lichen_ux_button_init(&b);
	(void)step_of(&b, true, 0);
	(void)lichen_ux_button_poll(&b, 500); /* feedback shown */
	/* Released at 1500 ms: after feedback, before the 2 s SOS threshold. */
	struct lichen_ux_button_step s = step_of(&b, false, 1500);
	CHECK(s.event == LICHEN_UX_BUTTON_EVT_HOLD_CANCEL,
	      "release after feedback but before SOS did not cancel (got %d)",
	      s.event);
	CHECK(s.led == LICHEN_UX_BUTTON_LED_RESTORE,
	      "hold cancel did not restore the LED");
}

static void test_hold_2s_arms_sos_and_led_takes_over(void)
{
	struct lichen_ux_button b;

	lichen_ux_button_init(&b);
	(void)step_of(&b, true, 0);
	(void)lichen_ux_button_poll(&b, 500);
	/* §4/§8: hold >=2s arms SOS (single-button hardware). */
	CHECK(lichen_ux_button_poll(&b, 1999).event != LICHEN_UX_BUTTON_EVT_SOS_ARM,
	      "SOS armed before 2 s");
	struct lichen_ux_button_step s = lichen_ux_button_poll(&b, 2000);
	CHECK(s.event == LICHEN_UX_BUTTON_EVT_SOS_ARM, "no SOS arm at 2 s");
	/* §4: the SOS LED pattern takes over at the threshold, mid-hold. */
	CHECK(s.led == LICHEN_UX_BUTTON_LED_SOS,
	      "SOS LED did not take over at the 2 s threshold");
	/* Release confirms the armed SOS exactly once (the commit moment) and
	 * keeps the SOS LED; it must NOT also advance the ring. */
	s = step_of(&b, false, 2100);
	CHECK(s.event == LICHEN_UX_BUTTON_EVT_SOS_ARM,
	      "release after SOS did not confirm the arm");
	CHECK(s.led == LICHEN_UX_BUTTON_LED_SOS,
	      "release after SOS dropped the SOS LED");
}

static void test_hold_5s_opens_reset_path(void)
{
	struct lichen_ux_button b;

	lichen_ux_button_init(&b);
	(void)step_of(&b, true, 0);
	(void)lichen_ux_button_poll(&b, 500);
	(void)lichen_ux_button_poll(&b, 2000); /* SOS armed + LED */
	/* §9: hold >=5s opens the factory-reset path. */
	CHECK(lichen_ux_button_poll(&b, 4999).event != LICHEN_UX_BUTTON_EVT_RESET_PATH,
	      "reset path before 5 s");
	struct lichen_ux_button_step s = lichen_ux_button_poll(&b, 5000);
	CHECK(s.event == LICHEN_UX_BUTTON_EVT_RESET_PATH, "no reset path at 5 s");
	/* Release confirms the open reset path exactly once. */
	s = step_of(&b, false, 5100);
	CHECK(s.event == LICHEN_UX_BUTTON_EVT_RESET_PATH,
	      "release after reset did not confirm the reset path (got %d)",
	      s.event);
}

static void test_reset_outranks_sos(void)
{
	struct lichen_ux_button b;

	lichen_ux_button_init(&b);
	(void)step_of(&b, true, 0);
	/* A stall past both thresholds: the first poll after 5 s must open
	 * reset, and SOS must never arm for this press. */
	struct lichen_ux_button_step s = lichen_ux_button_poll(&b, 6000);
	CHECK(s.event == LICHEN_UX_BUTTON_EVT_HOLD_START,
	      "first event after stall was not hold feedback (got %d)", s.event);
	s = lichen_ux_button_poll(&b, 6100);
	CHECK(s.event == LICHEN_UX_BUTTON_EVT_RESET_PATH,
	      "post-stall threshold was not reset path (got %d)", s.event);
	CHECK(lichen_ux_button_poll(&b, 6200).event == LICHEN_UX_BUTTON_EVT_NONE,
	      "SOS armed after reset path opened");
}

static void test_dedicated_sos_is_immediate(void)
{
	/* §4: a dedicated SOS button arms with no hold. */
	struct lichen_ux_button_step s = lichen_ux_button_sos_dedicated();
	CHECK(s.event == LICHEN_UX_BUTTON_EVT_SOS_DEDICATED,
	      "dedicated SOS did not arm immediately");
	CHECK(s.led == LICHEN_UX_BUTTON_LED_SOS,
	      "dedicated SOS did not assert the SOS LED");
}

static void test_very_short_press_is_advance(void)
{
	struct lichen_ux_button b;

	lichen_ux_button_init(&b);
	(void)step_of(&b, true, 0);
	/* Released before the 500 ms feedback deadline: a clean short press. */
	CHECK(step_of(&b, false, 499).event == LICHEN_UX_BUTTON_EVT_ADVANCE,
	      "sub-500ms press did not advance");
}

static void test_no_spurious_events_when_idle(void)
{
	struct lichen_ux_button b;

	lichen_ux_button_init(&b);
	CHECK(lichen_ux_button_poll(&b, 0).event == LICHEN_UX_BUTTON_EVT_NONE,
	      "poll emitted an event with no press");
	CHECK(lichen_ux_button_poll(&b, 100000).event == LICHEN_UX_BUTTON_EVT_NONE,
	      "poll emitted an event while idle");
}

static void test_null_safety(void)
{
	lichen_ux_button_init(NULL);
	CHECK(lichen_ux_button_feed(NULL, true, 0).event == LICHEN_UX_BUTTON_EVT_NONE,
	      "NULL feed emitted an event");
	CHECK(lichen_ux_button_poll(NULL, 0).event == LICHEN_UX_BUTTON_EVT_NONE,
	      "NULL poll emitted an event");
}

int main(void)
{
	test_short_press_advances_ring();
	test_hold_feedback_within_500ms();
	test_release_before_sos_cancels_hold();
	test_hold_2s_arms_sos_and_led_takes_over();
	test_hold_5s_opens_reset_path();
	test_reset_outranks_sos();
	test_dedicated_sos_is_immediate();
	test_very_short_press_is_advance();
	test_no_spurious_events_when_idle();
	test_null_safety();

	if (failures != 0) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return EXIT_FAILURE;
	}
	puts("ux_button: all spec 19 §4/§8/§9 checks passed");
	return EXIT_SUCCESS;
}
