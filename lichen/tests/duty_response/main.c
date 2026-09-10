// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

/** Host tests for the duty-cycle 5.03 congestion response (spec 07
 * 10.2.3, R-07-031; bead b7z9.45.b) — mirrors the python
 * congestion_service_unavailable contract. */

#include <lichen/duty_response.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>


static void test_shape_and_defaults(void)
{
	struct lichen_duty_response r;

	assert(lichen_duty_congestion_response(LICHEN_CONGESTION_CRITICAL,
					       -1, &r) == 0);
	assert(r.code == 0xA3); /* 5.03 */
	/* Negative retry_after selects the 120 s default ("not provided"). */
	assert(r.max_age == 120);

	const uint8_t *p = r.payload;
	size_t text_len = 0;
	const char *text = NULL;

	p++; /* map(3) */
	/* "reason" */
	assert((*p & 0xE0U) == 0x60U);
	text_len = (size_t)(*p & 0x1FU);
	p++;
	assert(memcmp(p, "reason", text_len) == 0);
	p += text_len;
	/* "duty_cycle" */
	assert((*p & 0xE0U) == 0x60U);
	text_len = (size_t)(*p & 0x1FU);
	p++;
	assert(memcmp(p, "duty_cycle", text_len) == 0);
	p += text_len;
	/* "retry_after" */
	assert((*p & 0xE0U) == 0x60U);
	text_len = (size_t)(*p & 0x1FU);
	p++;
	assert(memcmp(p, "retry_after", text_len) == 0);
	p += text_len;
	/* value: 0x18 0x78 (uint8 120, the negative-sentinel default) */
	assert(*p == 0x18);
	p++;
	assert(*p == 120);
	p++;
	/* "level" key: 0x65 tstr(5) [33..38]; value: 0x68 tstr(8) "critical"
	 * [40..48]. */
	assert((*p & 0xE0U) == 0x60U);
	text_len = (size_t)(*p & 0x1FU);
	p++;
	assert(memcmp(p, "level", text_len) == 0);
	p += text_len;
	/* "critical" */
	assert((*p & 0xE0U) == 0x60U);
	text_len = (size_t)(*p & 0x1FU);
	p++;
	assert(memcmp(p, "critical", text_len) == 0);
	p += text_len;
	(void)text;
}

static void test_negative_clamps_to_zero(void)
{
	struct lichen_duty_response r;

	assert(lichen_duty_congestion_response(LICHEN_CONGESTION_NORMAL, -5,
					       &r) == 0);
	/* Negative retry_after means "not provided" -> the 120 s default
	 * (documented sentinel in duty_response.h). */
	const uint8_t *p = r.payload;
	/* Skip map(3), "reason" tstr, "duty_cycle" tstr, "retry_after" tstr. */
	p++;
	p += 1 + 6;
	p += 1 + 10;
	p += 1 + 11;
	/* retry_after value 0x18 0x78 (uint8 120). */
	assert(*p == 0x18);
	p++;
	assert(*p == 120);
	assert(r.max_age == 120);
}

static void test_positive_retry_after_preserved(void)
{
	struct lichen_duty_response r;

	assert(lichen_duty_congestion_response(LICHEN_CONGESTION_EXHAUSTED, 45,
					       &r) == 0);
	assert(r.max_age == 45);

	const uint8_t *p = r.payload;
	/* Walk: map(3) | "reason"(1+6) | "duty_cycle"(1+10) | "retry_after"
	 * key(1+11) | value 0x18 0x2d (uint8 marker + 45). */
	p++;                     /* map header */
	p += 1 + 6;             /* "reason" key */
	p += 1 + 10;            /* "duty_cycle" value */
	p += 1 + 11;            /* "retry_after" key */
	assert(*p == 0x18);     /* uint8 marker */
	p++;
	assert(*p == 45);       /* the value 45 */
}

static void test_level_names(void)
{
	struct lichen_duty_response r;

	assert(lichen_duty_congestion_response(LICHEN_CONGESTION_EXHAUSTED, 5,
					       &r) == 0);
	const uint8_t *p = r.payload;
	/* Walk to the level value: map(3), reason, duty_cycle, retry_after. */
	p += 1;
	p += 1 + 6; /* "reason" */
	p += 1 + 10; /* "duty_cycle" */
	p += 1 + 11; /* "retry_after" */
	p += 1; /* retry_after uint 5 */
	p += 1 + 5; /* "level" key */
	assert(*p == 0x69); /* tstr(9) header for "exhausted" */
	size_t text_len = 9;
	p++;
	assert(memcmp(p, "exhausted", text_len) == 0);
}

static void test_level_from_usage(void)
{
	assert(lichen_congestion_level_from_usage(0) ==
	       LICHEN_CONGESTION_NORMAL);
	assert(lichen_congestion_level_from_usage(699) ==
	       LICHEN_CONGESTION_NORMAL);
	assert(lichen_congestion_level_from_usage(700) ==
	       LICHEN_CONGESTION_ELEVATED);
	assert(lichen_congestion_level_from_usage(849) ==
	       LICHEN_CONGESTION_ELEVATED);
	assert(lichen_congestion_level_from_usage(850) ==
	       LICHEN_CONGESTION_CRITICAL);
	assert(lichen_congestion_level_from_usage(949) ==
	       LICHEN_CONGESTION_CRITICAL);
	assert(lichen_congestion_level_from_usage(950) ==
	       LICHEN_CONGESTION_EXHAUSTED);
}

static void test_null_guard(void)
{
	assert(lichen_duty_congestion_response(LICHEN_CONGESTION_NORMAL, 1,
					       NULL) == -22);
}


static void test_explicit_zero_preserved(void)
{
	struct lichen_duty_response r;

	/* Explicit 0 is a real value (Max-Age 0 = "immediately stale"). */
	assert(lichen_duty_congestion_response(LICHEN_CONGESTION_NORMAL, 0,
					       &r) == 0);
	assert(r.max_age == 0);
	const uint8_t *p = r.payload;
	/* Walk: map(3) | "reason"(1+6) | "duty_cycle"(1+10) | "retry_after"
	 * key(1+11) | value 0x00. */
	p += 1;
	p += 1 + 6;
	p += 1 + 10;
	p += 1 + 11;
	assert(*p == 0x00); /* value 0, not the 120 default */
}

static void test_large_retry_after_uint16(void)
{
	struct lichen_duty_response r;

	/* 3600 needs the 0x19 uint16 form. */
	assert(lichen_duty_congestion_response(LICHEN_CONGESTION_EXHAUSTED,
					       3600, &r) == 0);
	assert(r.max_age == 3600);
	const uint8_t *p = r.payload;
	/* Walk: map(3) | reason(1+6) | duty_cycle(1+10) | retry_after key
	 * (1+11) | value 0x19 0x0e 0x10. */
	p += 1;
	p += 1 + 6;
	p += 1 + 10;
	p += 1 + 11;
	assert(*p == 0x19);
	p++;
	assert((uint16_t)((p[0] << 8) | p[1]) == 3600);
}

int main(void)
{
	test_shape_and_defaults();
	test_negative_clamps_to_zero();
	test_positive_retry_after_preserved();
	test_level_names();
	test_level_from_usage();
	test_explicit_zero_preserved();
	test_large_retry_after_uint16();
	test_null_guard();
	printf("duty response tests passed\n");
	return 0;
}
