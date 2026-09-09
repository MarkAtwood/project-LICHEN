/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Host tests for the 5.03 sender-backoff state machine
 * (spec 07-transport-app.md 10.2.4, R-07-032).
 *
 * The CBOR fixtures below are hand-encoded per RFC 8949 for the spec's
 * fixed-shape duty payload {reason: "duty_cycle", retry_after: N,
 * level: M}; expected durations mirror the Rust (lichen-coap client.rs
 * DEFAULT_503_BACKOFF_S=60, MAX_BACKOFF_S=3600) and Python (ip_coap.py)
 * reference clients. Nothing here is derived from backoff.c itself.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <lichen/coap_backoff.h>

/* Hand-encoded CBOR: {reason: "duty_cycle", retry_after: 90, level: 2} */
static const uint8_t PAYLOAD_RETRY_90[] = {
	0xA3, /* map(3) */
	0x66, 'r', 'e', 'a', 's', 'o', 'n', /* "reason" */
	0x6A, 'd', 'u', 't', 'y', '_', 'c', 'y', 'c', 'l', 'e', /* "duty_cycle" */
	0x6B, 'r', 'e', 't', 'r', 'y', '_', 'a', 'f', 't', 'e', 'r',
	0x18, 0x5A, /* uint(90), 1-byte extended form */
	0x65, 'l', 'e', 'v', 'e', 'l', /* "level" */
	0x02, /* uint(2) */
};

/* {retry_after: 5} */
static const uint8_t PAYLOAD_RETRY_5[] = {
	0xA1, 0x6B, 'r', 'e', 't', 'r', 'y', '_', 'a', 'f', 't', 'e', 'r',
	0x05,
};

/* {retry_after: 1000} - 2-byte extended uint */
static const uint8_t PAYLOAD_RETRY_1000[] = {
	0xA1, 0x6B, 'r', 'e', 't', 'r', 'y', '_', 'a', 'f', 't', 'e', 'r',
	0x19, 0x03, 0xE8,
};

/* {retry_after: 7200} - above the 3600 s DoS cap */
static const uint8_t PAYLOAD_RETRY_7200[] = {
	0xA1, 0x6B, 'r', 'e', 't', 'r', 'y', '_', 'a', 'f', 't', 'e', 'r',
	0x19, 0x1C, 0x20,
};

/* {retry_after: 120, reason: "duty_cycle"} - key before "reason" */
static const uint8_t PAYLOAD_RETRY_FIRST[] = {
	0xA2,
	0x6B, 'r', 'e', 't', 'r', 'y', '_', 'a', 'f', 't', 'e', 'r',
	0x18, 0x78, /* uint(120) */
	0x66, 'r', 'e', 'a', 's', 'o', 'n',
	0x6A, 'd', 'u', 't', 'y', '_', 'c', 'y', 'c', 'l', 'e',
};

/* {reason: "duty_cycle"} - no retry_after key */
static const uint8_t PAYLOAD_NO_RETRY[] = {
	0xA1, 0x66, 'r', 'e', 'a', 's', 'o', 'n',
	0x6A, 'd', 'u', 't', 'y', '_', 'c', 'y', 'c', 'l', 'e',
};

/* {} - empty map */
static const uint8_t PAYLOAD_EMPTY_MAP[] = {0xA0};

/* {retry_after: "x"} - non-integer value for the key */
static const uint8_t PAYLOAD_RETRY_TEXT[] = {
	0xA1, 0x6B, 'r', 'e', 't', 'r', 'y', '_', 'a', 'f', 't', 'e', 'r',
	0x61, 'x',
};

/* {retry_after: -1} - negative integer value */
static const uint8_t PAYLOAD_RETRY_NEGATIVE[] = {
	0xA1, 0x6B, 'r', 'e', 't', 'r', 'y', '_', 'a', 'f', 't', 'e', 'r',
	0x20,
};

/* {retry_after: uint in 4-byte form} - rejected by the tiny fixed-shape
 * scanner (cap 3600 needs at most the 2-byte form) */
static const uint8_t PAYLOAD_RETRY_FOUR_BYTE[] = {
	0xA1, 0x6B, 'r', 'e', 't', 'r', 'y', '_', 'a', 'f', 't', 'e', 'r',
	0x1A, 0x00, 0x00, 0x00, 0x01,
};

/* map(1) with a non-text key */
static const uint8_t PAYLOAD_INT_KEY[] = {
	0xA1, 0x05, 0x05,
};

/* Bare text "retry_after" - not a map at all */
static const uint8_t PAYLOAD_NOT_A_MAP[] = {
	0x6B, 'r', 'e', 't', 'r', 'y', '_', 'a', 'f', 't', 'e', 'r',
};

static void test_duration_null_empty_and_non_map(void)
{
	bool found = true;

	assert(lichen_coap_backoff_duration_s(NULL, 0, &found) == 60U);
	assert(!found);

	const uint8_t empty = 0;

	found = true;
	assert(lichen_coap_backoff_duration_s(&empty, 0U, &found) == 60U);
	assert(!found);

	found = false;
	assert(lichen_coap_backoff_duration_s(PAYLOAD_NOT_A_MAP,
					      sizeof(PAYLOAD_NOT_A_MAP),
					      &found) == 60U);
	assert(!found);
}

static void test_duration_retry_after_variants(void)
{
	bool found;

	found = false;
	assert(lichen_coap_backoff_duration_s(PAYLOAD_RETRY_90,
					      sizeof(PAYLOAD_RETRY_90),
					      &found) == 90U);
	assert(found);

	found = false;
	assert(lichen_coap_backoff_duration_s(PAYLOAD_RETRY_5,
					      sizeof(PAYLOAD_RETRY_5),
					      &found) == 5U);
	assert(found);

	found = false;
	assert(lichen_coap_backoff_duration_s(PAYLOAD_RETRY_1000,
					      sizeof(PAYLOAD_RETRY_1000),
					      &found) == 1000U);
	assert(found);

	found = false;
	assert(lichen_coap_backoff_duration_s(PAYLOAD_RETRY_FIRST,
					      sizeof(PAYLOAD_RETRY_FIRST),
					      &found) == 120U);
	assert(found);
}

static void test_duration_cap_3600(void)
{
	bool found;

	found = false;
	assert(lichen_coap_backoff_duration_s(PAYLOAD_RETRY_7200,
					      sizeof(PAYLOAD_RETRY_7200),
					      &found) == 3600U);
	assert(found);
}

static void test_duration_defaults_when_no_usable_value(void)
{
	bool found;

	const struct {
		const uint8_t *payload;
		size_t len;
	} cases[] = {
		{PAYLOAD_NO_RETRY, sizeof(PAYLOAD_NO_RETRY)},
		{PAYLOAD_EMPTY_MAP, sizeof(PAYLOAD_EMPTY_MAP)},
		{PAYLOAD_RETRY_TEXT, sizeof(PAYLOAD_RETRY_TEXT)},
		{PAYLOAD_RETRY_NEGATIVE, sizeof(PAYLOAD_RETRY_NEGATIVE)},
		{PAYLOAD_RETRY_FOUR_BYTE, sizeof(PAYLOAD_RETRY_FOUR_BYTE)},
		{PAYLOAD_INT_KEY, sizeof(PAYLOAD_INT_KEY)},
	};

	for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
		found = true;
		assert(lichen_coap_backoff_duration_s(cases[i].payload,
						      cases[i].len,
						      &found) == 60U);
		assert(!found);
	}
}

static void test_duration_truncated_maps_fall_back(void)
{
	/* PAYLOAD_RETRY_90 layout: map(3) + "reason":"duty_cycle"
	 * (bytes 1..18) + "retry_after" key (19..30) + value 0x18 0x5A
	 * (31..32) + "level":2 tail (33..39).
	 * Prefixes that cut inside the retry_after key or value must fall
	 * back to the default; once the complete key+value is present the
	 * scanner may return it even though the map tail is truncated. */
	bool found;

	for (size_t len = 0U; len <= 32U; len++) {
		found = true;
		assert(lichen_coap_backoff_duration_s(PAYLOAD_RETRY_90, len,
						      &found) == 60U);
		assert(!found);
	}
	for (size_t len = 33U; len < sizeof(PAYLOAD_RETRY_90); len++) {
		found = false;
		assert(lichen_coap_backoff_duration_s(PAYLOAD_RETRY_90, len,
						      &found) == 90U);
		assert(found);
	}
}

static void test_arm_active_expiry(void)
{
	struct lichen_coap_backoff backoff;
	const int64_t t0 = 1000000;

	memset(&backoff, 0, sizeof(backoff));

	lichen_coap_backoff_arm(&backoff, 60U, t0);
	assert(backoff.until_ms == t0 + 60000);
	assert(lichen_coap_backoff_active(&backoff, t0));
	assert(lichen_coap_backoff_active(&backoff, t0 + 59999));
	assert(!lichen_coap_backoff_active(&backoff, t0 + 60000));
	assert(lichen_coap_backoff_remaining_ms(&backoff, t0 + 30000) == 30000);
	assert(lichen_coap_backoff_remaining_ms(&backoff, t0 + 60000) == 0);
}

static void test_arm_zero_is_inactive(void)
{
	struct lichen_coap_backoff backoff;

	memset(&backoff, 0, sizeof(backoff));

	lichen_coap_backoff_arm(&backoff, 0U, 1000);
	assert(!backoff.active);
	assert(!lichen_coap_backoff_active(&backoff, 1000));
	assert(lichen_coap_backoff_remaining_ms(&backoff, 1000) == 0);
}

static void test_arm_caps_duration(void)
{
	struct lichen_coap_backoff backoff;
	const int64_t t0 = 5;

	memset(&backoff, 0, sizeof(backoff));

	lichen_coap_backoff_arm(&backoff, 7200U, t0);
	assert(lichen_coap_backoff_active(&backoff, t0 + 3600000 - 1));
	assert(!lichen_coap_backoff_active(&backoff, t0 + 3600000));
}

static void test_clear(void)
{
	struct lichen_coap_backoff backoff;

	memset(&backoff, 0, sizeof(backoff));

	lichen_coap_backoff_arm(&backoff, 60U, 0);
	lichen_coap_backoff_clear(&backoff);
	assert(!lichen_coap_backoff_active(&backoff, 1));
	assert(lichen_coap_backoff_remaining_ms(&backoff, 1) == 0);
}

static void test_rearm_extends_window(void)
{
	struct lichen_coap_backoff backoff;
	const int64_t t0 = 0;

	memset(&backoff, 0, sizeof(backoff));

	lichen_coap_backoff_arm(&backoff, 30U, t0);
	/* Second 5.03 ten seconds later re-arms from the new "now". */
	lichen_coap_backoff_arm(&backoff, 60U, t0 + 10000);
	assert(lichen_coap_backoff_active(&backoff, t0 + 69999));
	assert(!lichen_coap_backoff_active(&backoff, t0 + 70000));
}

static void test_null_safety(void)
{
	lichen_coap_backoff_arm(NULL, 60U, 0);
	lichen_coap_backoff_clear(NULL);
	assert(!lichen_coap_backoff_active(NULL, 0));
	assert(lichen_coap_backoff_remaining_ms(NULL, 0) == 0);

	bool found;

	assert(lichen_coap_backoff_duration_s(NULL, 10U, &found) == 60U);
	assert(!found);
}

int main(void)
{
	test_duration_null_empty_and_non_map();
	test_duration_retry_after_variants();
	test_duration_cap_3600();
	test_duration_defaults_when_no_usable_value();
	test_duration_truncated_maps_fall_back();
	test_arm_active_expiry();
	test_arm_zero_is_inactive();
	test_arm_caps_duration();
	test_clear();
	test_rearm_extends_window();
	test_null_safety();
	return 0;
}
