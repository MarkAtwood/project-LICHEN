/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* ASSIGNED_SF DIO option codec + effective-SF resolution
 * (spec/02-physical-link.md 3.4, R-02-008; spec/02a 2a.8).
 * Behavioral oracle: python/src/lichen/link/sf_assignment.py and
 * test/vectors/sf_assignment.json (hash_32 column is the FNV-1a32 oracle). */

#include <lichen/sf_assignment.h>
#include <lichen/link.h>

#include <assert.h>
#include <stddef.h>
#include <string.h>

static void test_parse_option(void)
{
	const uint8_t good[3] = { 0x14, 1, 9 };
	const uint8_t bad_type[3] = { 0x15, 1, 9 };
	const uint8_t bad_len[3] = { 0x14, 2, 9 };
	const uint8_t sf_too_low[3] = { 0x14, 1, 6 };
	const uint8_t sf_too_high[3] = { 0x14, 1, 13 };
	uint8_t sf = 0;

	assert(lichen_sf_assignment_parse_option(good, sizeof(good), &sf));
	assert(sf == 9);

	/* Strictly > boundary: SF7 and SF12 are valid. */
	assert(lichen_sf_assignment_parse_option(
		       (const uint8_t[]){ 0x14, 1, 7 }, 3, &sf));
	assert(sf == 7);
	assert(lichen_sf_assignment_parse_option(
		       (const uint8_t[]){ 0x14, 1, 12 }, 3, &sf));
	assert(sf == 12);

	assert(!lichen_sf_assignment_parse_option(bad_type, sizeof(bad_type), &sf));
	assert(!lichen_sf_assignment_parse_option(bad_len, sizeof(bad_len), &sf));
	assert(!lichen_sf_assignment_parse_option(sf_too_low, sizeof(sf_too_low), &sf));
	assert(!lichen_sf_assignment_parse_option(sf_too_high, sizeof(sf_too_high), &sf));
	assert(!lichen_sf_assignment_parse_option(good, 2, &sf));
	assert(!lichen_sf_assignment_parse_option(NULL, 3, &sf));
}

static void test_hash_fallback_matches_vectors(void)
{
	/* sf_assignment.json hash-based rows: SF = 7 + (hash_32(IID) % 6).
	 * hash_32 values are the independent FNV-1a32 oracle column. */
	static const struct {
		uint8_t iid[8];
		uint8_t expected_sf;
	} rows[] = {
		{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 10 },
		{ { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }, 12 },
		{ { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, 8 },
		{ { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, 10 },
		{ { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe }, 12 },
	};

	for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
		/* Not joined, no assignment -> hash fallback still applies
		 * per the effective-SF priority (the joined gate selects the
		 * SF10 default only when no assignment exists). */
		uint8_t sf = lichen_sf_assignment_effective(0U, true,
							    rows[i].iid);
		assert(sf == rows[i].expected_sf);
	}
}

static void test_gateway_assigned_precedence(void)
{
	/* sf_assignment.json gateway_assigned_precedence: assigned SF 9
	 * overrides hash-based 12 for IID 0011223344556677. */
	uint8_t iid[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
	assert(lichen_sf_assignment_effective(9, true, iid) == 9);
}

static void test_join_fallback_sf10(void)
{
	/* sf_assignment.json join_fallback_sf10: not joined, no assignment
	 * -> SF10 (backwards compat). */
	uint8_t iid[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
	assert(lichen_sf_assignment_effective(0, false, iid) == 10);
}

int main(void)
{
	test_parse_option();
	test_hash_fallback_matches_vectors();
	test_gateway_assigned_precedence();
	test_join_fallback_sf10();
	return 0;
}
