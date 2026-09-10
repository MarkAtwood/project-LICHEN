/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Unit tests for the in-session SCHC fragment rules (spec 5.6; bead
 *        l1qw.3.7.6.4): session admission, 24-bit replay high-water,
 *        idempotent duplicates, conflicting-tile fail-closed, non-opener
 *        FCNs, 0xffffff exhaustion (no wrap).
 */

#include <lichen/schc_session_rx.h>

#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_passed;

#define RUN_TEST(fn)                        \
	do {                                \
		printf("  %s...", #fn);     \
		tests_run++;                \
		if (fn()) {                 \
			printf(" OK\n");    \
			tests_passed++;     \
		}                           \
	} while (0)

#define CHECK(cond, msg)                          \
	do {                                      \
		if (!(cond)) {                    \
			printf(" FAIL: %s\n", msg); \
			return 0;                 \
		}                                 \
	} while (0)

static const uint8_t TILE_A[8] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7};
static const uint8_t TILE_B[8] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7};

static int test_admission_opener_only(void)
{
	/* Only W=0/FCN=62 opens. */
	CHECK(lichen_schc_rx_admit(0, 62, 1, 0) == LICHEN_SCHC_RX_OPEN,
	      "canonical opener admits");
	/* Every other FCN never opens. */
	for (uint8_t fcn = 0; fcn <= 61; fcn++) {
		CHECK(lichen_schc_rx_admit(0, fcn, 1, 0) ==
			      LICHEN_SCHC_RX_OPEN_NOT_OPENER,
		      "regular non-opener FCN rejected");
	}
	/* All-1 (63) never opens. */
	CHECK(lichen_schc_rx_admit(0, 63, 1, 0) ==
		      LICHEN_SCHC_RX_OPEN_NOT_OPENER,
	      "All-1 never opens");
	/* W=1 opener-shaped fragment never opens. */
	CHECK(lichen_schc_rx_admit(1, 62, 1, 0) ==
		      LICHEN_SCHC_RX_OPEN_NOT_OPENER,
	      "W=1 opener rejected");
	return 1;
}

static int test_admission_floor_and_counter_bounds(void)
{
	/* Counter must strictly exceed the durable floor. */
	CHECK(lichen_schc_rx_admit(0, 62, 10, 10) ==
		      LICHEN_SCHC_RX_OPEN_STALE,
	      "counter == floor stale");
	CHECK(lichen_schc_rx_admit(0, 62, 9, 10) ==
		      LICHEN_SCHC_RX_OPEN_STALE,
	      "counter < floor stale");
	CHECK(lichen_schc_rx_admit(0, 62, 11, 10) == LICHEN_SCHC_RX_OPEN,
	      "counter > floor admits");

	/* A counter beyond the 24-bit space never admits (even as opener). */
	CHECK(lichen_schc_rx_admit(0, 62, LICHEN_SCHC_COUNTER_MAX + 1U, 0) ==
		      LICHEN_SCHC_RX_OPEN_EXHAUSTED,
	      "out-of-space counter exhausted");

	/* The ceiling itself is a legal final opener: no wrap after it. */
	CHECK(lichen_schc_rx_admit(0, 62, LICHEN_SCHC_COUNTER_MAX, 0) ==
		      LICHEN_SCHC_RX_OPEN,
	      "ceiling opener admits");
	/* ...but a floor AT the ceiling blocks every opener. */
	CHECK(lichen_schc_rx_admit(0, 62, LICHEN_SCHC_COUNTER_MAX,
				   LICHEN_SCHC_COUNTER_MAX) ==
		      LICHEN_SCHC_RX_OPEN_STALE,
	      "floor at ceiling blocks all");
	return 1;
}

static int test_open_pins_floor_and_high_water(void)
{
	static struct lichen_schc_rx rx;

	CHECK(lichen_schc_rx_open(NULL, 1) == -EINVAL, "NULL rx rejected");
	CHECK(lichen_schc_rx_open(&rx, LICHEN_SCHC_COUNTER_MAX + 1U) ==
		      -EINVAL,
	      "out-of-space counter rejected");
	CHECK(lichen_schc_rx_open(&rx, 42) == 0, "open succeeds");
	CHECK(rx.open, "session open");
	CHECK(rx.open_floor == 42, "opening counter is the floor");
	CHECK(lichen_schc_rx_high_water(&rx) == 42,
	      "opening counter is the initial high-water");
	return 1;
}

static int test_stale_and_fresh_counters(void)
{
	static struct lichen_schc_rx rx;

	(void)lichen_schc_rx_open(&rx, 100);

	/* Stale: counter <= high-water is not accepted, mutates nothing. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 61, TILE_A, sizeof(TILE_A),
				      100) == LICHEN_SCHC_RX_STALE_COUNTER,
	      "equal counter stale");
	CHECK(lichen_schc_rx_fragment(&rx, 0, 61, TILE_A, sizeof(TILE_A),
				      99) == LICHEN_SCHC_RX_STALE_COUNTER,
	      "lower counter stale");
	CHECK(lichen_schc_rx_high_water(&rx) == 100, "high-water unmoved");
	CHECK(rx.tile_len[61] == 0, "no tile stored");

	/* Fresh: strictly greater counter stores and advances. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 61, TILE_A, sizeof(TILE_A),
				      101) == LICHEN_SCHC_RX_STORED,
	      "fresh counter stores");
	CHECK(lichen_schc_rx_high_water(&rx) == 101, "high-water advanced");
	CHECK(rx.tile_len[61] == sizeof(TILE_A) &&
		      memcmp(rx.tiles[61], TILE_A, sizeof(TILE_A)) == 0,
	      "tile bytes stored");
	return 1;
}

static int test_idempotent_duplicate_advances_high_water(void)
{
	static struct lichen_schc_rx rx;

	(void)lichen_schc_rx_open(&rx, 10);
	(void)lichen_schc_rx_fragment(&rx, 0, 62, TILE_A, sizeof(TILE_A), 11);

	/* Identical bytes at a stored coordinate with a fresh counter:
	 * duplicate, not accepted as a new tile, but the high-water STILL
	 * advances. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, TILE_A, sizeof(TILE_A),
				      12) == LICHEN_SCHC_RX_DUPLICATE,
	      "identical repeat is a duplicate");
	CHECK(lichen_schc_rx_high_water(&rx) == 12,
	      "duplicate still advances high-water");
	CHECK(rx.tile_len[62] == sizeof(TILE_A) &&
		      memcmp(rx.tiles[62], TILE_A, sizeof(TILE_A)) == 0,
	      "stored tile untouched");
	return 1;
}

static int test_conflicting_tile_fails_closed(void)
{
	static struct lichen_schc_rx rx;

	(void)lichen_schc_rx_open(&rx, 10);
	(void)lichen_schc_rx_fragment(&rx, 0, 62, TILE_A, sizeof(TILE_A), 11);

	/* Different bytes at a stored coordinate: fail closed, NOTHING is
	 * cleared/replaced/reset, and the high-water does NOT advance. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, TILE_B, sizeof(TILE_B),
				      12) == LICHEN_SCHC_RX_CONFLICT,
	      "conflicting repeat rejected");
	CHECK(lichen_schc_rx_high_water(&rx) == 11,
	      "conflict does not advance high-water");
	CHECK(rx.tile_len[62] == sizeof(TILE_A) &&
		      memcmp(rx.tiles[62], TILE_A, sizeof(TILE_A)) == 0,
	      "stored tile preserved");
	/* A length-changing repeat at the same coordinate is also a
	 * conflict (different bytes). */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, TILE_A, 4, 13) ==
		      LICHEN_SCHC_RX_CONFLICT,
	      "length-changing repeat rejected");
	CHECK(lichen_schc_rx_high_water(&rx) == 11, "still no advance");
	return 1;
}

static int test_counter_exhaustion_no_wrap(void)
{
	static struct lichen_schc_rx rx;

	/* Open at the ceiling minus one: exactly one more fragment admits. */
	(void)lichen_schc_rx_open(&rx, LICHEN_SCHC_COUNTER_MAX - 1U);
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, TILE_A, sizeof(TILE_A),
				      LICHEN_SCHC_COUNTER_MAX) ==
		      LICHEN_SCHC_RX_STORED,
	      "ceiling counter admits once");
	CHECK(lichen_schc_rx_high_water(&rx) == LICHEN_SCHC_COUNTER_MAX,
	      "high-water at ceiling");

	/* At the ceiling nothing more can admit: no wrap, no reuse. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 61, TILE_B, sizeof(TILE_B),
				      LICHEN_SCHC_COUNTER_MAX) ==
		      LICHEN_SCHC_RX_EXHAUSTED,
	      "ceiling cannot be reused");
	CHECK(lichen_schc_rx_fragment(&rx, 0, 61, TILE_B, sizeof(TILE_B),
				      0) == LICHEN_SCHC_RX_EXHAUSTED,
	      "wrapped-to-zero cannot admit");
	CHECK(rx.tile_len[61] == 0, "no tile stored past exhaustion");
	return 1;
}

static int test_coordinate_bounds(void)
{
	static struct lichen_schc_rx rx;

	(void)lichen_schc_rx_open(&rx, 1);

	/* W=1/FCI=62 is a legal window-1 tile (index 125). */
	CHECK(lichen_schc_rx_fragment(&rx, 1, 62, TILE_A, sizeof(TILE_A),
				      2) == LICHEN_SCHC_RX_STORED,
	      "window-1 tile stores");

	/* W=2 is out of the two-window profile. */
	CHECK(lichen_schc_rx_fragment(&rx, 2, 62, TILE_A, sizeof(TILE_A),
				      3) == LICHEN_SCHC_RX_INVALID_COORD,
	      "W=2 invalid");
	/* FCN=63 (All-1) is not a regular tile coordinate here. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 63, TILE_A, sizeof(TILE_A),
				      4) == LICHEN_SCHC_RX_INVALID_COORD,
	      "All-1 FCN invalid as regular tile");
	/* An empty tile cannot be represented (tile_len 0 doubles as the
	 * coordinate-empty marker) and is rejected as invalid. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 0, NULL, 0, 5) ==
		      LICHEN_SCHC_RX_INVALID_COORD,
	      "empty tile invalid");
	/* A NULL tile with a nonzero length is likewise invalid. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 0, NULL, 8, 6) ==
		      LICHEN_SCHC_RX_INVALID_COORD,
	      "NULL tile invalid");
	return 1;
}

static int test_oversize_tile_rejected(void)
{
	static struct lichen_schc_rx rx;
	uint8_t big[256];

	memset(big, 0x5a, sizeof(big));
	(void)lichen_schc_rx_open(&rx, 1);

	/* tile_len beyond the fixed 179-byte tile must NOT reach memcpy:
	 * rejected, no tile stored, high-water unmoved. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, big, 180, 2) ==
		      LICHEN_SCHC_RX_INVALID_COORD,
	      "180-byte tile rejected");
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, big, 255, 2) ==
		      LICHEN_SCHC_RX_INVALID_COORD,
	      "255-byte tile rejected");
	CHECK(rx.tile_len[62] == 0, "oversize tile not stored");
	CHECK(lichen_schc_rx_high_water(&rx) == 1, "high-water unmoved");
	/* A full fixed-size tile is still accepted. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, big,
				      LICHEN_SCHC_RX_TILE_LEN, 2) ==
		      LICHEN_SCHC_RX_STORED,
	      "179-byte tile stores");
	return 1;
}

static int test_out_of_space_counter_rejected_in_session(void)
{
	static struct lichen_schc_rx rx;

	(void)lichen_schc_rx_open(&rx, 1);

	/* A counter beyond the 24-bit space must NOT be accepted in-session:
	 * it would defeat the no-wrap rule by pushing the high-water past
	 * the ceiling. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, TILE_A, sizeof(TILE_A),
				      LICHEN_SCHC_COUNTER_MAX + 1U) ==
		      LICHEN_SCHC_RX_EXHAUSTED,
	      "out-of-space counter rejected");
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, TILE_A, sizeof(TILE_A),
				      UINT32_MAX) ==
		      LICHEN_SCHC_RX_EXHAUSTED,
	      "u32-max counter rejected");
	CHECK(rx.tile_len[62] == 0, "no tile stored");
	CHECK(lichen_schc_rx_high_water(&rx) == 1, "high-water unmoved");
	/* The ceiling itself still admits as the final fragment. */
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, TILE_A, sizeof(TILE_A),
				      LICHEN_SCHC_COUNTER_MAX) ==
		      LICHEN_SCHC_RX_STORED,
	      "ceiling counter admits");
	return 1;
}

static int test_unopened_session_rejects_fragments(void)
{
	static struct lichen_schc_rx rx;

	memset(&rx, 0, sizeof(rx));
	CHECK(lichen_schc_rx_fragment(&rx, 0, 62, TILE_A, sizeof(TILE_A),
				      1) == LICHEN_SCHC_RX_INVALID_COORD,
	      "fragment on unopened session rejected");
	CHECK(lichen_schc_rx_high_water(&rx) == 0, "no high-water");
	return 1;
}

int main(void)
{
	printf("schc_session_rx tests (spec 5.6, l1qw.3.7.6.4)\n");
	RUN_TEST(test_admission_opener_only);
	RUN_TEST(test_admission_floor_and_counter_bounds);
	RUN_TEST(test_open_pins_floor_and_high_water);
	RUN_TEST(test_stale_and_fresh_counters);
	RUN_TEST(test_idempotent_duplicate_advances_high_water);
	RUN_TEST(test_conflicting_tile_fails_closed);
	RUN_TEST(test_counter_exhaustion_no_wrap);
	RUN_TEST(test_coordinate_bounds);
	RUN_TEST(test_oversize_tile_rejected);
	RUN_TEST(test_out_of_space_counter_rejected_in_session);
	RUN_TEST(test_unopened_session_rejects_fragments);
	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
