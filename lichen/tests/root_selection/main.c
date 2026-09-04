// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

/**
 * @file main.c
 * @brief Host tests for multi-root selection (spec/02a-coordinated-capacity
 *        .md 2a.5.2, R-02a-029..039) — mirrors the Python select_root cases.
 */

#include <lichen/link/root_selection.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static struct lichen_root_candidate cand(uint8_t preference, uint8_t stratum,
					 int8_t rssi, int8_t snr,
					 uint8_t iid_last, bool valid)
{
	struct lichen_root_candidate c;

	memset(&c, 0, sizeof(c));
	c.eui64[7] = iid_last;
	c.dodag_preference = preference;
	c.stratum = stratum;
	c.rssi_ema = rssi;
	c.snr_ema = snr;
	c.signature_valid = valid;
	return c;
}

static void test_preference_higher_wins(void)
{
	struct lichen_root_candidate candidates[2] = {
		cand(1, 0, -60, -20, 0x01, true),
		cand(5, 0, -60, -20, 0x02, true),
	};

	assert(lichen_root_select(candidates, 2) == 1);
}

static void test_stratum_lower_wins(void)
{
	struct lichen_root_candidate candidates[2] = {
		cand(3, 2, -60, -20, 0x01, true),
		cand(3, 0, -60, -20, 0x02, true),
	};

	assert(lichen_root_select(candidates, 2) == 1);
}

static void test_rssi_snr_combined_score(void)
{
	struct lichen_root_candidate candidates[2] = {
		/* RSSI -50, SNR -20: score = 2*(-50) + (-20) = -120. */
		cand(3, 1, -50, -20, 0x01, true),
		/* RSSI -70, SNR -10: score = 2*(-70) + (-10) = -150. */
		cand(3, 1, -70, -10, 0x02, true),
	};

	/* Higher combined score wins: candidate 0 (-120 > -150). */
	assert(lichen_root_select(candidates, 2) == 0);
}

static void test_iid_tiebreak_lower_wins(void)
{
	struct lichen_root_candidate candidates[2] = {
		cand(3, 1, -50, -20, 0x02, true),
		cand(3, 1, -50, -20, 0x01, true),
	};

	/* All scored fields equal: the numerically smaller IID wins. */
	assert(lichen_root_select(candidates, 2) == 1);
}

static void test_invalid_signature_discarded(void)
{
	struct lichen_root_candidate candidates[2] = {
		cand(9, 0, -30, -10, 0x01, false), /* better scores, invalid */
		cand(1, 5, -90, -30, 0x02, true),
	};

	/* 2a.5.1: unverified beacons are never selectable. */
	assert(lichen_root_select(candidates, 2) == 1);
}

static void test_all_invalid_selects_none(void)
{
	struct lichen_root_candidate candidates[2] = {
		cand(9, 0, -30, -10, 0x01, false),
		cand(1, 5, -90, -30, 0x02, false),
	};

	assert(lichen_root_select(candidates, 2) == -1);
}

static void test_null_and_empty_guards(void)
{
	assert(lichen_root_select(NULL, 0) == -1);

	struct lichen_root_candidate candidates[1];

	memset(candidates, 0, sizeof(candidates));
	assert(lichen_root_select(candidates, 0) == -1);
}

int main(void)
{
	test_preference_higher_wins();
	test_stratum_lower_wins();
	test_rssi_snr_combined_score();
	test_iid_tiebreak_lower_wins();
	test_invalid_signature_discarded();
	test_all_invalid_selects_none();
	test_null_and_empty_guards();
	printf("root selection tests passed\n");
	return 0;
}
