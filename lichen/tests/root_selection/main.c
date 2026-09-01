/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Root-selection ordered criteria (spec/02a-coordinated-capacity.md
 * sections 2a.5, 2a.5.1, 2a.5.2). Behavioral oracle:
 * python/src/lichen/link/slot_coordination.py select_root/compare_iid
 * and its tests. */

#include <lichen/root_selection.h>

#include <assert.h>
#include <stddef.h>
#include <string.h>

static struct lichen_root_candidate candidate(uint8_t id, int8_t preference,
					      uint8_t stratum,
					      int16_t rssi_ema, int8_t snr_ema,
					      bool signature_valid)
{
	struct lichen_root_candidate c = {
		.dodag_preference = preference,
		.stratum = stratum,
		.rssi_ema_dbm = rssi_ema,
		.snr_ema_db = snr_ema,
		.signature_valid = signature_valid,
	};
	c.eui64[7] = id;
	return c;
}

static void test_invalid_signatures_discarded(void)
{
	/* 2a.5.1: unverified beacons must never be selectable. */
	struct lichen_root_candidate candidates[2] = {
		candidate(1, 10, 0, -50, 10, false),
		candidate(2, 10, 0, -50, 10, false),
	};
	assert(lichen_root_select(NULL, 2) == NULL);
	assert(lichen_root_select(candidates, 0) == NULL);
	assert(lichen_root_select(candidates, 2) == NULL);
}

static void test_preference_wins(void)
{
	/* Higher DODAG Preference wins over everything below it. */
	struct lichen_root_candidate candidates[2] = {
		candidate(1, 1, 0, -40, 15, true),
		candidate(2, 2, 5, -30, 12, true),
	};
	const struct lichen_root_candidate *best =
		lichen_root_select(candidates, 2);
	assert(best != NULL && best->eui64[7] == 2);
}

static void test_stratum_wins(void)
{
	/* Equal preference: lower stratum wins. */
	struct lichen_root_candidate candidates[2] = {
		candidate(1, 2, 1, -40, 15, true),
		candidate(2, 2, 0, -90, -10, true),
	};
	const struct lichen_root_candidate *best =
		lichen_root_select(candidates, 2);
	assert(best != NULL && best->eui64[7] == 2);
}

static void test_combined_score_wins(void)
{
	/* Equal preference and stratum: RSSI weighted 2:1 over SNR.
	 * A: 2*(-40) + 15 = -65.  B: 2*(-45) + 30 = -60 -> B wins
	 * despite the much worse RSSI. */
	struct lichen_root_candidate candidates[2] = {
		candidate(1, 2, 1, -40, 15, true),
		candidate(2, 2, 1, -45, 30, true),
	};
	const struct lichen_root_candidate *best =
		lichen_root_select(candidates, 2);
	assert(best != NULL && best->eui64[7] == 2);
}

static void test_iid_tiebreak_wins(void)
{
	/* Fully equal scores: the numerically smaller EUI-64 wins. */
	struct lichen_root_candidate a = candidate(0x55, 2, 1, -40, 15, true);
	struct lichen_root_candidate b = candidate(0x33, 2, 1, -40, 15, true);
	const struct lichen_root_candidate *best =
		lichen_root_select((struct lichen_root_candidate[]){ a, b }, 2);
	assert(best != NULL && best->eui64[7] == 0x33);

	/* Same candidate pair, reversed order: selection is order-stable. */
	best = lichen_root_select((struct lichen_root_candidate[]){ b, a }, 2);
	assert(best != NULL && best->eui64[7] == 0x33);
}

static void test_unverified_never_beats_verified(void)
{
	/* A better-scoring unverified beacon must not beat a verified one. */
	struct lichen_root_candidate candidates[2] = {
		candidate(1, 5, 0, -10, 20, false),
		candidate(2, 0, 9, -100, -15, true),
	};
	const struct lichen_root_candidate *best =
		lichen_root_select(candidates, 2);
	assert(best != NULL && best->eui64[7] == 2);
}

static void test_compare_iid_tiebreak_is_big_endian(void)
{
	struct lichen_root_candidate a = candidate(0x01, 2, 1, -40, 15, true);
	struct lichen_root_candidate b = candidate(0x02, 2, 1, -40, 15, true);
	/* eui64[7] is the least-significant byte of the big-endian EUI-64:
	 * 0x01 < 0x02 numerically, so a wins. */
	assert(lichen_root_candidate_compare(&a, &b) < 0);
	assert(lichen_root_candidate_compare(&b, &a) > 0);
	assert(lichen_root_candidate_compare(&a, &a) == 0);
}

int main(void)
{
	test_invalid_signatures_discarded();
	test_preference_wins();
	test_stratum_wins();
	test_combined_score_wins();
	test_iid_tiebreak_wins();
	test_unverified_never_beats_verified();
	test_compare_iid_tiebreak_is_big_endian();
	return 0;
}
