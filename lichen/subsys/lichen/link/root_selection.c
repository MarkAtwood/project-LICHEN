// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

/**
 * @file root_selection.c
 * @brief Multi-root conflict resolution: ordered deterministic root
 *        selection (spec/02a-coordinated-capacity.md 2a.5.2, R-02a-029).
 *
 * Mirrors python/src/lichen/link/slot_coordination.py select_root() and
 * rust lichen-rpl multi_instance.rs select_root_index(): candidates with
 * invalid signatures are discarded first (2a.5.1), then the best candidate
 * is chosen by, in order of precedence:
 *   1. RPL DODAG Preference (higher wins)
 *   2. Stratum (lower wins)
 *   3. RSSI+SNR combined score (higher wins, RSSI weighted 2:1 over SNR)
 *   4. EUI-64 tiebreak (numerically smaller IID wins)
 */

#include <lichen/link/root_selection.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static int root_selection_compare(const struct lichen_root_candidate *a,
				  const struct lichen_root_candidate *b)
{
	/* 1. DODAG Preference: higher wins. */
	if (a->dodag_preference != b->dodag_preference) {
		return (a->dodag_preference > b->dodag_preference) ? -1 : 1;
	}
	/* 2. Stratum: lower wins (0 = GNSS, higher = worse). */
	if (a->stratum != b->stratum) {
		return (a->stratum < b->stratum) ? -1 : 1;
	}
	/* 3. Combined RSSI+SNR score: higher wins (RSSI weighted 2:1). */
	{
		int32_t score_a = 2 * (int32_t)a->rssi_ema + (int32_t)a->snr_ema;
		int32_t score_b = 2 * (int32_t)b->rssi_ema + (int32_t)b->snr_ema;

		if (score_a != score_b) {
			return (score_a > score_b) ? -1 : 1;
		}
	}
	/* 4. EUI-64 tiebreak: numerically smaller IID wins (unsigned
	 * big-endian compare of the 8-byte IID). */
	for (unsigned int i = 0U; i < 8U; i++) {
		if (a->eui64[i] != b->eui64[i]) {
			return (a->eui64[i] < b->eui64[i]) ? -1 : 1;
		}
	}
	return 0;
}

int lichen_root_select(const struct lichen_root_candidate *candidates,
		       size_t count)
{
	if (candidates == NULL || count == 0) {
		return -1;
	}

	size_t best = SIZE_MAX;

	for (size_t i = 0U; i < count; i++) {
		if (!candidates[i].signature_valid) {
			/* 2a.5.1: unverified beacons are never selectable
			 * (fail-closed, mirroring the Python/Rust
			 * signature_valid gate). */
			continue;
		}
		if (best == SIZE_MAX) {
			best = i;
			continue;
		}
		if (root_selection_compare(&candidates[i],
					   &candidates[best]) < 0) {
			best = i;
		}
	}
	return (best == SIZE_MAX) ? -1 : (int)best;
}
