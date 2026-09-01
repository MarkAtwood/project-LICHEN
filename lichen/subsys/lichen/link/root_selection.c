/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/root_selection.h>

#include <string.h>

int lichen_root_candidate_compare(const struct lichen_root_candidate *a,
				  const struct lichen_root_candidate *b)
{
	/* 1. Higher DODAG Preference wins (b higher -> b wins -> >0). */
	if (a->dodag_preference != b->dodag_preference) {
		return (int)b->dodag_preference - (int)a->dodag_preference;
	}

	/* 2. Lower stratum wins. */
	if (a->stratum != b->stratum) {
		return (int)a->stratum - (int)b->stratum;
	}

	/* 3. Higher combined score wins (RSSI weighted 2:1 over SNR). */
	int32_t score_a = 2 * (int32_t)a->rssi_ema_dbm + (int32_t)a->snr_ema_db;
	int32_t score_b = 2 * (int32_t)b->rssi_ema_dbm + (int32_t)b->snr_ema_db;
	if (score_a != score_b) {
		return (score_b > score_a) ? 1 : -1;
	}

	/* 4. Numerically smaller EUI-64 (big-endian) wins. */
	return memcmp(a->eui64, b->eui64, LICHEN_ROOT_EUI64_LEN);
}

const struct lichen_root_candidate *
lichen_root_select(const struct lichen_root_candidate *candidates, size_t count)
{
	if (candidates == NULL || count == 0) {
		return NULL;
	}

	const struct lichen_root_candidate *best = NULL;
	for (size_t i = 0; i < count; i++) {
		const struct lichen_root_candidate *candidate = &candidates[i];
		if (!candidate->signature_valid) {
			/* 2a.5.1: discard unverified beacons (fail-closed). */
			continue;
		}
		if (best == NULL ||
		    lichen_root_candidate_compare(candidate, best) < 0) {
			best = candidate;
		}
	}
	return best;
}
