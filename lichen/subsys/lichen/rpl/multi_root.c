/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/multi_root.h>

#include <string.h>

int lichen_multi_root_compare_iid(const uint8_t a[8], const uint8_t b[8])
{
	/* Big-endian byte compare == unsigned numeric compare; normalize to
	 * the contract (-1/0/+1) since memcmp only guarantees sign. */
	int cmp = memcmp(a, b, 8U);

	return (cmp > 0) - (cmp < 0);
}

/* Better-than comparator: true when @p a is a better root than @p b.
 * Lexicographic over the 2a.5.2 precedence; first difference wins. */
static bool candidate_beats(const struct lichen_root_candidate *a,
			    const struct lichen_root_candidate *b)
{
	if (a->dodag_preference != b->dodag_preference) {
		return a->dodag_preference > b->dodag_preference;
	}
	if (a->stratum != b->stratum) {
		return a->stratum < b->stratum;
	}
	/* RSSI weighted 2:1 over SNR (both dBm, so the combined score is
	 * negative; higher = better link). */
	const float score_a = 2.0f * a->rssi_ema + a->snr_ema;
	const float score_b = 2.0f * b->rssi_ema + b->snr_ema;

	if (score_a != score_b) {
		return score_a > score_b;
	}
	return lichen_multi_root_compare_iid(a->eui64, b->eui64) < 0;
}

const struct lichen_root_candidate *
lichen_multi_root_select(const struct lichen_root_candidate *candidates,
			 size_t count)
{
	const struct lichen_root_candidate *best = NULL;

	for (size_t i = 0; i < count; i++) {
		if (!candidates[i].signature_valid) {
			continue; /* 2a.5.1: unverified beacons are never roots */
		}
		if (best == NULL || candidate_beats(&candidates[i], best)) {
			best = &candidates[i];
		}
	}
	return best;
}
