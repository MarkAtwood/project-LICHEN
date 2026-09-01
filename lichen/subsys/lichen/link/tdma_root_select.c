/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/tdma_root_select.h>

#include <math.h>

void lichen_tdma_root_candidate_init(struct lichen_tdma_root_candidate *c,
				     const uint8_t eui64[8])
{
	if (c == NULL || eui64 == NULL) {
		return;
	}
	for (unsigned int i = 0; i < 8; i++) {
		c->eui64[i] = eui64[i];
	}
	c->dodag_preference = 0;
	c->stratum = 255;
	c->rssi_ema = -120.0f;
	c->snr_ema = -20.0f;
	c->signature_valid = false;
}

void lichen_tdma_root_candidate_sanitize(struct lichen_tdma_root_candidate *c)
{
	if (c == NULL) {
		return;
	}
	if (!isfinite(c->rssi_ema)) {
		c->rssi_ema = -120.0f;
	}
	if (!isfinite(c->snr_ema)) {
		c->snr_ema = -20.0f;
	}
}

float lichen_tdma_root_combined_score(
	const struct lichen_tdma_root_candidate *c)
{
	return 2.0f * c->rssi_ema + c->snr_ema;
}

uint64_t lichen_tdma_root_iid(const struct lichen_tdma_root_candidate *c)
{
	uint64_t iid = 0;

	for (unsigned int i = 0; i < 8; i++) {
		iid = (iid << 8) | c->eui64[i];
	}
	return iid;
}

int lichen_tdma_root_compare(const struct lichen_tdma_root_candidate *a,
			     const struct lichen_tdma_root_candidate *b)
{
	/* 1. DODAG Preference: higher wins. */
	if (a->dodag_preference != b->dodag_preference) {
		return a->dodag_preference > b->dodag_preference ? -1 : 1;
	}
	/* 2. Stratum: lower wins. */
	if (a->stratum != b->stratum) {
		return a->stratum < b->stratum ? -1 : 1;
	}
	/* 3. Combined score: higher wins. */
	float score_a = lichen_tdma_root_combined_score(a);
	float score_b = lichen_tdma_root_combined_score(b);

	if (!isfinite(score_a) || !isfinite(score_b)) {
		/* Rust guarantees non-NaN by sanitizing at construction;
		 * defensively reproduce the sanitized scores here
		 * (2*-120 + -20 = -260) so this branch is score-equivalent
		 * to a sanitized compare, not merely "NaN loses".
		 */
		if (!isfinite(score_a)) {
			score_a = -260.0f;
		}
		if (!isfinite(score_b)) {
			score_b = -260.0f;
		}
	}
	if (score_a != score_b) {
		return score_a > score_b ? -1 : 1;
	}
	/* 4. IID tiebreak: numerically smaller wins. */
	uint64_t iid_a = lichen_tdma_root_iid(a);
	uint64_t iid_b = lichen_tdma_root_iid(b);

	if (iid_a != iid_b) {
		return iid_a < iid_b ? -1 : 1;
	}
	return 0;
}

const struct lichen_tdma_root_candidate *lichen_tdma_select_root(
	const struct lichen_tdma_root_candidate *candidates, size_t n)
{
	const struct lichen_tdma_root_candidate *best = NULL;

	if (candidates == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < n; i++) {
		if (!candidates[i].signature_valid) {
			continue;
		}
		if (best == NULL ||
		    lichen_tdma_root_compare(&candidates[i], best) < 0) {
			best = &candidates[i];
		}
	}
	return best;
}
