/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file asymmetric_link.c
 * @brief Fleet asymmetric-link detector (diag.10, spec 02a 2a.10.5 family).
 */

#include <lichen/asymmetric_link.h>

#include <string.h>

void lichen_asym_link_init(struct lichen_asym_link_detector *det)
{
	if (det == NULL) {
		return;
	}
	memset(det, 0, sizeof(*det));
	det->tx_threshold = LICHEN_ASYM_MIN_TX;
	det->ratio = LICHEN_ASYM_RATIO;
	det->window_ms = LICHEN_ASYM_WINDOW_MS;
}

static struct lichen_asym_peer *asym_find_or_add(
	struct lichen_asym_link_detector *det, const uint8_t iid[8],
	int64_t now_ms)
{
	for (size_t i = 0; i < det->count; i++) {
		if (memcmp(det->peers[i].iid, iid, 8) == 0) {
			return &det->peers[i];
		}
	}
	if (det->count == LICHEN_ASYM_MAX_PEERS) {
		/* Evict the peer with the oldest window start. */
		size_t oldest = 0;
		for (size_t i = 1; i < det->count; i++) {
			if (det->peers[i].first_ms < det->peers[oldest].first_ms) {
				oldest = i;
			}
		}
		det->peers[oldest] = det->peers[det->count - 1];
		det->count--;
	}
	if (det->count == LICHEN_ASYM_MAX_PEERS) {
		return NULL;
	}
	struct lichen_asym_peer *p = &det->peers[det->count];
	memset(p, 0, sizeof(*p));
	memcpy(p->iid, iid, 8);
	p->first_ms = (uint64_t)now_ms;
	det->count++;
	return p;
}

void lichen_asym_link_record_tx(struct lichen_asym_link_detector *det,
				const uint8_t iid[8], int64_t now_ms)
{
	if (det == NULL || iid == NULL) {
		return;
	}
	struct lichen_asym_peer *p = asym_find_or_add(det, iid, now_ms);
	if (p != NULL) {
		p->tx++;
	}
}

void lichen_asym_link_record_rx(struct lichen_asym_link_detector *det,
				const uint8_t iid[8], int64_t now_ms)
{
	if (det == NULL || iid == NULL) {
		return;
	}
	struct lichen_asym_peer *p = asym_find_or_add(det, iid, now_ms);
	if (p != NULL) {
		p->rx++;
	}
}

size_t lichen_asym_link_evaluate(const struct lichen_asym_link_detector *det,
				 uint8_t out_iids[][8], size_t out_cap,
				 int64_t now_ms)
{
	if (det == NULL || out_iids == NULL) {
		return 0;
	}

	size_t found = 0;
	for (size_t i = 0; i < det->count; i++) {
		const struct lichen_asym_peer *p = &det->peers[i];

		/* Evaluation window: 5 minutes since first contact. */
		if ((uint64_t)now_ms - p->first_ms < det->window_ms) {
			continue;
		}

		/* Ratio test: TX >= threshold and RX * ratio < TX. */
		if (p->tx >= det->tx_threshold &&
		    (uint64_t)p->rx * (uint64_t)det->ratio < (uint64_t)p->tx) {
			if (found < out_cap) {
				memcpy(out_iids[found], p->iid, 8);
				found++;
			}
		}
	}
	return found;
}
