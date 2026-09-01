/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file tdma_root_select.h
 * @brief Multi-root conflict resolution: ordered deterministic root
 *	  selection (C port of python slot_coordination.py select_root /
 *	  rust lichen-rpl multi_instance.rs RootCandidate, spec
 *	  02a-coordinated-capacity.md 2a.5 R-02a-029..039; bead b7z9.24.2).
 *
 * Selection criteria in order of precedence (2a.5.2):
 *   1. DODAG Preference (higher wins)
 *   2. Stratum (lower wins)
 *   3. RSSI + SNR combined score, RSSI weighted 2:1 (higher wins)
 *   4. EUI-64 IID tiebreak (numerically smaller wins)
 *
 * SECURITY (2a.5.1): a candidate is only selectable after its beacon
 * Schnorr48 signature verified; @ref signature_valid defaults to false
 * and a select over only-invalid candidates returns NULL (fail-closed).
 */

#ifndef LICHEN_LINK_TDMA_ROOT_SELECT_H_
#define LICHEN_LINK_TDMA_ROOT_SELECT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct lichen_tdma_root_candidate {
	uint8_t eui64[8];
	uint8_t dodag_preference;
	uint8_t stratum;
	/* EMA-smoothed RF metrics in dB/dBm. */
	float rssi_ema;
	float snr_ema;
	bool signature_valid;
};

/**
 * Initialize a candidate with the reference defaults (dodag_preference 0,
 * stratum 255, RSSI -120 dBm, SNR -20 dB, signature invalid) and copy
 * eui64. eui64 must be non-NULL.
 */
void lichen_tdma_root_candidate_init(struct lichen_tdma_root_candidate *c,
				     const uint8_t eui64[8]);

/** Sanitize non-finite (NaN/inf) RF metrics to the worst-case defaults.
 *  Rust parity note: the Rust reference sanitizes NaN only; +inf/-inf
 *  poisoning is handled here (tracked for Rust separately).
 */
void lichen_tdma_root_candidate_sanitize(struct lichen_tdma_root_candidate *c);

/** Combined RSSI+SNR score (RSSI weighted 2:1 over SNR). */
float lichen_tdma_root_combined_score(const struct lichen_tdma_root_candidate *c);

/** IID of the candidate's EUI-64 as an unsigned big-endian integer. */
uint64_t lichen_tdma_root_iid(const struct lichen_tdma_root_candidate *c);

/**
 * Compare two candidates: returns < 0 when a is the better root, > 0 when
 * b is better, 0 when all four criteria tie. Both pointers must be
 * non-NULL.
 */
int lichen_tdma_root_compare(const struct lichen_tdma_root_candidate *a,
			     const struct lichen_tdma_root_candidate *b);

/**
 * Select the best valid root from candidates (n entries). candidates may
 * be NULL only when n is 0. Returns NULL when n is 0 or no candidate has
 * a valid signature. Ties across all criteria resolve to the earliest
 * candidate.
 */
const struct lichen_tdma_root_candidate *lichen_tdma_select_root(
	const struct lichen_tdma_root_candidate *candidates, size_t n);

#endif /* LICHEN_LINK_TDMA_ROOT_SELECT_H_ */
