// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

/**
 * @file root_selection.h
 * @brief Multi-root conflict resolution: ordered deterministic root
 *        selection (spec/02a-coordinated-capacity.md 2a.5.2, R-02a-029).
 *
 * Mirrors python/src/lichen/link/slot_coordination.py select_root() and
 * rust lichen-rpl multi_instance.rs select_root_index().
 */

#ifndef LICHEN_LINK_ROOT_SELECTION_H_
#define LICHEN_LINK_ROOT_SELECTION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** One candidate root learned from a received beacon. */
struct lichen_root_candidate {
	uint8_t eui64[8];       /**< Candidate root's EUI-64. */
	uint8_t dodag_preference; /**< RPL DODAG Preference (higher wins). */
	uint8_t stratum;        /**< Time-provider stratum (lower wins). */
	int8_t rssi_ema;        /**< EMA-smoothed RSSI in dBm. */
	int8_t snr_ema;         /**< EMA-smoothed SNR in dB. */
	bool signature_valid;   /**< True only after Schnorr48 verification. */
};

/**
 * @brief Select the best root candidate.
 *
 * Selection criteria in order of precedence (spec 02a 2a.5.2):
 * 1. RPL DODAG Preference (higher wins)
 * 2. Stratum (lower wins)
 * 3. RSSI+SNR combined score (higher wins, RSSI weighted 2:1 over SNR)
 * 4. EUI-64 tiebreak (numerically smaller IID wins)
 *
 * Candidates with signature_valid == false are never selectable
 * (spec 02a 2a.5.1 fail-closed).
 *
 * @param candidates Candidate array (may be NULL).
 * @param count      Number of candidates.
 * @return Index of the best candidate, or -1 when none is selectable.
 */
int lichen_root_select(const struct lichen_root_candidate *candidates,
		       size_t count);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LINK_ROOT_SELECTION_H_ */
