/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file multi_root.h
 * @brief Multi-root conflict resolution: root selection (spec 02a 2a.5).
 *
 * C port of python/src/lichen/link/slot_coordination.py RootCandidate /
 * select_root and rust/lichen-rpl/src/multi_instance.rs RootCandidate.
 *
 * Selection precedence (2a.5.2), first difference wins:
 *   1. DODAG preference — HIGHER wins
 *   2. Time-provider stratum — lower wins (0 = GNSS, 1 = NTP, ...)
 *   3. Combined link score — HIGHER wins, RSSI weighted 2:1 over SNR
 *      (score = 2 * rssi_ema + snr_ema, both in dBm)
 *   4. EUI-64 tiebreak — numerically smaller IID wins (2a.5.2)
 *
 * SECURITY (2a.5.1): candidates whose beacon signature did not verify are
 * discarded before selection; an unverified beacon must never be
 * selectable as root.
 */

#ifndef LICHEN_MULTI_ROOT_H_
#define LICHEN_MULTI_ROOT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** A candidate root advertised via beacon. */
struct lichen_root_candidate {
	int32_t dodag_preference; /**< RPL DODAG preference (higher wins). */
	uint32_t stratum;	  /**< Time-provider stratum (lower wins). */
	float rssi_ema;		  /**< EMA-smoothed RSSI in dBm. */
	float snr_ema;		  /**< EMA-smoothed SNR in dB. */
	uint8_t eui64[8];	  /**< Root EUI-64 (IID = last 8 bytes). */
	bool signature_valid;	  /**< Schnorr48 beacon signature verified. */
};

/**
 * @brief Compare two EUI-64 IIDs as unsigned big-endian integers (2a.5.2).
 * @return -1 when @p a wins (smaller), 0 on equality, +1 when @p b wins.
 */
int lichen_multi_root_compare_iid(const uint8_t a[8], const uint8_t b[8]);

/**
 * @brief Select the best root among verified candidates (spec 02a 2a.5).
 *
 * Candidates with signature_valid == false are discarded first (2a.5.1).
 * Ties resolve by the precedence order in the file header.
 *
 * @param candidates Candidate array (may be NULL when @p count is 0).
 * @param count Number of candidates.
 * @return Pointer to the winning candidate within @p candidates, or NULL
 *         when @p count is 0 or every candidate fails the signature check.
 */
const struct lichen_root_candidate *
lichen_multi_root_select(const struct lichen_root_candidate *candidates,
			 size_t count);

#endif /* LICHEN_MULTI_ROOT_H_ */
