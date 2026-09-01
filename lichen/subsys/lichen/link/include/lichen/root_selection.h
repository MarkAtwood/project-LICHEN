/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_LINK_ROOT_SELECTION_H_
#define LICHEN_LINK_ROOT_SELECTION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** EUI-64 length for root candidates (spec/02a 2a.5.2). */
#define LICHEN_ROOT_EUI64_LEN 8u

/**
 * @brief A candidate root beacon (spec/02a-coordinated-capacity.md 2a.5).
 *
 * SECURITY: @p signature_valid defaults to false (fail-closed, mirroring
 * python RootCandidate.from_beacon and Rust RootCandidate::new). Set it
 * true ONLY after successful Schnorr48 signature verification of the
 * beacon (spec 2a.5.1); an unverified beacon must never be selectable.
 */
struct lichen_root_candidate {
	int8_t dodag_preference; /**< RPL DODAG Preference (higher wins) */
	uint8_t stratum;         /**< Time-provider stratum (lower wins) */
	int16_t rssi_ema_dbm;    /**< EMA-smoothed RSSI in dBm */
	int8_t snr_ema_db;       /**< EMA-smoothed SNR in dB */
	uint8_t eui64[LICHEN_ROOT_EUI64_LEN]; /**< Root EUI-64 */
	bool signature_valid;    /**< True only after signature verification */
};

/**
 * @brief Compare two candidates by the 2a.5.2 selection order.
 *
 * Order of precedence: higher DODAG Preference wins; lower stratum wins;
 * higher combined score wins (RSSI weighted 2:1 over SNR); numerically
 * smaller EUI-64 (big-endian) wins as the tiebreak.
 *
 * @param[in] a First candidate
 * @param[in] b Second candidate
 * @return <0 if @p a wins, 0 if equal, >0 if @p b wins
 */
int lichen_root_candidate_compare(const struct lichen_root_candidate *a,
				  const struct lichen_root_candidate *b);

/**
 * @brief Select the best root from the candidates (spec 2a.5).
 *
 * Candidates without a verified signature are discarded first (2a.5.1,
 * fail-closed). Returns NULL when @p candidates is NULL, @p count is zero,
 * or every candidate has an invalid signature.
 *
 * @param[in] candidates Candidate array
 * @param[in] count      Number of candidates
 * @return The best candidate, or NULL
 */
const struct lichen_root_candidate *
lichen_root_select(const struct lichen_root_candidate *candidates, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LINK_ROOT_SELECTION_H_ */
