/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rf_path_asymmetry.h
 * @brief Radio RF path asymmetry detector (diag.5, spec 02a 2a.10.5 family).
 *
 * Tracks TX success vs RX-ever frame reception over a tumbling 60-second
 * window. Diagnoses RF switch misconfiguration:
 * - TX > 10 successful and RX == 0 -> DIAG_RADIO_TX_ONLY (RF switch stuck:
 *   frames leave but nothing arrives)
 * - RX > 10 and every TX errored -> DIAG_RADIO_RX_ONLY (receive path fine,
 *   transmit path dead)
 *
 * Freestanding (no kernel dependencies): time is injected by the caller.
 */

#ifndef LICHEN_RF_PATH_ASYMMETRY_H_
#define LICHEN_RF_PATH_ASYMMETRY_H_

#include <stdbool.h>
#include <stdint.h>

/** Tumbling evaluation window (ms). Spec diag.5: 60 seconds. */
#define LICHEN_RF_PATH_WINDOW_MS 60000U

/** Minimum successful TX count before the TX-only test fires (strictly
 *  greater than this value). */
#define LICHEN_RF_PATH_MIN_TX_OK 10U

/** Minimum RX frame count before the RX-only test fires (strictly greater
 *  than this value). */
#define LICHEN_RF_PATH_MIN_RX 10U

/** Detected asymmetry direction. */
enum lichen_rf_path_result {
	LICHEN_RF_PATH_NONE = 0,
	LICHEN_RF_PATH_TX_ONLY,   /**< TX succeeds, no RX ever */
	LICHEN_RF_PATH_RX_ONLY,   /**< RX works, no successful TX */
};

/** RF path asymmetry detector state. */
struct lichen_rf_path_asymmetry {
	uint32_t tx_ok;       /**< Successful lora_send calls in window */
	uint32_t tx_err;      /**< Failed lora_send calls in window */
	uint32_t rx_frames;   /**< Valid RX frames received in window */
	uint64_t window_start_ms; /**< Tumbling window start (monotonic ms) */
	bool active;          /**< True once any event armed the window */
};

/** Reset all counters and start a new window (call at init). */
void lichen_rf_path_asymmetry_init(struct lichen_rf_path_asymmetry *state);

/** Record one lora_send() result (success or error). */
void lichen_rf_path_asymmetry_record_tx(
	struct lichen_rf_path_asymmetry *state, int ret, int64_t now_ms);

/** Record one valid RX frame. */
void lichen_rf_path_asymmetry_record_rx(
	struct lichen_rf_path_asymmetry *state, int64_t now_ms);

/**
 * @brief Evaluate the current 60-second window.
 *
 * Returns the detected asymmetry direction, then resets all counters and
 * starts a new tumbling window (the caller reports the result via
 * lichen_diag_report if it is not NONE).
 *
 * @param state  Detector state
 * @param now_ms Current monotonic ms
 * @return LICHEN_RF_PATH_NONE, TX_ONLY, or RX_ONLY
 */
enum lichen_rf_path_result lichen_rf_path_asymmetry_evaluate(
	struct lichen_rf_path_asymmetry *state, int64_t now_ms);

#endif /* LICHEN_RF_PATH_ASYMMETRY_H_ */
