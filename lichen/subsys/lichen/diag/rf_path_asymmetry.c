/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rf_path_asymmetry.c
 * @brief Radio RF path asymmetry detector (diag.5, spec 02a 2a.10.5 family).
 */

#include <lichen/rf_path_asymmetry.h>

#include <string.h>

void lichen_rf_path_asymmetry_init(struct lichen_rf_path_asymmetry *state)
{
	if (state == NULL) {
		return;
	}
	memset(state, 0, sizeof(*state));
}

void lichen_rf_path_asymmetry_record_tx(
	struct lichen_rf_path_asymmetry *state, int ret, int64_t now_ms)
{
	if (state == NULL) {
		return;
	}
	if (!state->active) {
		state->active = true;
		state->window_start_ms = (uint64_t)now_ms;
	}
	if (ret >= 0) {
		state->tx_ok++;
	} else {
		state->tx_err++;
	}
}

void lichen_rf_path_asymmetry_record_rx(
	struct lichen_rf_path_asymmetry *state, int64_t now_ms)
{
	if (state == NULL) {
		return;
	}
	if (!state->active) {
		state->active = true;
		state->window_start_ms = (uint64_t)now_ms;
	}
	state->rx_frames++;
}

enum lichen_rf_path_result lichen_rf_path_asymmetry_evaluate(
	struct lichen_rf_path_asymmetry *state, int64_t now_ms)
{
	if (state == NULL) {
		return LICHEN_RF_PATH_NONE;
	}

	/* Never-active (no events since last tumble): nothing to evaluate. */
	if (!state->active) {
		return LICHEN_RF_PATH_NONE;
	}

	/* Window not yet elapsed: keep accumulating. */
	if ((uint64_t)now_ms - state->window_start_ms <
	    LICHEN_RF_PATH_WINDOW_MS) {
		return LICHEN_RF_PATH_NONE;
	}

	enum lichen_rf_path_result result = LICHEN_RF_PATH_NONE;

	if (state->tx_ok > LICHEN_RF_PATH_MIN_TX_OK && state->rx_frames == 0) {
		/* TX succeeds but no valid frame ever received: RF switch
		 * stuck in the TX path (or the peer network is absent). */
		result = LICHEN_RF_PATH_TX_ONLY;
	} else if (state->rx_frames > LICHEN_RF_PATH_MIN_RX &&
		   state->tx_ok == 0 && state->tx_err > 0) {
		/* Receiving fine but every attempted TX errored: transmit
		 * path dead. (A node that never attempted TX is a quiet or
		 * listen-only node, not an RF fault — do not flag.) */
		result = LICHEN_RF_PATH_RX_ONLY;
	}

	/* Tumbling window: reset counters and start fresh. */
	memset(state, 0, sizeof(*state));
	return result;
}
