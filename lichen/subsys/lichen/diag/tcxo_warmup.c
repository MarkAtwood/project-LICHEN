/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file tcxo_warmup.c
 * @brief TCXO ready verification with warm-up adaptation (diag.4, spec 02a
 *        2a.10.5 family).
 */

#include <lichen/tcxo_warmup.h>

#include <stddef.h>

const uint16_t lichen_tcxo_retry_delays_ms[4] = { 10U, 20U, 50U, 100U };

void lichen_tcxo_warmup_init(struct lichen_tcxo_warmup *state)
{
	if (state != NULL) {
		state->warmup_ms = 0U;
		state->adaptations = 0U;
	}
}

bool lichen_tcxo_warmup_wait(struct lichen_tcxo_warmup *state,
			     lichen_tcxo_status_fn status_fn, void *user,
			     void (*sleep_ms)(uint32_t), int64_t now_ms,
			     void (*on_adapt)(uint32_t measured_ms))
{
	(void)state;
	(void)now_ms;

	/* Immediate check: fast TCXO may already be ready. */
	if (status_fn(user)) {
		return true;
	}

	/* Increasing retries: 10/20/50/100 ms (spec diag.4). Never fails —
	 * each retry just waits longer. */
	for (uint8_t i = 0U; i < LICHEN_TCXO_RETRY_COUNT; i++) {
		uint16_t delay = lichen_tcxo_retry_delays_ms[i];
		sleep_ms(delay);
		if (status_fn(user)) {
			/* Adapt: record the measured warm-up for subsequent
			 * direct-wait transitions. */
			if (state != NULL) {
				uint32_t measured = delay;
				if (measured > state->warmup_ms) {
					state->warmup_ms = measured;
					state->adaptations++;
					if (on_adapt != NULL) {
						on_adapt(measured);
					}
				}
			}
			return true;
		}
	}

	/* Still not ready after all retries: record the cumulative elapsed
	 * warm-up (180 ms) so subsequent transitions wait at least this long
	 * up-front — "never fail, just wait longer" per diag.4. */
	if (state != NULL) {
		uint32_t elapsed = 0U;
		for (uint8_t i = 0U; i < LICHEN_TCXO_RETRY_COUNT; i++) {
			elapsed += lichen_tcxo_retry_delays_ms[i];
		}
		if (elapsed > state->warmup_ms) {
			state->warmup_ms = elapsed;
			state->adaptations++;
		}
	}
	return false;
}
