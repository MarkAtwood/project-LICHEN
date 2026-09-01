/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file tcxo_warmup.h
 * @brief TCXO ready verification with warm-up adaptation (diag.4, spec 02a
 *        2a.10.5 family).
 *
 * After SetStandby(STDBY_XOSC), the SX1262 mode bits may not show
 * STANDBY_XOSC immediately (TCXO warm-up). This module polls the injected
 * status reader with increasing delays (10/20/50/100 ms), records the
 * measured warm-up time, and adapts: subsequent standby transitions wait
 * the recorded time up-front instead of polling. Never fails — if the
 * status still doesn't show XOSC after the max delay, it reports the
 * measured delay so the caller waits longer next time.
 *
 * Freestanding (no kernel dependencies): the status reader and delays are
 * injected by the caller.
 */

#ifndef LICHEN_TCXO_WARMUP_H_
#define LICHEN_TCXO_WARMUP_H_

#include <stdbool.h>
#include <stdint.h>

/** Retry delays (ms) in increasing order. */
extern const uint16_t lichen_tcxo_retry_delays_ms[4];

/** Number of retry delays. */
#define LICHEN_TCXO_RETRY_COUNT 4U

/** Status reader: returns true when the radio reports STANDBY_XOSC. */
typedef bool (*lichen_tcxo_status_fn)(void *user);

/** TCXO warm-up adaptation state. */
struct lichen_tcxo_warmup {
	uint32_t warmup_ms;   /**< Recorded warm-up delay for direct waits */
	uint32_t adaptations; /**< Times the recorded delay was updated */
};

/** Zero-initialize the adaptation state (0 = no recorded warm-up yet). */
void lichen_tcxo_warmup_init(struct lichen_tcxo_warmup *state);

/**
 * @brief Wait for STANDBY_XOSC with increasing retry delays.
 *
 * Polls @p status_fn immediately, then after each delay in
 * lichen_tcxo_retry_delays_ms. Each poll call receives the delay used so
 * the platform can sleep between polls.
 *
 * Records the elapsed warm-up time and adapts the recorded delay for
 * subsequent transitions (monotonic max). Reports DIAG_RADIO_TCXO_ADAPT
 * via @p on_adapt when the recorded delay changes.
 *
 * @param state        Adaptation state
 * @param status_fn    Status reader (true = XOSC ready)
 * @param user         Context for @p status_fn
 * @param sleep_fn     Platform sleep (ms); may spin, must advance time
 * @param now_ms       Current monotonic ms (read once at entry)
 * @param on_adapt     Optional callback on warm-up adaptation (nullable)
 * @return true when XOSC confirmed; false only if still not ready after
 *         the final 100 ms retry (caller waits longer next time)
 */
bool lichen_tcxo_warmup_wait(struct lichen_tcxo_warmup *state,
			     lichen_tcxo_status_fn status_fn, void *user,
			     void (*sleep_ms)(uint32_t), int64_t now_ms,
			     void (*on_adapt)(uint32_t measured_ms));

#endif /* LICHEN_TCXO_WARMUP_H_ */
