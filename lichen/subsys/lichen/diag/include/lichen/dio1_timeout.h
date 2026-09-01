/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file dio1_timeout.h
 * @brief DIO1 interrupt timeout detector with pin adaptation (diag.2, spec
 *        02a 2a.10.5 family).
 *
 * After lora_send, the TX_DONE IRQ should fire on DIO1 within ~2x expected
 * airtime. This detector:
 * 1. extends the wait to 4x airtime
 * 2. if still no IRQ, scans alternate DIO1 pin candidates (from the DTS
 *    compatible list, caller-supplied)
 * 3. reports DIO1_ADAPT with the pin that worked (updating the active IRQ
 *    pin at runtime) or DIO1_FAIL if none did
 *
 * Freestanding (no kernel dependencies): the IRQ-wait and pin-activate
 * callbacks are platform-provided; time is injected.
 */

#ifndef LICHEN_DIO1_TIMEOUT_H_
#define LICHEN_DIO1_TIMEOUT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** DIO1 pin descriptor (one DTS candidate). */
struct lichen_dio1_pin {
	uint8_t pin;     /**< GPIO pin number */
	void *port_dev;  /**< Platform port device handle (opaque) */
};

/** Adaptation outcome. */
enum lichen_dio1_outcome {
	LICHEN_DIO1_CONFIRMED = 0,  /**< IRQ fired within the timeout */
	LICHEN_DIO1_ADAPTED,        /**< Alternate pin worked; active pin updated */
	LICHEN_DIO1_FAIL,           /**< No candidate produced an IRQ */
};

/** Platform callbacks. */
struct lichen_dio1_ops {
	/**
	 * @brief Configure @p port_dev/@p pin as the DIO1 IRQ source.
	 * @return true on success
	 */
	bool (*activate_pin)(void *user, void *port_dev, uint8_t pin);
};

/** DIO1 timeout detector state (zero-init via init). */
struct lichen_dio1_detector {
	uint8_t active_pin;                        /**< Currently-armed DIO1 pin */
	void *active_port;                         /**< Port device of the active pin */
	const struct lichen_dio1_pin *candidates;  /**< Alternate candidates */
	size_t candidate_count;                    /**< Number of alternates */
	bool adapted;                              /**< A pin adaptation occurred */
};

/** Zero-initialize (call before arming; candidates wired by the caller). */
void lichen_dio1_timeout_init(struct lichen_dio1_detector *det,
			      const struct lichen_dio1_pin *candidates,
			      size_t candidate_count);

/**
 * @brief Wait for the TX_DONE IRQ with timeout extension and pin adaptation.
 *
 * Waits @p airtime_ms * 2 for the IRQ via @p wait_irq_fn (returns true when
 * the IRQ fires). On timeout, extends to 4x. On second timeout, walks the
 * alternate pin candidates: each candidate is activate_pin()-ed and given
 * one 4x-airtime wait; the first pin whose IRQ fires becomes the active pin
 * (runtime adaptation). If no candidate works, the original pin is restored
 * as active (best-effort) and FAIL is returned.
 *
 * The caller reports ADAPTED/FAIL via lichen_diag_report; this module only
 * returns the outcome.
 *
 * @param active_port  Port device of the currently-active pin
 * @param active_pin   Currently-active DIO1 pin
 * @param detector     Candidate list + ops (adaptation source)
 * @param ops          Platform callbacks
 * @param user         Context for ops
 * @param wait_irq     Waits up to @p timeout_ms for the DIO1 IRQ; returns
 *                     true if it fired (platform-owned wait)
 * @param airtime_ms   Expected TX airtime (base for the 2x/4x timeouts)
 * @return CONFIRMED, ADAPTED (state->active_pin updated), or FAIL
 */
enum lichen_dio1_outcome lichen_dio1_timeout_wait(
	void *active_port, uint8_t active_pin,
	struct lichen_dio1_detector *detector, const struct lichen_dio1_ops *ops,
	void *user,
	bool (*wait_irq)(void *user, void *port_dev, uint8_t pin,
			 uint32_t timeout_ms),
	uint32_t airtime_ms);

#endif /* LICHEN_DIO1_TIMEOUT_H_ */
