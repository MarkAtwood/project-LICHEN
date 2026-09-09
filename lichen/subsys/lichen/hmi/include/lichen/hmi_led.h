/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * LICHEN HMI LED language driver — fixed state table (spec/19-device-ux.md
 * §10, tier H and the LEDs on E/O).
 *
 * Six states only. New patterns require amending the spec table (and this
 * driver's table with it), never inventing patterns at the call site.
 */

#ifndef LICHEN_HMI_LED_H_
#define LICHEN_HMI_LED_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The six LED states of spec 19 §10. No others exist. */
enum lichen_hmi_led_state {
	LICHEN_HMI_LED_JOINED_IDLE = 0, /**< off (LEDs are not decorations) */
	LICHEN_HMI_LED_JOINING,         /**< 0.5 Hz, 10% duty */
	LICHEN_HMI_LED_MESSAGE_WAITING, /**< 0.25 Hz, 5% duty (subtle) */
	LICHEN_HMI_LED_SOS_ACTIVE,      /**< 2 Hz, 50% duty, continuous */
	LICHEN_HMI_LED_HOLD_IN_PROGRESS,/**< 4 Hz, 50% duty, until threshold */
	LICHEN_HMI_LED_FAULT,           /**< 1 Hz, 50% duty, until cleared */
};

/** Blink pattern: on for @ref on_ms every @ref period_ms.
 *
 * period_ms == 0 means steady off. The LED is on during the first on_ms
 * of each period (phase starts on).
 */
struct lichen_hmi_led_pattern {
	uint16_t period_ms;
	uint16_t on_ms;
};

/** Fixed spec 19 §10 table lookup.
 *
 * Returns the steady-off pattern for any state outside the six defined
 * values (fail toward less information, spec 19 §12 order 4).
 */
struct lichen_hmi_led_pattern lichen_hmi_led_pattern(
	enum lichen_hmi_led_state state);

/** Evaluate the LED at phase offset @p tick_ms within @p state's pattern.
 *
 * Pure function of the fixed table; the caller owns time and the actual
 * GPIO/LED actuation (board glue drives the LED from this verdict).
 * tick_ms may be any monotonic millisecond timestamp — only the value
 * modulo the pattern period matters.
 */
bool lichen_hmi_led_is_on(enum lichen_hmi_led_state state, uint32_t tick_ms);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_HMI_LED_H_ */
