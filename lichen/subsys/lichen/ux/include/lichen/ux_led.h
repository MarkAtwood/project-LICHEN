/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_UX_LED_H_
#define LICHEN_UX_LED_H_

/**
 * @file ux_led.h
 * @brief Spec 19 §10 LED language — the fixed 6-state blink table.
 *
 * The table is normative and closed: six states, each a (rate Hz, duty %)
 * pair, driven by the *current* device state. No other patterns exist; a
 * new pattern requires amending spec 19 §10, not extending this driver.
 *
 * Split: this header + ux_led_core.c are a pure timing engine with no
 * GPIO/Zephyr dependency (host-testable). The Zephyr backend
 * (ux_led_zephyr.c, CONFIG_LICHEN_UX_LED) maps the engine's on/off
 * verdict onto the led0 GPIO via lichen_hal_led_get().
 */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The six LED states from spec 19 §10. Exactly six; no others exist. */
enum lichen_ux_led_state {
	LICHEN_UX_LED_JOINED_IDLE = 0,      /**< joined, idle: off */
	LICHEN_UX_LED_JOINING = 1,          /**< joining: 0.5 Hz, 10% duty */
	LICHEN_UX_LED_MESSAGE_WAITING = 2,  /**< message waiting: 0.25 Hz, 5% duty */
	LICHEN_UX_LED_SOS_ACTIVE = 3,       /**< SOS active: 2 Hz, 50%, continuous */
	LICHEN_UX_LED_HOLD_IN_PROGRESS = 4, /**< hold: 4 Hz, 50%, until threshold */
	LICHEN_UX_LED_FAULT = 5,            /**< fault (any): 1 Hz, 50% */
	LICHEN_UX_LED_STATE_COUNT = 6,
};

/** Pure timing engine state. Callers hold one instance per LED channel. */
struct lichen_ux_led {
	enum lichen_ux_led_state state;
	uint64_t phase_start_ms; /**< when the current state's phase began */
};

/** Init the engine to joined-idle (off) at time 0. */
void lichen_ux_led_init(struct lichen_ux_led *led);

/** Switch to @p state at time @p now_ms (phase resets). Out-of-range
 * states are ignored (the closed table admits no others). */
void lichen_ux_led_set(struct lichen_ux_led *led, enum lichen_ux_led_state state,
		       uint64_t now_ms);

/** Evaluate the LED on/off verdict for @p now_ms against the spec §10
 * table. Pure: no I/O, deterministic. */
bool lichen_ux_led_eval(const struct lichen_ux_led *led, uint64_t now_ms);

/** Current state (for diagnostics / the fplq.9 verification matrix). */
enum lichen_ux_led_state lichen_ux_led_state_get(const struct lichen_ux_led *led);

#ifdef __ZEPHYR__
/* Zephyr backend (CONFIG_LICHEN_UX_LED): owns one led0 driver instance.
 * No-LED targets (hal_led_get fails) are a quiet no-op. */

/** Init the engine and start the GPIO tick. Returns k_work_schedule's
 * result (0/1 on queue, negative errno on failure). */
int lichen_ux_led_start(void);

/** Switch the driven LED state (spec 19 §10 table). */
void lichen_ux_led_state_set(enum lichen_ux_led_state state);

/** Current driven state (diagnostics). */
enum lichen_ux_led_state lichen_ux_led_state_peek(void);
#endif /* __ZEPHYR__ */

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_UX_LED_H_ */
