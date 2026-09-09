/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_UX_BUTTON_H_
#define LICHEN_UX_BUTTON_H_

/**
 * @file ux_button.h
 * @brief Spec 19 §4/§8/§9 button interaction grammar — interaction engine.
 *
 * Universal grammar (spec 19 §4): short-press advances the screen ring;
 * press-and-hold >=2s arms SOS (single-button hardware); >=5s opens the
 * factory-reset path (§9); a dedicated SOS button arms immediately with no
 * hold. Hold feedback is mandatory within 500 ms of button-down (§4).
 *
 * Split: this header + ux_button_core.c are a pure, host-testable
 * interaction engine — the FSM, thresholds, and event vocabulary, with no
 * GPIO dependency. The Zephyr backend (ux_button_zephyr.c,
 * CONFIG_LICHEN_UX_BUTTON) feeds debounced press/release from the user
 * button GPIO and dispatches the resulting events.
 */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Debounce window: a raw edge shorter than this is a bounce, not a press. */
#define LICHEN_UX_BUTTON_DEBOUNCE_MS 25U
/** Hold feedback must appear within this budget of button-down (§4). */
#define LICHEN_UX_BUTTON_FEEDBACK_MS 500U
/** Hold >= 2 s arms SOS (single-button hardware, §4/§8). */
#define LICHEN_UX_BUTTON_SOS_HOLD_MS 2000U
/** Hold >= 5 s opens the factory-reset path (§9). */
#define LICHEN_UX_BUTTON_RESET_HOLD_MS 5000U

/** Interaction events emitted by the engine. The screen/LED/SOS/reset
 * handlers consume these; the engine itself performs no side effects. */
enum lichen_ux_button_event {
	LICHEN_UX_BUTTON_EVT_NONE = 0,
	LICHEN_UX_BUTTON_EVT_ADVANCE,       /**< short-press: next screen (§4) */
	LICHEN_UX_BUTTON_EVT_HOLD_START,    /**< feedback deadline reached (§4) */
	LICHEN_UX_BUTTON_EVT_HOLD_CANCEL,   /**< released before SOS threshold */
	LICHEN_UX_BUTTON_EVT_SOS_ARM,       /**< hold >= 2 s (§4/§8) */
	LICHEN_UX_BUTTON_EVT_RESET_PATH,    /**< hold >= 5 s (§9) */
	LICHEN_UX_BUTTON_EVT_SOS_DEDICATED, /**< dedicated SOS button press (§4) */
};

/** LED override the backend must apply for the H tier (§10). The engine
 * owns the LED only during a hold/SOS; on other events it hands control
 * back (RESTORE) so it never stomps a state another module set. */
enum lichen_ux_button_led {
	LICHEN_UX_BUTTON_LED_NONE = 0,    /**< engine asserts nothing */
	LICHEN_UX_BUTTON_LED_HOLD,        /**< hold in progress: 4 Hz (§4) */
	LICHEN_UX_BUTTON_LED_SOS,         /**< SOS armed: 2 Hz (§10) */
	LICHEN_UX_BUTTON_LED_RESTORE,     /**< hold over, not SOS: prior state */
};

/** Result of one engine step: the event (if any) plus the LED override the
 * backend must apply this step. Events fire exactly once per cause (a hold
 * arms SOS at the threshold; release does not re-emit it). */
struct lichen_ux_button_step {
	enum lichen_ux_button_event event;
	enum lichen_ux_button_led led;
};

/** Interaction engine state. One instance per user button. */
struct lichen_ux_button {
	bool pressed;           /**< debounced logical button state */
	uint64_t down_since_ms; /**< when the current press began (pressed only) */
	bool feedback_sent;     /**< HOLD_START already emitted for this press */
	bool sos_armed;         /**< SOS_HOLD threshold crossed for this press */
	bool reset_path;        /**< RESET_HOLD threshold crossed for this press */
};

/** Init the engine to idle/released. */
void lichen_ux_button_init(struct lichen_ux_button *btn);

/** Feed one debounced logical edge: @p pressed is the settled button state
 * at @p now_ms. Returns the event (if any) and the H-tier LED override the
 * backend must apply. The caller owns debounce: raw edges must be settled
 * before feeding.
 */
struct lichen_ux_button_step lichen_ux_button_feed(
	struct lichen_ux_button *btn, bool pressed, uint64_t now_ms);

/** Poll the engine at @p now_ms (no edge). Emits HOLD_START when the 500 ms
 * feedback deadline is reached and SOS_ARM/RESET_PATH at their thresholds,
 * without waiting for release. Feed on the backend's tick. */
struct lichen_ux_button_step lichen_ux_button_poll(
	struct lichen_ux_button *btn, uint64_t now_ms);

/** Dedicated SOS button: immediate arming, no hold (§4). Pure — emits the
 * dedicated event without touching the user-button FSM. */
struct lichen_ux_button_step lichen_ux_button_sos_dedicated(void);

#ifdef __ZEPHYR__
/* Zephyr backend (CONFIG_LICHEN_UX_BUTTON): owns the user-button GPIO. */

/** Event handler for consumer subsystems (screen ring, SOS, reset). Called
 * from the workqueue thread with the dispatched event. */
typedef void (*lichen_ux_button_handler_t)(enum lichen_ux_button_event event);

/** Init the engine, configure the user-button GPIO, and arm its edge
 * interrupt. @p handler receives dispatched events (may be NULL to drive
 * only the H-tier LED hold feedback). No-button targets (hal_button_get
 * fails) are a quiet no-op. Returns 0 or a negative errno. */
int lichen_ux_button_start(lichen_ux_button_handler_t handler);
#endif /* __ZEPHYR__ */

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_UX_BUTTON_H_ */
