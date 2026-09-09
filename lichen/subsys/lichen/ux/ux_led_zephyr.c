/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ux_led_zephyr.c
 * @brief Spec 19 §10 LED language — Zephyr backend.
 *
 * Drives led0 from the pure timing engine (ux_led_core.c) using the GPIO
 * from lichen_hal_led_get(). A periodic work item evaluates the on/off
 * verdict and applies it with gpio_pin_set_dt(). No LED at all
 * (hal_led_get fails, or CONFIG_LICHEN_HAS_LEDS off) is a quiet no-op:
 * headless-SDK and simulator targets simply have no status LED.
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>

#include <lichen/ux_led.h>
#include <lichen/hal.h>

/* Tick granularity for the GPIO update. The fastest spec pattern is the
 * 4 Hz hold (250 ms period, 125 ms on). Ticking at 1/8th of the shortest
 * on-window keeps edges within ~15 ms of the ideal, well under the human
 * perception floor for an LED. */
#define UX_LED_TICK_MS 16U

static struct lichen_ux_led s_led;
static struct gpio_dt_spec s_led_gpio;
static bool s_gpio_valid;
static struct k_work_delayable s_tick;

static void ux_led_tick(struct k_work *work)
{
	ARG_UNUSED(work);

	bool on = lichen_ux_led_eval(&s_led, k_uptime_get());

	if (s_gpio_valid) {
		(void)gpio_pin_set_dt(&s_led_gpio, on ? 1 : 0);
	}
	k_work_reschedule(&s_tick, K_MSEC(UX_LED_TICK_MS));
}

int lichen_ux_led_start(void)
{
	lichen_ux_led_init(&s_led);
	s_gpio_valid = lichen_hal_led_get(&s_led_gpio) == 0;
	if (!s_gpio_valid) {
		/* No LED: quiet no-op. Do NOT schedule a tick — a battery mesh
		 * node must not wake the system workqueue every 16 ms to write
		 * a GPIO that does not exist. */
		return 0;
	}
	k_work_init_delayable(&s_tick, ux_led_tick);
	return k_work_schedule(&s_tick, K_MSEC(UX_LED_TICK_MS));
}

void lichen_ux_led_state_set(enum lichen_ux_led_state state)
{
	lichen_ux_led_set(&s_led, state, k_uptime_get());
}

enum lichen_ux_led_state lichen_ux_led_state_peek(void)
{
	return lichen_ux_led_state_get(&s_led);
}
