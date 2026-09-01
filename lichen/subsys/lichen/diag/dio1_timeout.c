/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file dio1_timeout.c
 * @brief DIO1 interrupt timeout detector with pin adaptation (diag.2, spec
 *        02a 2a.10.5 family).
 */

#include <lichen/dio1_timeout.h>

#include <string.h>

void lichen_dio1_timeout_init(
	struct lichen_dio1_detector *det,
	const struct lichen_dio1_pin *candidates, size_t candidate_count)
{
	if (det == NULL) {
		return;
	}
	det->active_pin = 0U;
	det->active_port = NULL;
	det->candidates = candidates;
	det->candidate_count = candidate_count;
	det->adapted = false;
}

enum lichen_dio1_outcome lichen_dio1_timeout_wait(
	void *active_port, uint8_t active_pin,
	struct lichen_dio1_detector *detector, const struct lichen_dio1_ops *ops,
	void *user, bool (*wait_irq)(void *user, void *port_dev, uint8_t pin,
				     uint32_t timeout_ms),
	uint32_t airtime_ms)
{
	if (detector == NULL || ops == NULL || wait_irq == NULL) {
		return LICHEN_DIO1_FAIL;
	}

	/* Step 1: standard wait — 2x expected airtime. */
	if (wait_irq(user, active_port, active_pin, airtime_ms * 2U)) {
		detector->active_pin = active_pin;
		detector->active_port = active_port;
		return LICHEN_DIO1_CONFIRMED;
	}

	/* Step 2: extend to 4x (spec diag.2). */
	if (wait_irq(user, active_port, active_pin, airtime_ms * 4U)) {
		detector->active_pin = active_pin;
		detector->active_port = active_port;
		return LICHEN_DIO1_CONFIRMED;
	}

	/* Step 3: scan alternate pin candidates (spec diag.2). */
	if (detector->candidates != NULL && ops->activate_pin != NULL) {
		for (size_t i = 0; i < detector->candidate_count; i++) {
			const struct lichen_dio1_pin *c =
				&detector->candidates[i];
			if (c->pin == active_pin && c->port_dev == active_port) {
				continue; /* already tried */
			}
			if (!ops->activate_pin(user, c->port_dev, c->pin)) {
				continue;
			}
			if (wait_irq(user, c->port_dev, c->pin,
				     airtime_ms * 4U)) {
				/* Runtime adaptation: this pin is now the
				 * active DIO1 IRQ source. */
				detector->active_pin = c->pin;
				detector->active_port = c->port_dev;
				detector->adapted = true;
				return LICHEN_DIO1_ADAPTED;
			}
		}
	}

	/* No candidate produced an IRQ: restore the original pin as active
	 * (best-effort so the platform stays consistent) and report FAIL. */
	if (ops->activate_pin != NULL) {
		(void)ops->activate_pin(user, active_port, active_pin);
	}
	detector->active_pin = active_pin;
	detector->active_port = active_port;
	return LICHEN_DIO1_FAIL;
}
