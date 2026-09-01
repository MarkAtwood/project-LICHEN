/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file diag.h
 * @brief Hardware diagnostics event ring (spec 18.x LCI diagnostics).
 *
 * Any subsystem can report a diagnostic event via lichen_diag_report();
 * events land in a ring buffer, print human-readable over the console, and
 * are served as a CBOR array on GET /diag.
 */

#ifndef LICHEN_DIAG_H_
#define LICHEN_DIAG_H_

#include <stdbool.h>
#include <stdint.h>

/** Subsystem that produced the event. */
enum lichen_diag_subsystem {
	LICHEN_DIAG_SUB_RADIO = 0,
	LICHEN_DIAG_SUB_GPS,
	LICHEN_DIAG_SUB_DISPLAY,
	LICHEN_DIAG_SUB_POWER,
	LICHEN_DIAG_SUB_LINK,
	LICHEN_DIAG_SUB_COAP,
	LICHEN_DIAG_SUB_SCHED,
	LICHEN_DIAG_SUB_OTHER,
	LICHEN_DIAG_SUB_COUNT,
};

/** One diagnostic event in the ring. */
struct lichen_diag_event {
	uint64_t timestamp_ms;                  /**< Monotonic ms since boot */
	uint8_t subsystem;                      /**< lichen_diag_subsystem */
	uint16_t event_code;                    /**< Caller-defined code */
	uint32_t detail;                        /**< Caller-defined detail */
	char message[33];                       /**< NUL-terminated text */
};

/** Initialize the diagnostics ring (idempotent). */
void lichen_diag_init(void);

/**
 * @brief Report a diagnostic event.
 *
 * Appends to the ring (overwriting the oldest when full), then prints a
 * human-readable line over the console.
 *
 * @param subsystem Producing subsystem
 * @param event_code Caller-defined event code
 * @param detail Caller-defined detail value
 * @param message NUL-terminated description (truncated to 32 chars)
 */
void lichen_diag_report(enum lichen_diag_subsystem subsystem,
			uint16_t event_code, uint32_t detail,
			const char *message);

/** Number of events currently retained. */
size_t lichen_diag_count(void);

/**
 * @brief Copy event @p index (0 = oldest retained) into @p out.
 * @return true if the index was valid
 */
bool lichen_diag_get(size_t index, struct lichen_diag_event *out);

#endif /* LICHEN_DIAG_H_ */
