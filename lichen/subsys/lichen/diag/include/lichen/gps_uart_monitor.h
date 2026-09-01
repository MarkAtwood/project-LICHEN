/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file gps_uart_monitor.h
 * @brief GPS UART health and baud detection (diag.6, spec 02a 2a.10.5
 *        family).
 *
 * Watches the GPS UART byte/NMEA stream and never requires manual baud
 * configuration:
 * - >10 consecutive NMEA checksum failures at the current baud -> try the
 *   alternative bauds (9600, 38400, 115200) automatically
 * - no bytes for 10 seconds -> UART_SILENT (wiring/power fault)
 * - valid NMEA but no fix for 120 s -> NO_FIX (antenna/sky issue, distinct
 *   from a wiring failure)
 *
 * Freestanding (no kernel dependencies): bytes and time are injected by
 * the caller. The baud-switch callback is platform-provided.
 */

#ifndef LICHEN_GPS_UART_MONITOR_H_
#define LICHEN_GPS_UART_MONITOR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Consecutive checksum failures before a baud retry is triggered. */
#define LICHEN_GPS_BAD_CHECKSUM_LIMIT 10U

/** Silent period (no bytes at all) before UART_SILENT fires (ms). */
#define LICHEN_GPS_SILENT_MS 10000U

/** Valid-NMEA-but-no-fix grace period (ms). */
#define LICHEN_GPS_NO_FIX_MS 120000U

/** Number of candidate bauds. */
#define LICHEN_GPS_BAUD_COUNT 3U

/** Candidate baud rates in the adaptation order. */
extern const uint32_t lichen_gps_bauds[LICHEN_GPS_BAUD_COUNT];

/**
 * @brief Platform callback: reconfigure the GPS UART to @p baud.
 *
 * @param user   Platform context (may be NULL)
 * @param baud   Requested baud rate
 * @return 0 when the UART was reconfigured, negative errno otherwise
 */
typedef int (*lichen_gps_baud_switch_fn)(void *user, uint32_t baud);

/** Monitor verdict for one poll. */
enum lichen_gps_uart_status {
	LICHEN_GPS_UART_HEALTHY = 0, /**< Bytes flowing, no action needed */
	LICHEN_GPS_UART_SILENT,      /**< No bytes for 10 s */
	LICHEN_GPS_UART_NO_FIX,      /**< Valid NMEA, no fix for 120 s */
	LICHEN_GPS_UART_ADAPTED,     /**< Switched to a different baud */
	LICHEN_GPS_UART_EXHAUSTED,   /**< All candidate bauds tried, still bad */
};

/** GPS UART monitor state (zero-initialize via init). */
struct lichen_gps_uart_monitor {
	uint64_t last_byte_ms;   /**< Monotonic ms of the last RX byte */
	bool seen_byte;          /**< Any byte received since init/reset */
	bool silent_reported;    /**< UART_SILENT latched until bytes flow */

	bool seen_valid_nmea;    /**< At least one checksum-valid frame */
	uint64_t first_nmea_ms;  /**< Monotonic ms of the first valid frame */
	bool nofix_reported;     /**< NO_FIX latched */

	uint32_t bad_streak;     /**< Consecutive checksum failures */
	uint8_t baud_index;      /**< Current index into lichen_gps_bauds */
	bool tried[LICHEN_GPS_BAUD_COUNT]; /**< Bauds already attempted */
};

/** Zero-initialize the monitor state. */
void lichen_gps_uart_monitor_init(struct lichen_gps_uart_monitor *monitor);

/**
 * @brief Feed one received byte from the GPS UART.
 *
 * @param monitor     Monitor state
 * @param valid_frame True when the byte completed a checksum-valid NMEA
 *                    frame (the parser decides; false = failure or noise)
 * @param now_ms      Current monotonic ms
 * @param switch_fn   Platform baud-switch callback (may be NULL: the
 *                    monitor tracks the streak but cannot adapt)
 * @param user        Context passed to @p switch_fn
 * @return HEALTHY, ADAPTED (switched baud), or EXHAUSTED (all tried)
 */
enum lichen_gps_uart_status lichen_gps_uart_monitor_on_byte(
	struct lichen_gps_uart_monitor *monitor, bool valid_frame,
	int64_t now_ms, lichen_gps_baud_switch_fn switch_fn, void *user);

/**
 * @brief Poll the monitor for silence and no-fix conditions.
 *
 * UART_SILENT latches until bytes flow again; NO_FIX latches until the
 * caller reports a fix (by resetting the monitor or observing one).
 *
 * @param monitor Monitor state
 * @param now_ms  Current monotonic ms
 * @return HEALTHY, UART_SILENT, or NO_FIX
 */
enum lichen_gps_uart_status lichen_gps_uart_monitor_poll(
	const struct lichen_gps_uart_monitor *monitor, int64_t now_ms);

#endif /* LICHEN_GPS_UART_MONITOR_H_ */
