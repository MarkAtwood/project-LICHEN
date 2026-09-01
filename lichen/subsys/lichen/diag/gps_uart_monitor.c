/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file gps_uart_monitor.c
 * @brief GPS UART health and baud detection (diag.6, spec 02a 2a.10.5
 *        family).
 */

#include <lichen/gps_uart_monitor.h>

#include <string.h>

const uint32_t lichen_gps_bauds[LICHEN_GPS_BAUD_COUNT] = { 9600U, 38400U,
							   115200U };

void lichen_gps_uart_monitor_init(struct lichen_gps_uart_monitor *monitor)
{
	if (monitor != NULL) {
		memset(monitor, 0, sizeof(*monitor));
	}
}

enum lichen_gps_uart_status lichen_gps_uart_monitor_on_byte(
	struct lichen_gps_uart_monitor *monitor, bool valid_frame,
	int64_t now_ms, lichen_gps_baud_switch_fn switch_fn, void *user)
{
	if (monitor == NULL) {
		return LICHEN_GPS_UART_HEALTHY;
	}

	/* Any byte clears the silent latch and refreshes the timestamp. */
	monitor->last_byte_ms = (uint64_t)now_ms;
	monitor->seen_byte = true;
	monitor->silent_reported = false;

	if (valid_frame) {
		monitor->bad_streak = 0U;
		if (!monitor->seen_valid_nmea) {
			monitor->seen_valid_nmea = true;
			monitor->first_nmea_ms = (uint64_t)now_ms;
		}
		return LICHEN_GPS_UART_HEALTHY;
	}

	/* Checksum failure or noise: grow the streak. */
	monitor->bad_streak++;
	if (monitor->bad_streak <= LICHEN_GPS_BAD_CHECKSUM_LIMIT ||
	    switch_fn == NULL) {
		return LICHEN_GPS_UART_HEALTHY;
	}

	/* Streak exceeded: try the next candidate baud not yet attempted.
	 * The current baud is marked tried here so it is not re-probed
	 * before EXHAUSTED; re-probing it after a full rotation is a
	 * deliberate recovery attempt. */
	/* Streak exceeded: try the next candidate baud not yet attempted.
	 * The current baud is marked tried here so it is not re-probed
	 * before EXHAUSTED; re-probing it after a full rotation is a
	 * deliberate recovery attempt. Candidates are marked tried on
	 * attempt (success or failure) so a failing switch_fn is not
	 * hammered indefinitely. */
	if (!monitor->tried[monitor->baud_index]) {
		monitor->tried[monitor->baud_index] = true;
	}
	for (uint8_t step = 1U; step <= LICHEN_GPS_BAUD_COUNT; step++) {
		uint8_t candidate = (uint8_t)((monitor->baud_index + step) %
					      LICHEN_GPS_BAUD_COUNT);
		if (monitor->tried[candidate]) {
			continue;
		}
		monitor->tried[candidate] = true;
		if (switch_fn(user, lichen_gps_bauds[candidate]) == 0) {
			monitor->baud_index = candidate;
			monitor->bad_streak = 0U;
			return LICHEN_GPS_UART_ADAPTED;
		}
	}

	/* Every candidate tried (or the switch callback keeps failing). */
	return LICHEN_GPS_UART_EXHAUSTED;
}

enum lichen_gps_uart_status lichen_gps_uart_monitor_poll(
	const struct lichen_gps_uart_monitor *monitor, int64_t now_ms)
{
	if (monitor == NULL) {
		return LICHEN_GPS_UART_HEALTHY;
	}

	/* No bytes at all, or bytes stopped 10 s ago -> silent (latched
	 * until bytes flow; on_byte clears the latch). */
	if (!monitor->seen_byte ||
	    (uint64_t)now_ms - monitor->last_byte_ms >=
		    LICHEN_GPS_SILENT_MS) {
		((struct lichen_gps_uart_monitor *)monitor)->silent_reported =
			true;
		return LICHEN_GPS_UART_SILENT;
	}

	/* Valid NMEA flowing but no fix for 120 s -> antenna/sky issue
	 * (latched until the caller observes a fix). */
	if (monitor->seen_valid_nmea &&
	    (uint64_t)now_ms - monitor->first_nmea_ms >=
		    LICHEN_GPS_NO_FIX_MS) {
		((struct lichen_gps_uart_monitor *)monitor)->nofix_reported =
			true;
		return LICHEN_GPS_UART_NO_FIX;
	}

	return LICHEN_GPS_UART_HEALTHY;
}
