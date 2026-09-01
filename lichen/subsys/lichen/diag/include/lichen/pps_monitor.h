/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file pps_monitor.h
 * @brief GPS PPS interrupt verification (diag.7, spec 02a 2a.10.5 family).
 *
 * After the first GPS fix, the node expects a 1 Hz pulse-per-second GPIO
 * interrupt from the GNSS module. This detector arms a 10-second timer on
 * the first fix; if the PPS interrupt count is still zero when the timer
 * fires, the PPS wiring or interrupt configuration is wrong and the
 * detector reports DIAG_GPS_NO_PPS. When working, it reports the measured
 * PPS rate (expected 1.000 Hz ± 1%).
 *
 * Freestanding (no kernel dependencies): counters and time are injected by
 * the caller.
 */

#ifndef LICHEN_PPS_MONITOR_H_
#define LICHEN_PPS_MONITOR_H_

#include <stdbool.h>
#include <stdint.h>

/** Grace period after first fix before the PPS check fires (ms). */
#define LICHEN_PPS_GRACE_MS 10000U

/** Expected PPS rate in millihertz (1.000 Hz). */
#define LICHEN_PPS_EXPECTED_MHZ 1000U

/** Tolerance around the expected rate (± 1%). */
#define LICHEN_PPS_TOLERANCE_MHZ 10U

/** Verification outcome. */
enum lichen_pps_status {
	LICHEN_PPS_PENDING = 0,  /**< Armed, grace period not yet elapsed */
	LICHEN_PPS_OK,           /**< Pulses present within tolerance */
	LICHEN_PPS_RATE_OFF,     /**< Pulses present but rate out of tolerance */
	LICHEN_PPS_NO_PPS,       /**< No pulses since arm (wiring/config fault) */
};

/** PPS monitor state. */
struct lichen_pps_monitor {
	bool armed;            /**< Timer started (first fix seen) */
	bool fix_seen;         /**< First GGA fix-quality > 0 observed */
	bool evaluated;        /**< First post-deadline verdict latched */
	uint64_t arm_ms;       /**< Monotonic ms when armed */
	uint64_t deadline_ms;  /**< arm_ms + grace period */
	uint32_t pps_count;    /**< PPS GPIO interrupt count since arm */
	uint32_t evaluated_count; /**< Count consumed by the last evaluation */
	uint64_t last_eval_ms; /**< Monotonic ms of the last evaluation */
	enum lichen_pps_status verdict; /**< Latched first post-deadline verdict */
};

/** Zero-initialize the monitor state (memset works too). */
void lichen_pps_monitor_init(struct lichen_pps_monitor *monitor);

/**
 * @brief Notify the monitor that the first GPS fix arrived.
 *
 * Arms the 10-second grace timer. Only the first call takes effect.
 */
void lichen_pps_monitor_on_fix(struct lichen_pps_monitor *mon,
			       int64_t now_ms);

/** Count one PPS GPIO interrupt. */
void lichen_pps_monitor_on_pps(struct lichen_pps_monitor *monitor);

/**
 * @brief Poll the monitor after the grace deadline.
 *
 * Returns PENDING while armed and the deadline has not passed. The first
 * post-deadline call evaluates the pulses over the grace window, latches
 * the verdict, and returns it; all later calls return the latched verdict
 * (idempotent — the health verdict never flaps across re-polls).
 *
 * @param monitor Monitor state (must be zero-initialized via
 *                lichen_pps_monitor_init)
 * @param now_ms  Current monotonic ms
 * @return PENDING, OK, RATE (rate out of tolerance), or NO_PPS
 */
enum lichen_pps_status lichen_pps_monitor_poll(
	struct lichen_pps_monitor *monitor, int64_t now_ms);

#endif /* LICHEN_PPS_MONITOR_H_ */
