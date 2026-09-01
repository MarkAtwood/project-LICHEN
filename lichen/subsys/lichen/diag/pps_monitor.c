/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file pps_monitor.c
 * @brief GPS PPS interrupt verification (diag.7, spec 02a 2a.10.5 family).
 */

#include <lichen/pps_monitor.h>

#include <string.h>

void lichen_pps_monitor_init(struct lichen_pps_monitor *monitor)
{
	if (monitor != NULL) {
		memset(monitor, 0, sizeof(*monitor));
	}
}

void lichen_pps_monitor_on_fix(struct lichen_pps_monitor *monitor,
			       int64_t now_ms)
{
	if (monitor == NULL || monitor->fix_seen) {
		return;
	}
	monitor->fix_seen = true;
	monitor->armed = true;
	monitor->arm_ms = (uint64_t)now_ms;
	monitor->deadline_ms = monitor->arm_ms + LICHEN_PPS_GRACE_MS;
}

void lichen_pps_monitor_on_pps(struct lichen_pps_monitor *monitor)
{
	if (monitor == NULL || !monitor->armed) {
		return;
	}
	monitor->pps_count++;
}

enum lichen_pps_status lichen_pps_monitor_poll(
	struct lichen_pps_monitor *monitor, int64_t now_ms)
{
	if (monitor == NULL || !monitor->armed) {
		return LICHEN_PPS_PENDING;
	}
	if ((uint64_t)now_ms < monitor->deadline_ms) {
		return LICHEN_PPS_PENDING;
	}

	/* First post-deadline evaluation: latch the verdict (rate over the
	 * full grace window). Later calls return the latched verdict so the
	 * health result never flaps across re-polls. */
	if (monitor->evaluated) {
		return monitor->verdict;
	}
	monitor->evaluated = true;
	monitor->last_eval_ms = (uint64_t)now_ms;
	monitor->evaluated_count = monitor->pps_count;

	if (monitor->pps_count == 0U) {
		/* No interrupts: PPS GPIO or interrupt config fault. */
		monitor->verdict = LICHEN_PPS_NO_PPS;
		return monitor->verdict;
	}

	/* Observed rate in millihertz over the grace window. */
	uint64_t elapsed_ms = (uint64_t)now_ms - monitor->arm_ms;
	if (elapsed_ms == 0U) {
		monitor->verdict = LICHEN_PPS_PENDING;
		return monitor->verdict;
	}
	uint64_t observed_mhz =
	    (uint64_t)monitor->pps_count * 1000U * 1000U / elapsed_ms;

	if (observed_mhz + LICHEN_PPS_TOLERANCE_MHZ <
		    LICHEN_PPS_EXPECTED_MHZ ||
	    observed_mhz >
		    LICHEN_PPS_EXPECTED_MHZ + LICHEN_PPS_TOLERANCE_MHZ) {
		monitor->verdict = LICHEN_PPS_RATE_OFF;
	} else {
		monitor->verdict = LICHEN_PPS_OK;
	}
	return monitor->verdict;
}
