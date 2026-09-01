/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_failure_tracker.h
 * @brief Bounded per-signer consecutive SCHC decompression-failure
 *	  tracker (spec/03-adaptation.md 5.7; C port of rust
 *	  lichen-schc context.rs RuleVersionFailureTracker; bead b7z9.67).
 *
 * Tracks consecutive decompression failures keyed by the 32-byte
 * authenticated link signer. Capacity is bounded: when full, a new
 * signer fails closed (LICHEN_SCHC_FT_FULL) without evicting existing
 * runs. A threshold crossing emits exactly one notification per
 * consecutive run; a successful decompression clears only that signer.
 */

#ifndef LICHEN_SCHC_FAILURE_TRACKER_H_
#define LICHEN_SCHC_FAILURE_TRACKER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LICHEN_SCHC_FT_MAX_SOURCES 16u
#define LICHEN_SCHC_FT_SOURCE_LEN 32u

/** Per-signer entry. */
struct lichen_schc_ft_entry {
	bool used;
	uint8_t source[LICHEN_SCHC_FT_SOURCE_LEN];
	uint16_t count;
	bool notified;
};

/** Record outcome. */
enum lichen_schc_ft_result {
	LICHEN_SCHC_FT_OK = 0,	   /**< Recorded, threshold not reached */
	LICHEN_SCHC_FT_NOTIFY = 1, /**< Threshold crossed: notify operator */
	LICHEN_SCHC_FT_FULL = -1,  /**< Tracker full, new signer rejected */
	LICHEN_SCHC_FT_INVALID = -2,
};

/** Bounded failure tracker. Caller allocates statically. */
struct lichen_schc_failure_tracker {
	uint16_t threshold;
	uint16_t capacity;
	uint16_t entry_count;
	struct lichen_schc_ft_entry entries[LICHEN_SCHC_FT_MAX_SOURCES];
	uint64_t capacity_events;
};

/**
 * Initialize the tracker. threshold must be >= 1, capacity must be
 * >= 1 and <= LICHEN_SCHC_FT_MAX_SOURCES.
 * @return 0 on success, -EINVAL on invalid args.
 */
int lichen_schc_failure_tracker_init(struct lichen_schc_failure_tracker *t,
				     uint16_t threshold, uint16_t capacity);

/**
 * Record one decompression failure for the given signer.
 * @return LICHEN_SCHC_FT_NOTIFY when the threshold is crossed for the
 * first time in this consecutive run, LICHEN_SCHC_FT_OK when recorded
 * below threshold, LICHEN_SCHC_FT_FULL when the tracker is full (the
 * existing runs are preserved; capacity_events is incremented).
 */
enum lichen_schc_ft_result
lichen_schc_failure_tracker_record_failure(struct lichen_schc_failure_tracker *t,
					   const uint8_t source[LICHEN_SCHC_FT_SOURCE_LEN]);

/**
 * Clear the consecutive-failure run for a signer after a successful
 * decompression. No-op when the signer has no active run.
 */
void lichen_schc_failure_tracker_record_success(
	struct lichen_schc_failure_tracker *t,
	const uint8_t source[LICHEN_SCHC_FT_SOURCE_LEN]);

/**
 * Retire tracking state when the owning link retires/evicts this signer.
 * Same as record_success but explicit for link lifetime events.
 */
void lichen_schc_failure_tracker_retire(
	struct lichen_schc_failure_tracker *t,
	const uint8_t source[LICHEN_SCHC_FT_SOURCE_LEN]);

/** Number of failures that could not be assigned a bounded source slot. */
uint64_t lichen_schc_failure_tracker_capacity_events(
	const struct lichen_schc_failure_tracker *t);

#endif /* LICHEN_SCHC_FAILURE_TRACKER_H_ */
