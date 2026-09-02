/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_failure_tracker.h
 * @brief Bounded consecutive decompression-failure tracker (spec 03 5.7).
 *
 * C port of rust/lichen-schc/src/context.rs RuleVersionFailureTracker:
 * production decompression ingress maintains a bounded consecutive-failure
 * tracker keyed by the authenticated link signer.
 *
 * Contract (spec/03-adaptation.md 5.7 Decompression Failure Handling):
 * - unknown rules / truncated or non-canonical residues / invalid
 *   decompressed packets increment that signer's consecutive count
 * - output-buffer or transport failure does NOT increment
 * - a successful decompression clears only that signer
 * - the threshold emits exactly one notification per consecutive run
 * - when the bounded table is full, fail closed for untracked signers
 *   and NEVER evict existing runs
 *
 * Merge note: the beads-worker-4 API is kept because the merged
 * production callers (link/link_ctx.c 2-arg init, link/lichen_link_rx.c
 * record/clear) and tests/schc_failure_tracker/src/main.c use it. The
 * other parent's richer variant (3-arg init with capacity parameter,
 * enum result, record_success/retire; bead b7z9.67) had no production
 * callers; its retire-on-link-lifetime intent is covered by
 * lichen_schc_failure_clear().
 */

#ifndef LICHEN_SCHC_FAILURE_TRACKER_H_
#define LICHEN_SCHC_FAILURE_TRACKER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Authenticated signer identity: 32-byte Ed25519 public key. */
#define LICHEN_SCHC_TRACKER_KEY_LEN 32U

/** Bounded number of concurrently tracked signers (spec 5.7 static memory). */
#define LICHEN_SCHC_TRACKER_MAX_SOURCES 16U

/** Tracker at capacity: the signer was not tracked (fail closed). */
#define LICHEN_SCHC_TRACKER_FULL (-2)

/** One signer's consecutive-failure run. */
struct lichen_schc_failure_entry {
	uint8_t pubkey[LICHEN_SCHC_TRACKER_KEY_LEN];
	uint16_t count;
	bool notified;
	bool active;
};

/**
 * @brief Bounded per-signer consecutive-failure tracker (static storage).
 */
struct lichen_schc_failure_tracker {
	uint16_t threshold;
	struct lichen_schc_failure_entry entries[LICHEN_SCHC_TRACKER_MAX_SOURCES];
	uint64_t capacity_events;
};

/**
 * @brief Construct a bounded tracker (zero threshold is invalid).
 */
void lichen_schc_failure_tracker_init(struct lichen_schc_failure_tracker *t,
				      uint16_t threshold);

/**
 * @brief Record one failure for @p pubkey and report a newly crossed
 *        threshold.
 * @return true exactly once per consecutive run at the threshold;
 *         false otherwise, or when the table is full and the signer is
 *         untracked (fail closed, no eviction; capacity_events increments).
 */
bool lichen_schc_failure_record(struct lichen_schc_failure_tracker *t,
				const uint8_t pubkey[LICHEN_SCHC_TRACKER_KEY_LEN]);

/** Clear the signer's consecutive-failure run after success. */
void lichen_schc_failure_clear(struct lichen_schc_failure_tracker *t,
			       const uint8_t pubkey[LICHEN_SCHC_TRACKER_KEY_LEN]);

/** Count of failures that could not be assigned a bounded slot. */
uint64_t lichen_schc_failure_capacity_events(
	const struct lichen_schc_failure_tracker *t);

#endif /* LICHEN_SCHC_FAILURE_TRACKER_H_ */
