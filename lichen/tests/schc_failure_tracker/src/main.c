/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Consecutive decompression-failure tracker tests (spec 03 5.7, bead
 * b7z9.67): per-signer bounded accounting mirroring the Rust
 * RuleVersionFailureTracker. */

#include <lichen/schc_failure_tracker.h>

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("FAIL: %s\n", msg);                             \
			failures++;                                            \
		}                                                              \
	} while (0)

static void make_key(uint8_t out[LICHEN_SCHC_TRACKER_KEY_LEN], uint8_t last)
{
	memset(out, 0, LICHEN_SCHC_TRACKER_KEY_LEN);
	out[LICHEN_SCHC_TRACKER_KEY_LEN - 1U] = last;
}

int main(void)
{
	struct lichen_schc_failure_tracker t;
	uint8_t k1[LICHEN_SCHC_TRACKER_KEY_LEN];
	uint8_t k2[LICHEN_SCHC_TRACKER_KEY_LEN];
	uint8_t k3[LICHEN_SCHC_TRACKER_KEY_LEN];

	make_key(k1, 1);
	make_key(k2, 2);
	/* Distinct from the fill keys (which use last bytes 1..16). */
	make_key(k3, 0xEE);

	/* 1. Notification exactly once per run at the threshold. */
	lichen_schc_failure_tracker_init(&t, 3);
	CHECK(!lichen_schc_failure_record(&t, k1), "run: 1st no notify");
	CHECK(!lichen_schc_failure_record(&t, k1), "run: 2nd not notified");
	CHECK(lichen_schc_failure_record(&t, k1), "run: 3rd notifies once");
	CHECK(!lichen_schc_failure_record(&t, k1), "run: no re-notify");
	CHECK(lichen_schc_failure_capacity_events(&t) == 0U,
	      "no capacity events yet");

	/* 2. Success clears only that signer. */
	lichen_schc_failure_clear(&t, k1);
	CHECK(!lichen_schc_failure_record(&t, k1), "after clear: 1st");
	CHECK(!lichen_schc_failure_record(&t, k1), "after clear: 2nd");
	CHECK(lichen_schc_failure_record(&t, k1), "after clear: notify again");
	/* Clear of an unrelated key must not disturb k1's run. */
	lichen_schc_failure_clear(&t, k2);
	lichen_schc_failure_clear(&t, k1);
	CHECK(!lichen_schc_failure_record(&t, k1) &&
		      !lichen_schc_failure_record(&t, k1),
	      "k1 run restarted from zero after its own clear");

	/* 3. Fail closed at capacity: untracked signer gets no notification
	 * and existing runs are NOT evicted. */
	lichen_schc_failure_tracker_init(&t, 2);
	uint8_t keys[LICHEN_SCHC_TRACKER_MAX_SOURCES][LICHEN_SCHC_TRACKER_KEY_LEN];
	for (size_t i = 0U; i < LICHEN_SCHC_TRACKER_MAX_SOURCES; i++) {
		make_key(keys[i], (uint8_t)(i + 1U));
		CHECK(!lichen_schc_failure_record(&t, keys[i]),
		      "fill: first failure of each signer");
	}
	CHECK(!lichen_schc_failure_record(&t, k3),
	      "untracked signer at capacity fails closed");
	CHECK(lichen_schc_failure_capacity_events(&t) == 1U,
	      "capacity event counted");
	CHECK(lichen_schc_failure_record(&t, keys[0]),
	      "existing run survived capacity pressure");

	/* 4. Threshold 1: every first failure notifies. */
	lichen_schc_failure_tracker_init(&t, 1);
	CHECK(lichen_schc_failure_record(&t, k1), "threshold 1 notifies");
	CHECK(!lichen_schc_failure_record(&t, k1), "no re-notify at threshold 1");

	/* 5. Zero threshold disables tracking. */
	lichen_schc_failure_tracker_init(&t, 0);
	CHECK(!lichen_schc_failure_record(&t, k1), "zero threshold inert");

	/* 6. NULL guards. */
	lichen_schc_failure_tracker_init(&t, 3);
	CHECK(!lichen_schc_failure_record(&t, NULL), "NULL pubkey rejected");
	lichen_schc_failure_clear(&t, NULL);
	CHECK(!lichen_schc_failure_record(NULL, k1), "NULL tracker rejected");

	if (failures == 0) {
		printf("PASS: schc_failure_tracker\n");
	}
	return failures == 0 ? 0 : 1;
}
