/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * Host test consuming test/vectors/rule_versioning.json
 * failure_tracker vectors (bead b7z9.67): bounded per-signer
 * consecutive decompression-failure tracker. Oracle: rust
 * lichen-schc context.rs RuleVersionFailureTracker and the committed
 * vector expected_results.
 */

#include <lichen/schc_failure_tracker.h>

#include <errno.h>
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

static void hex_to_32(const char *hex, uint8_t out[32])
{
	for (size_t i = 0; i < 32; i++) {
		unsigned int b;
		sscanf(&hex[i * 2], "%2x", &b);
		out[i] = (uint8_t)b;
	}
}

/* Vector: failure_tracker_capacity_fails_closed_without_eviction
 * capacity=1, threshold=2. Sources: A, B, A.
 * Expected: below_threshold, tracker_full, notify_operator. */
static void test_vector_capacity_fails_closed(void)
{
	struct lichen_schc_failure_tracker t;
	enum lichen_schc_ft_result r;
	uint8_t src_a[32], src_b[32], src_c[32];

	hex_to_32("d04ab232742bb4ab3a1368bd4615e4e6d0"
		  "224ab71a016baf8520a332c9778737", src_a);
	hex_to_32("17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce",
		  src_b);
	memcpy(src_c, src_a, 32); /* third call reuses source A */

	CHECK(lichen_schc_failure_tracker_init(&t, 2, 1) == 0,
	      "init capacity=1 threshold=2");

	/* Source A: first failure, count 1 < 2 -> below threshold. */
	r = lichen_schc_failure_tracker_record_failure(&t, src_a);
	CHECK(r == LICHEN_SCHC_FT_OK, "source A first failure below threshold");

	/* Source B: tracker full (capacity 1) -> fail closed, no eviction. */
	r = lichen_schc_failure_tracker_record_failure(&t, src_b);
	CHECK(r == LICHEN_SCHC_FT_FULL,
	      "source B rejected when tracker full");
	CHECK(lichen_schc_failure_tracker_capacity_events(&t) == 1,
	      "capacity event counted");

	/* Source A again: existing run preserved (not evicted by B). */
	r = lichen_schc_failure_tracker_record_failure(&t, src_a);
	CHECK(r == LICHEN_SCHC_FT_NOTIFY,
	      "source A second failure crosses threshold: notify");
}

static void test_threshold_one_notify_immediately(void)
{
	struct lichen_schc_failure_tracker t;
	uint8_t src[32];

	memset(src, 0xAB, 32);
	CHECK(lichen_schc_failure_tracker_init(&t, 1, 4) == 0,
	      "init threshold=1");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_NOTIFY,
	      "threshold 1 notifies on first failure");
	/* Second failure: already notified, no repeat. */
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "second failure does not re-notify");
}

static void test_success_clears_run(void)
{
	struct lichen_schc_failure_tracker t;
	uint8_t src[32];

	memset(src, 0xCD, 32);
	CHECK(lichen_schc_failure_tracker_init(&t, 3, 4) == 0, "init t=3");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "failure 1");
	/* Success clears the run. */
	lichen_schc_failure_tracker_record_success(&t, src);
	/* Next failure restarts from count 1 (no notification at 1). */
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "success clears consecutive run");
}

static void test_retire_clears_state(void)
{
	struct lichen_schc_failure_tracker t;
	uint8_t src[32];

	memset(src, 0xEF, 32);
	CHECK(lichen_schc_failure_tracker_init(&t, 2, 4) == 0, "retire init");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "retire: failure recorded");
	lichen_schc_failure_tracker_retire(&t, src);
	/* After retire, the signer gets a fresh run (no threshold carry). */
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "retire: fresh run after retire");
}

static void test_null_guards(void)
{
	struct lichen_schc_failure_tracker t;
	uint8_t src[32];

	memset(src, 1, 32);
	CHECK(lichen_schc_failure_tracker_init(NULL, 2, 4) == -EINVAL,
	      "init NULL rejected");
	CHECK(lichen_schc_failure_tracker_init(&t, 0, 4) == -EINVAL,
	      "zero threshold rejected");
	CHECK(lichen_schc_failure_tracker_init(&t, 2, 0) == -EINVAL,
	      "zero capacity rejected");
	CHECK(lichen_schc_failure_tracker_init(&t, 2, 17) == -EINVAL,
	      "capacity > max rejected");
	CHECK(lichen_schc_failure_tracker_record_failure(NULL, src) ==
		      LICHEN_SCHC_FT_INVALID,
	      "record NULL tracker rejected");
	lichen_schc_failure_tracker_record_success(NULL, src);
	lichen_schc_failure_tracker_retire(NULL, src);
	CHECK(lichen_schc_failure_tracker_capacity_events(NULL) == 0,
	      "capacity_events NULL -> 0");
}

/* Success-then-failure: clear resets count (vector: success_clears_run). */
static void test_success_then_failure(void)
{
	struct lichen_schc_failure_tracker t;
	uint8_t src[32];

	memset(src, 0xAB, 32);
	CHECK(lichen_schc_failure_tracker_init(&t, 3, 4) == 0, "stf: init");
	/* Three failures cross threshold (count 3 == 3). */
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "stf: failure 1 below");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "stf: failure 2 below");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_NOTIFY,
	      "stf: failure 3 notifies");
	/* Success clears. */
	lichen_schc_failure_tracker_record_success(&t, src);
	/* Next failure restarts from count 1 (no threshold carry). */
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "stf: post-success failure below threshold");
}

/* Retire-then-refail: retire clears state, refail starts fresh. */
static void test_retire_then_refail(void)
{
	struct lichen_schc_failure_tracker t;
	uint8_t src[32];

	memset(src, 0xEF, 32);
	CHECK(lichen_schc_failure_tracker_init(&t, 2, 4) == 0, "rtr: init");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "rtr: failure 1");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_NOTIFY,
	      "rtr: failure 2 notifies (threshold 2)");
	/* Retire clears the signer's state. */
	lichen_schc_failure_tracker_retire(&t, src);
	/* Refail starts fresh count 1 (below threshold 2). */
	CHECK(lichen_schc_failure_tracker_record_failure(&t, src) ==
		      LICHEN_SCHC_FT_OK,
	      "rtr: post-retire refail fresh count");
}

static void test_middle_clear_regression(void)
{
	struct lichen_schc_failure_tracker t;
	uint8_t a[32], b[32], c[32], d[32];

	memset(a, 0x01, 32);
	memset(b, 0x02, 32);
	memset(c, 0x03, 32);
	memset(d, 0x04, 32);
	CHECK(lichen_schc_failure_tracker_init(&t, 5, 3) == 0, "mc: init");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, a) == LICHEN_SCHC_FT_OK, "mc: A");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, b) == LICHEN_SCHC_FT_OK, "mc: B");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, c) == LICHEN_SCHC_FT_OK, "mc: C");
	lichen_schc_failure_tracker_record_success(&t, b);
	CHECK(lichen_schc_failure_tracker_record_failure(&t, d) ==
		      LICHEN_SCHC_FT_OK,
	      "mc: D takes B's slot");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, a) ==
		      LICHEN_SCHC_FT_OK,
	      "mc: A still tracked");
	CHECK(lichen_schc_failure_tracker_record_failure(&t, c) ==
		      LICHEN_SCHC_FT_OK,
	      "mc: C still tracked");
}

int main(void)
{
	test_vector_capacity_fails_closed();
	test_threshold_one_notify_immediately();
	test_success_clears_run();
	test_retire_clears_state();
	test_null_guards();
	test_success_then_failure();
	test_retire_then_refail();
	test_middle_clear_regression();

	if (failures == 0) {
		printf("PASS: schc_failure_tracker\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
