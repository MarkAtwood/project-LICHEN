/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Unit tests for the bounded SCHC session state tables (spec 5.6;
 *        bead l1qw.3.7.6.2).
 */

#include <lichen/schc_session_table.h>

#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_passed;

#define RUN_TEST(fn)                        \
	do {                                \
		printf("  %s...", #fn);     \
		tests_run++;                \
		if (fn()) {                 \
			printf(" OK\n");    \
			tests_passed++;     \
		}                           \
	} while (0)

#define CHECK(cond, msg)                          \
	do {                                      \
		if (!(cond)) {                    \
			printf(" FAIL: %s\n", msg); \
			return 0;                 \
		}                                 \
	} while (0)

static struct lichen_schc_identity mk_id(uint8_t first)
{
	struct lichen_schc_identity id;

	memset(&id.pubkey[0], 0, LICHEN_SCHC_IDENTITY_LEN);
	id.pubkey[0] = first;
	return id;
}

static struct lichen_schc_ctx_key mk_key(uint8_t local, uint8_t remote,
					 uint64_t gen, uint8_t rule)
{
	struct lichen_schc_ctx_key k;

	k.local = mk_id(local);
	k.remote = mk_id(remote);
	k.generation = gen;
	k.rule_id = rule;
	return k;
}

static int test_key_equal_fields(void)
{
	struct lichen_schc_ctx_key a = mk_key(1, 2, 7, 0x78);
	struct lichen_schc_ctx_key same = mk_key(1, 2, 7, 0x78);
	struct lichen_schc_ctx_key diff_gen = mk_key(1, 2, 8, 0x78);
	struct lichen_schc_ctx_key diff_rule = mk_key(1, 2, 7, 0x79);
	struct lichen_schc_ctx_key diff_remote = mk_key(1, 3, 7, 0x78);

	CHECK(lichen_schc_ctx_key_equal(&a, &same), "identical keys equal");
	CHECK(!lichen_schc_ctx_key_equal(&a, &diff_gen), "generation differs");
	CHECK(!lichen_schc_ctx_key_equal(&a, &diff_rule), "rule differs");
	CHECK(!lichen_schc_ctx_key_equal(&a, &diff_remote), "remote differs");
	CHECK(!lichen_schc_ctx_key_equal(NULL, &a), "NULL not equal");
	return 1;
}

static int test_ctx_alloc_and_find(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_context *ctx = NULL;
	struct lichen_schc_ctx_key k = mk_key(1, 2, 1, 0x78);

	lichen_schc_table_init(&t);
	CHECK(lichen_schc_ctx_alloc(&t, &k, &ctx) == 0, "alloc succeeds");
	CHECK(ctx != NULL && ctx->occupied, "slot occupied");
	CHECK(lichen_schc_ctx_find(&t, &k) == ctx, "find returns slot");
	CHECK(t.context_count == 1, "count is 1");
	return 1;
}

static int test_ctx_alloc_idempotent_duplicate(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_context *a = NULL;
	struct lichen_schc_context *b = NULL;
	struct lichen_schc_ctx_key k = mk_key(1, 2, 1, 0x78);

	lichen_schc_table_init(&t);
	CHECK(lichen_schc_ctx_alloc(&t, &k, &a) == 0, "first alloc");
	CHECK(lichen_schc_ctx_alloc(&t, &k, &b) == 0, "dup alloc succeeds");
	CHECK(a == b, "duplicate returns same slot");
	CHECK(t.context_count == 1, "still one context");
	return 1;
}

static int test_ctx_per_signer_cap(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_context *ctx = NULL;

	lichen_schc_table_init(&t);
	/* Same remote signer (9), distinct rules -> up to 4 contexts. */
	for (uint8_t rule = 0; rule < LICHEN_SCHC_MAX_CTX_PER_SIGNER; rule++) {
		struct lichen_schc_ctx_key k =
			mk_key(1, 9, 1, (uint8_t)(0x80 + rule));

		CHECK(lichen_schc_ctx_alloc(&t, &k, &ctx) == 0,
		      "alloc within per-signer cap");
	}
	/* 5th context for the same signer must fail -EAGAIN. */
	struct lichen_schc_ctx_key fifth = mk_key(1, 9, 1, 0x99);

	CHECK(lichen_schc_ctx_alloc(&t, &fifth, &ctx) == -EAGAIN,
	      "5th context for signer rejected");
	CHECK(t.context_count == LICHEN_SCHC_MAX_CTX_PER_SIGNER,
	      "count capped at per-signer limit");
	return 1;
}

static int test_ctx_per_signer_cap_does_not_block_other_signer(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_context *ctx = NULL;

	lichen_schc_table_init(&t);
	for (uint8_t rule = 0; rule < LICHEN_SCHC_MAX_CTX_PER_SIGNER; rule++) {
		struct lichen_schc_ctx_key k =
			mk_key(1, 9, 1, (uint8_t)(0x80 + rule));

		CHECK(lichen_schc_ctx_alloc(&t, &k, &ctx) == 0, "fill signer 9");
	}
	/* A DIFFERENT signer still allocates. */
	struct lichen_schc_ctx_key other = mk_key(1, 10, 1, 0x78);

	CHECK(lichen_schc_ctx_alloc(&t, &other, &ctx) == 0,
	      "other signer unaffected by per-signer cap");
	return 1;
}

static int test_ctx_global_cap_no_evict(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_context *ctx = NULL;
	struct lichen_schc_ctx_key keys[LICHEN_SCHC_MAX_CONTEXTS];

	lichen_schc_table_init(&t);
	/* Fill the global table with distinct signers (4 each). */
	size_t n = 0;

	for (uint8_t signer = 1; n < LICHEN_SCHC_MAX_CONTEXTS; signer++) {
		for (uint8_t rule = 0;
		     rule < LICHEN_SCHC_MAX_CTX_PER_SIGNER &&
		     n < LICHEN_SCHC_MAX_CONTEXTS;
		     rule++, n++) {
			keys[n] = mk_key(1, signer, 1, (uint8_t)(0x80 + rule));
			CHECK(lichen_schc_ctx_alloc(&t, &keys[n], &ctx) == 0,
			      "fill global table");
		}
	}
	CHECK(t.context_count == LICHEN_SCHC_MAX_CONTEXTS, "table full");

	/* A fresh signer overflows: -ENOBUFS, and NO existing context evicted. */
	struct lichen_schc_ctx_key overflow = mk_key(1, 0xfe, 1, 0x78);

	CHECK(lichen_schc_ctx_alloc(&t, &overflow, &ctx) == -ENOBUFS,
	      "global exhaustion returns ENOBUFS");
	CHECK(t.context_count == LICHEN_SCHC_MAX_CONTEXTS,
	      "count unchanged after exhaustion");
	for (size_t i = 0; i < LICHEN_SCHC_MAX_CONTEXTS; i++) {
		CHECK(lichen_schc_ctx_find(&t, &keys[i]) != NULL,
		      "no active context evicted on exhaustion");
	}
	return 1;
}

static int test_tombstone_put_find(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_ctx_key k = mk_key(1, 2, 1, 0x78);
	struct lichen_schc_tombstone *ts;

	lichen_schc_table_init(&t);
	CHECK(lichen_schc_tombstone_put(&t, &k,
					LICHEN_SCHC_TERMINAL_COMPLETED, 100,
					5000) == 0,
	      "tombstone put");
	ts = lichen_schc_tombstone_find(&t, &k);
	CHECK(ts != NULL, "tombstone found");
	CHECK(ts->outcome == LICHEN_SCHC_TERMINAL_COMPLETED, "outcome stored");
	CHECK(ts->high_water == 100, "high water stored");
	CHECK(ts->terminal_time == 5000, "terminal time stored");
	CHECK(t.tombstone_count == 1, "count is 1");
	return 1;
}

static int test_tombstone_overflow_evicts_oldest_by_terminal_time(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_ctx_key oldest_key;

	lichen_schc_table_init(&t);
	/* Fill all 256 tombstone slots; the OLDEST terminal_time is slot 0. */
	for (size_t i = 0; i < LICHEN_SCHC_MAX_TOMBSTONES; i++) {
		struct lichen_schc_ctx_key k =
			mk_key(1, (uint8_t)i, 1, (uint8_t)(0x80 + (i % 2)));

		/* terminal_time increasing with i; i=0 has the smallest. */
		CHECK(lichen_schc_tombstone_put(&t, &k,
						LICHEN_SCHC_TERMINAL_COMPLETED,
						100, (uint32_t)(1000 + i)) == 0,
		      "fill tombstones");
		if (i == 0) {
			oldest_key = k;
		}
	}
	CHECK(t.tombstone_count == LICHEN_SCHC_MAX_TOMBSTONES, "tombstones full");
	CHECK(lichen_schc_tombstone_find(&t, &oldest_key) != NULL,
	      "oldest present before overflow");

	/* One more -> evicts the oldest (terminal_time 1000). */
	struct lichen_schc_ctx_key new_key = mk_key(1, 0xab, 1, 0x78);

	CHECK(lichen_schc_tombstone_put(&t, &new_key,
					LICHEN_SCHC_TERMINAL_COMPLETED, 100,
					9999) == 0,
	      "overflow put succeeds (eviction, not failure)");
	CHECK(t.tombstone_count == LICHEN_SCHC_MAX_TOMBSTONES,
	      "count still bounded");
	CHECK(lichen_schc_tombstone_find(&t, &oldest_key) == NULL,
	      "oldest tombstone evicted");
	CHECK(lichen_schc_tombstone_find(&t, &new_key) != NULL,
	      "new tombstone present");
	return 1;
}

static int test_tombstone_refresh_monotonic_high_water(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_ctx_key k = mk_key(1, 2, 1, 0x78);
	struct lichen_schc_tombstone *ts;

	lichen_schc_table_init(&t);
	CHECK(lichen_schc_tombstone_put(&t, &k, LICHEN_SCHC_TERMINAL_COMPLETED,
					100, 5000) == 0,
	      "initial terminal hw=100");
	/* A replayed captured terminal frame with a regressed high-water MUST
	 * NOT lower the stored session-wide greatest counter. */
	CHECK(lichen_schc_tombstone_put(&t, &k, LICHEN_SCHC_TERMINAL_COMPLETED,
					50, 6000) == 0,
	      "reterminal with lower hw=50");
	ts = lichen_schc_tombstone_find(&t, &k);
	CHECK(ts != NULL && ts->high_water == 100, "high-water not regressed");
	CHECK(ts->terminal_time == 6000, "terminal_time advanced to freshest");
	CHECK(t.tombstone_count == 1, "still one tombstone");
	/* A strictly newer counter DOES advance the high-water. */
	CHECK(lichen_schc_tombstone_put(&t, &k, LICHEN_SCHC_TERMINAL_COMPLETED,
					150, 7000) == 0,
	      "reterminal with newer hw=150");
	ts = lichen_schc_tombstone_find(&t, &k);
	CHECK(ts->high_water == 150, "high-water advanced on newer counter");
	/* A replay carrying an OLDER terminal_time MUST NOT regress the
	 * eviction/hold-down clock (decreasing direction). */
	CHECK(lichen_schc_tombstone_put(&t, &k, LICHEN_SCHC_TERMINAL_COMPLETED,
					150, 4000) == 0,
	      "reterminal with older terminal_time=4000");
	ts = lichen_schc_tombstone_find(&t, &k);
	CHECK(ts->terminal_time == 7000, "terminal_time not regressed");
	return 1;
}

static int test_floor_put_monotonic(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_ctx_key k = mk_key(1, 2, 1, 0x78);
	struct lichen_schc_floor *f;

	lichen_schc_table_init(&t);
	CHECK(lichen_schc_floor_put(&t, &k, 100) == 0, "floor put 100");
	CHECK(lichen_schc_floor_put(&t, &k, 50) == 0, "floor put lower 50");
	f = lichen_schc_floor_find(&t, &k);
	CHECK(f != NULL && f->high_water == 100, "floor not lowered");
	CHECK(lichen_schc_floor_put(&t, &k, 150) == 0, "floor raise to 150");
	f = lichen_schc_floor_find(&t, &k);
	CHECK(f->high_water == 150, "floor raised");
	CHECK(t.floor_count == 1, "one floor entry");
	return 1;
}

static int test_floor_overflow_evicts_smallest_high_water(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_ctx_key smallest_key;

	lichen_schc_table_init(&t);
	/* Fill all 256 floor slots with increasing high_water; i=0 smallest. */
	for (size_t i = 0; i < LICHEN_SCHC_MAX_FLOORS; i++) {
		struct lichen_schc_ctx_key k =
			mk_key(1, (uint8_t)i, 1, (uint8_t)(0x80 + (i % 2)));

		CHECK(lichen_schc_floor_put(&t, &k, (uint32_t)(100 + i)) == 0,
		      "fill floors");
		if (i == 0) {
			smallest_key = k;
		}
	}
	CHECK(t.floor_count == LICHEN_SCHC_MAX_FLOORS, "floors full");
	CHECK(lichen_schc_floor_find(&t, &smallest_key) != NULL,
	      "smallest floor present before overflow");

	/* One more -> evicts the floor with the SMALLEST high_water. */
	struct lichen_schc_ctx_key new_key = mk_key(1, 0xcd, 1, 0x78);

	CHECK(lichen_schc_floor_put(&t, &new_key, 9999) == 0,
	      "overflow floor put succeeds (eviction, not failure)");
	CHECK(t.floor_count == LICHEN_SCHC_MAX_FLOORS, "count still bounded");
	CHECK(lichen_schc_floor_find(&t, &smallest_key) == NULL,
	      "smallest-high_water floor evicted");
	CHECK(lichen_schc_floor_find(&t, &new_key) != NULL,
	      "new floor present");
	return 1;
}

static int test_invalidate_generation_atomic(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_context *ctx = NULL;
	struct lichen_schc_identity remote = mk_id(2);
	struct lichen_schc_ctx_key k_gen1 = mk_key(1, 2, 1, 0x78);
	struct lichen_schc_ctx_key k_gen2 = mk_key(1, 2, 2, 0x79);

	lichen_schc_table_init(&t);
	CHECK(lichen_schc_ctx_alloc(&t, &k_gen1, &ctx) == 0, "ctx gen1");
	CHECK(lichen_schc_ctx_alloc(&t, &k_gen2, &ctx) == 0, "ctx gen2");
	CHECK(lichen_schc_tombstone_put(&t, &k_gen1,
					LICHEN_SCHC_TERMINAL_COMPLETED, 1,
					100) == 0,
	      "tomb gen1");
	CHECK(lichen_schc_floor_put(&t, &k_gen1, 1) == 0, "floor gen1");

	/* Retire generation 1: only gen1 entries removed, gen2 survives. */
	int n = lichen_schc_table_invalidate_generation(&t, &remote, 1);

	CHECK(n == 3, "three gen1 entries invalidated");
	CHECK(lichen_schc_ctx_find(&t, &k_gen1) == NULL, "ctx gen1 gone");
	CHECK(lichen_schc_tombstone_find(&t, &k_gen1) == NULL, "tomb gen1 gone");
	CHECK(lichen_schc_floor_find(&t, &k_gen1) == NULL, "floor gen1 gone");
	CHECK(lichen_schc_ctx_find(&t, &k_gen2) != NULL, "ctx gen2 survives");
	CHECK(t.context_count == 1, "one context remains");
	return 1;
}

static int test_invalidate_generation_isolates_same_key_reinstall(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_context *ctx = NULL;
	struct lichen_schc_identity remote = mk_id(2);
	struct lichen_schc_ctx_key old_gen = mk_key(1, 2, 5, 0x78);

	lichen_schc_table_init(&t);
	CHECK(lichen_schc_ctx_alloc(&t, &old_gen, &ctx) == 0, "ctx old gen");
	/* Same key reinstalled under a NEW generation: invalidate old. */
	CHECK(lichen_schc_table_invalidate_generation(&t, &remote, 5) == 1,
	      "old generation retired");
	CHECK(lichen_schc_ctx_find(&t, &old_gen) == NULL, "old state gone");
	/* The new generation (different token) is unaffected by the retire. */
	struct lichen_schc_ctx_key new_gen = mk_key(1, 2, 6, 0x78);

	CHECK(lichen_schc_ctx_alloc(&t, &new_gen, &ctx) == 0, "new gen alloc");
	CHECK(lichen_schc_table_invalidate_generation(&t, &remote, 5) == 0,
	      "re-retire of old gen matches nothing");
	CHECK(lichen_schc_ctx_find(&t, &new_gen) != NULL, "new gen isolated");
	return 1;
}

static int test_null_arg_rejection(void)
{
	static struct lichen_schc_session_table t;
	struct lichen_schc_context *ctx = NULL;
	struct lichen_schc_ctx_key k = mk_key(1, 2, 1, 0x78);

	lichen_schc_table_init(&t);
	CHECK(lichen_schc_ctx_alloc(NULL, &k, &ctx) == -EINVAL, "alloc NULL tbl");
	CHECK(lichen_schc_ctx_alloc(&t, NULL, &ctx) == -EINVAL, "alloc NULL key");
	CHECK(lichen_schc_ctx_alloc(&t, &k, NULL) == -EINVAL, "alloc NULL out");
	CHECK(lichen_schc_tombstone_put(&t, NULL, LICHEN_SCHC_TERMINAL_COMPLETED,
					0, 0) == -EINVAL,
	      "tomb NULL key");
	CHECK(lichen_schc_floor_put(&t, NULL, 0) == -EINVAL, "floor NULL key");
	CHECK(lichen_schc_table_invalidate_generation(&t, NULL, 1) == -EINVAL,
	      "invalidate NULL remote");
	return 1;
}

int main(void)
{
	printf("SCHC session table (bounded state) tests\n");
	printf("========================================\n");

	RUN_TEST(test_key_equal_fields);
	RUN_TEST(test_ctx_alloc_and_find);
	RUN_TEST(test_ctx_alloc_idempotent_duplicate);
	RUN_TEST(test_ctx_per_signer_cap);
	RUN_TEST(test_ctx_per_signer_cap_does_not_block_other_signer);
	RUN_TEST(test_ctx_global_cap_no_evict);
	RUN_TEST(test_tombstone_put_find);
	RUN_TEST(test_tombstone_overflow_evicts_oldest_by_terminal_time);
	RUN_TEST(test_tombstone_refresh_monotonic_high_water);
	RUN_TEST(test_floor_put_monotonic);
	RUN_TEST(test_floor_overflow_evicts_smallest_high_water);
	RUN_TEST(test_invalidate_generation_atomic);
	RUN_TEST(test_invalidate_generation_isolates_same_key_reinstall);
	RUN_TEST(test_null_arg_rejection);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
