/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Unit tests for the SCHC session authority lifecycle (spec 5.6;
 *        bead l1qw.3.7.6.3): authenticated install, generation-currentness
 *        gate, revoke/reinstall generation isolation, silent-drop
 *        no-mutation, atomic all-or-nothing invalidation.
 */

#include <lichen/schc_authority.h>

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

static struct lichen_schc_identity mk_id2(uint8_t b0, uint8_t b1)
{
	struct lichen_schc_identity id;

	memset(&id.pubkey[0], 0, LICHEN_SCHC_IDENTITY_LEN);
	id.pubkey[0] = b0;
	id.pubkey[1] = b1;
	return id;
}

static struct lichen_schc_identity mk_id(uint8_t first)
{
	return mk_id2(first, 0);
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

static int test_init_zeroes(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	struct lichen_schc_identity r = mk_id(9);

	lichen_schc_authority_init(&a, &t);
	CHECK(a.table == &t, "table bound");
	CHECK(a.record_count == 0, "no records");
	CHECK(a.next_generation == 0, "issuer counter at 0");
	CHECK(!lichen_schc_authority_generation_current(&a, &r, 1),
	      "nothing current after init");
	return 1;
}

static int test_install_mints_fresh_generations(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	struct lichen_schc_identity ra = mk_id(2);
	struct lichen_schc_identity rb = mk_id(3);
	lichen_schc_generation_t ga = 0;
	lichen_schc_generation_t gb = 0;

	lichen_schc_authority_init(&a, &t);
	/* Authenticated DIO install: caller supplies the authenticated
	 * identity only; the authority mints the token. */
	CHECK(lichen_schc_authority_install(&a, &ra, &ga) == 0, "install A");
	CHECK(ga != LICHEN_SCHC_GENERATION_INVALID, "A got a real token");
	CHECK(lichen_schc_authority_install(&a, &rb, &gb) == 0, "install B");
	CHECK(gb != ga, "tokens distinct (no caller-selected authority)");
	CHECK(ga == 1 && gb == 2, "tokens minted monotonically from 1");
	CHECK(a.record_count == 2, "two records");
	return 1;
}

static int test_install_rejects_bad_args(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	struct lichen_schc_authority unbound;
	struct lichen_schc_identity r = mk_id(4);
	lichen_schc_generation_t gen = 55;

	lichen_schc_authority_init(&a, &t);
	memset(&unbound, 0, sizeof(unbound));
	CHECK(lichen_schc_authority_install(NULL, &r, &gen) == -EINVAL,
	      "NULL auth");
	CHECK(lichen_schc_authority_install(&a, NULL, &gen) == -EINVAL,
	      "NULL remote");
	CHECK(lichen_schc_authority_install(&a, &r, NULL) == -EINVAL,
	      "NULL out");
	CHECK(lichen_schc_authority_install(&unbound, &r, &gen) == -EINVAL,
	      "unbound authority (no table)");
	CHECK(gen == 55, "untouched out on early NULL failure");
	CHECK(lichen_schc_authority_revoke(NULL, &r) == -EINVAL,
	      "revoke NULL auth");
	CHECK(lichen_schc_authority_revoke(&a, NULL) == -EINVAL,
	      "revoke NULL remote");
	CHECK(lichen_schc_authority_revoke(&unbound, &r) == -EINVAL,
	      "revoke unbound authority");
	return 1;
}

static int test_currentness_gate(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	struct lichen_schc_identity ra = mk_id(5);
	struct lichen_schc_identity unknown = mk_id(6);
	lichen_schc_generation_t gen = 0;
	struct lichen_schc_ctx_key good = mk_key(1, 5, 0, 0x78);
	struct lichen_schc_ctx_key stale = mk_key(1, 5, 99, 0x78);
	struct lichen_schc_ctx_key nope = mk_key(1, 6, 1, 0x78);
	struct lichen_schc_ctx_key zero = mk_key(1, 5, 0, 0x78);

	lichen_schc_authority_init(&a, &t);
	CHECK(lichen_schc_authority_install(&a, &ra, &gen) == 0, "install");
	good.generation = gen;
	CHECK(lichen_schc_authority_key_current(&a, &good),
	      "minted generation current");
	CHECK(!lichen_schc_authority_key_current(&a, &stale),
	      "stale generation not current");
	CHECK(!lichen_schc_authority_key_current(&a, &nope),
	      "unknown signer not current");
	CHECK(!lichen_schc_authority_key_current(&a, &zero),
	      "GENERATION_INVALID never current");
	CHECK(!lichen_schc_authority_key_current(&a, NULL),
	      "NULL key not current");
	CHECK(!lichen_schc_authority_generation_current(NULL, &ra, gen),
	      "NULL auth not current");
	CHECK(!lichen_schc_authority_generation_current(&a, NULL, gen),
	      "NULL remote not current");
	CHECK(!lichen_schc_authority_generation_current(
		      &a, &unknown, gen),
	      "unknown remote not current");
	return 1;
}

static int test_atomic_replacement_invalidates_everything(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	struct lichen_schc_identity ra = mk_id(7);
	struct lichen_schc_identity rb = mk_id(8);
	lichen_schc_generation_t g1 = 0;
	lichen_schc_generation_t g2 = 0;
	lichen_schc_generation_t gb = 0;
	struct lichen_schc_context *ctx = NULL;
	struct lichen_schc_ctx_key a78 = mk_key(1, 7, 0, 0x78);
	struct lichen_schc_ctx_key a79 = mk_key(1, 7, 0, 0x79);
	struct lichen_schc_ctx_key b78 = mk_key(1, 8, 0, 0x78);

	lichen_schc_authority_init(&a, &t);
	CHECK(lichen_schc_authority_install(&a, &ra, &g1) == 0, "install A");
	CHECK(lichen_schc_authority_install(&a, &rb, &gb) == 0, "install B");
	a78.generation = g1;
	a79.generation = g1;
	b78.generation = gb;

	/* Populate every state class under A/g1, plus parallel B state. */
	CHECK(lichen_schc_ctx_alloc(&t, &a78, &ctx) == 0, "ctx 0x78");
	CHECK(lichen_schc_ctx_alloc(&t, &a79, &ctx) == 0, "ctx 0x79");
	CHECK(lichen_schc_tombstone_put(&t, &a78,
					LICHEN_SCHC_TERMINAL_COMPLETED, 5, 100) == 0,
	      "tombstone");
	CHECK(lichen_schc_floor_put(&t, &a78, 5) == 0, "floor");
	CHECK(lichen_schc_ctx_alloc(&t, &b78, &ctx) == 0, "B ctx");
	CHECK(lichen_schc_floor_put(&t, &b78, 3) == 0, "B floor");
	CHECK(t.context_count == 3 && t.tombstone_count == 1 &&
		      t.floor_count == 2,
	      "populated");

	/* Rotation: replacement DIO evidence for the SAME key. */
	CHECK(lichen_schc_authority_install(&a, &ra, &g2) == 0, "rotate A");
	CHECK(g2 != g1, "fresh token minted");

	/* All-or-nothing: every A/g1 entry retired... */
	CHECK(lichen_schc_ctx_find(&t, &a78) == NULL, "A ctx 0x78 gone");
	CHECK(lichen_schc_ctx_find(&t, &a79) == NULL, "A ctx 0x79 gone");
	CHECK(lichen_schc_tombstone_find(&t, &a78) == NULL,
	      "A tombstone gone");
	CHECK(lichen_schc_floor_find(&t, &a78) == NULL, "A floor gone");
	CHECK(t.context_count == 1 && t.tombstone_count == 0 &&
		      t.floor_count == 1,
	      "counts reflect full retirement");
	/* ...and nothing outside the retired (remote, generation) pair. */
	CHECK(lichen_schc_ctx_find(&t, &b78) != NULL, "B ctx intact");
	CHECK(lichen_schc_floor_find(&t, &b78) != NULL, "B floor intact");
	CHECK(lichen_schc_authority_key_current(&a, &b78),
	      "B generation still current");
	CHECK(!lichen_schc_authority_key_current(&a, &a78),
	      "old A generation retired");
	a78.generation = g2;
	CHECK(lichen_schc_authority_key_current(&a, &a78),
	      "new A generation current");
	return 1;
}

static int test_revoke_reinstall_same_key_isolated(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	struct lichen_schc_identity r = mk_id(10);
	lichen_schc_generation_t g1 = 0;
	lichen_schc_generation_t g2 = 0;
	struct lichen_schc_context *ctx = NULL;
	struct lichen_schc_ctx_key old_key = mk_key(1, 10, 0, 0x78);

	lichen_schc_authority_init(&a, &t);
	CHECK(lichen_schc_authority_install(&a, &r, &g1) == 0, "install");
	old_key.generation = g1;
	CHECK(lichen_schc_ctx_alloc(&t, &old_key, &ctx) == 0, "ctx");
	CHECK(lichen_schc_tombstone_put(&t, &old_key,
					LICHEN_SCHC_TERMINAL_SENDER_ABORT, 9,
					200) == 0,
	      "tombstone");
	CHECK(lichen_schc_floor_put(&t, &old_key, 9) == 0, "floor");

	CHECK(lichen_schc_authority_revoke(&a, &r) == 0, "revoke");
	CHECK(a.record_count == 0, "record dropped");
	CHECK(lichen_schc_ctx_find(&t, &old_key) == NULL, "ctx retired");
	CHECK(lichen_schc_tombstone_find(&t, &old_key) == NULL,
	      "tombstone retired");
	CHECK(lichen_schc_floor_find(&t, &old_key) == NULL, "floor retired");
	CHECK(!lichen_schc_authority_key_current(&a, &old_key),
	      "old generation not current");

	/* Same public key reinstalled: fresh, distinct, isolated generation. */
	CHECK(lichen_schc_authority_install(&a, &r, &g2) == 0, "reinstall");
	CHECK(g2 != g1 && g2 > g1, "fresh token, not resurrected");
	CHECK(!lichen_schc_authority_key_current(&a, &old_key),
	      "old state still unreachable after reinstall");
	CHECK(lichen_schc_ctx_find(&t, &old_key) == NULL,
	      "old ctx stays unreachable");
	CHECK(lichen_schc_floor_find(&t, &old_key) == NULL,
	      "old floor stays unreachable");
	return 1;
}

static int test_revoke_unknown_is_noop(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	struct lichen_schc_identity r = mk_id(11);
	struct lichen_schc_authority before;

	lichen_schc_authority_init(&a, &t);
	memcpy(&before, &a, sizeof(before));
	CHECK(lichen_schc_authority_revoke(&a, &r) == 0,
	      "revoke of unknown signer succeeds");
	CHECK(memcmp(&before, &a, sizeof(a)) == 0, "authority untouched");
	return 1;
}

static int test_unauthenticated_gate_mutates_nothing(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	static struct lichen_schc_session_table t_before;
	struct lichen_schc_authority a_before;
	struct lichen_schc_identity r = mk_id(12);
	lichen_schc_generation_t gen = 0;
	struct lichen_schc_context *ctx = NULL;
	struct lichen_schc_ctx_key key = mk_key(1, 12, 0, 0x78);
	struct lichen_schc_ctx_key forged = mk_key(1, 77, 42, 0x78);
	struct lichen_schc_ctx_key stale;

	lichen_schc_authority_init(&a, &t);
	CHECK(lichen_schc_authority_install(&a, &r, &gen) == 0, "install");
	key.generation = gen;
	CHECK(lichen_schc_ctx_alloc(&t, &key, &ctx) == 0, "live ctx");
	stale = key;
	stale.generation = gen + 1;

	memcpy(&t_before, &t, sizeof(t));
	memcpy(&a_before, &a, sizeof(a));

	/* Forged (unknown signer) and stale-generation control messages are
	 * silently dropped: the gate denies them and NOTHING mutates. */
	CHECK(!lichen_schc_authority_key_current(&a, &forged),
	      "forged control denied");
	CHECK(!lichen_schc_authority_key_current(&a, &stale),
	      "stale control denied");
	CHECK(memcmp(&t_before, &t, sizeof(t)) == 0, "table byte-identical");
	CHECK(memcmp(&a_before, &a, sizeof(a)) == 0,
	      "authority byte-identical");
	return 1;
}

static int test_record_cap_fails_closed(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	lichen_schc_generation_t gen = 0;
	lichen_schc_generation_t first_gen = 0;
	struct lichen_schc_identity first = mk_id2(0, 0);
	struct lichen_schc_identity extra = mk_id2(0xfe, 0xfe);

	lichen_schc_authority_init(&a, &t);
	for (size_t i = 0; i < LICHEN_SCHC_MAX_TRUST_RECORDS; i++) {
		struct lichen_schc_identity r =
			mk_id2((uint8_t)(i & 0xffU), (uint8_t)(i >> 8));

		CHECK(lichen_schc_authority_install(&a, &r, &gen) == 0,
		      "fill to cap");
		if (i == 0) {
			first_gen = gen;
		}
	}
	CHECK(a.record_count == LICHEN_SCHC_MAX_TRUST_RECORDS, "at cap");

	/* 257th install fails closed: no eviction of a current record. */
	CHECK(lichen_schc_authority_install(&a, &extra, &gen) == -ENOBUFS,
	      "overflow rejected");
	CHECK(gen == LICHEN_SCHC_GENERATION_INVALID,
	      "no token published on failure");
	CHECK(a.record_count == LICHEN_SCHC_MAX_TRUST_RECORDS,
	      "count unchanged");
	CHECK(lichen_schc_authority_generation_current(&a, &first, first_gen),
	      "first record not evicted");
	return 1;
}

static int test_replacement_at_full_capacity(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	lichen_schc_generation_t gen = 0;
	lichen_schc_generation_t g1 = 0;
	lichen_schc_generation_t g2 = 0;
	struct lichen_schc_identity first = mk_id2(0, 0);
	struct lichen_schc_context *ctx = NULL;
	struct lichen_schc_ctx_key old_key = mk_key(1, 0, 0, 0x78);

	lichen_schc_authority_init(&a, &t);
	for (size_t i = 0; i < LICHEN_SCHC_MAX_TRUST_RECORDS; i++) {
		struct lichen_schc_identity r =
			mk_id2((uint8_t)(i & 0xffU), (uint8_t)(i >> 8));

		CHECK(lichen_schc_authority_install(&a, &r, &gen) == 0,
		      "fill to cap");
		if (i == 0) {
			g1 = gen;
		}
	}
	old_key.generation = g1;
	CHECK(lichen_schc_ctx_alloc(&t, &old_key, &ctx) == 0, "g1 ctx");

	/* Rotation is a replacement, not a new record: it must succeed at
	 * full capacity, retire the old generation, and keep the count. */
	CHECK(lichen_schc_authority_install(&a, &first, &g2) == 0,
	      "replacement at cap succeeds");
	CHECK(g2 != g1, "fresh token");
	CHECK(a.record_count == LICHEN_SCHC_MAX_TRUST_RECORDS,
	      "count unchanged by replacement");
	CHECK(lichen_schc_ctx_find(&t, &old_key) == NULL,
	      "old-generation ctx retired at cap");
	CHECK(lichen_schc_authority_generation_current(&a, &first, g2),
	      "rotated record current");
	return 1;
}

static int test_generation_exhaustion_fails_closed(void)
{
	static struct lichen_schc_session_table t;
	static struct lichen_schc_authority a;
	struct lichen_schc_identity r = mk_id(13);
	lichen_schc_generation_t gen = 99;

	lichen_schc_authority_init(&a, &t);
	a.next_generation = UINT64_MAX; /* white-box: force the ceiling */
	CHECK(lichen_schc_authority_install(&a, &r, &gen) == -EOVERFLOW,
	      "mint exhaustion rejected");
	CHECK(gen == LICHEN_SCHC_GENERATION_INVALID,
	      "no token published on failure");
	CHECK(a.record_count == 0, "no record created");
	return 1;
}

int main(void)
{
	printf("schc_authority tests (spec 5.6 lifecycle):\n");
	RUN_TEST(test_init_zeroes);
	RUN_TEST(test_install_mints_fresh_generations);
	RUN_TEST(test_install_rejects_bad_args);
	RUN_TEST(test_currentness_gate);
	RUN_TEST(test_atomic_replacement_invalidates_everything);
	RUN_TEST(test_revoke_reinstall_same_key_isolated);
	RUN_TEST(test_revoke_unknown_is_noop);
	RUN_TEST(test_unauthenticated_gate_mutates_nothing);
	RUN_TEST(test_record_cap_fails_closed);
	RUN_TEST(test_replacement_at_full_capacity);
	RUN_TEST(test_generation_exhaustion_fails_closed);
	printf("schc_authority: %d/%d passed\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
