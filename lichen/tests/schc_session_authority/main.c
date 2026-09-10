/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Unit tests for the SCHC session authority lifecycle (spec 5.6;
 *        bead l1qw.3.7.6.3): authenticated install, generation currentness
 *        gating, revoke/reinstall generation isolation, silent drop of
 *        unauthenticated fragments, atomic all-or-nothing invalidation.
 */

#include <lichen/schc_session_authority.h>

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

/* Populate one entry of each bounded class for (remote, gen). */
static void populate_all(struct lichen_schc_session_table *t, uint8_t remote,
			 uint64_t gen)
{
	struct lichen_schc_ctx_key k = mk_key(1, remote, gen, 0x78);
	struct lichen_schc_context *ctx = NULL;

	(void)lichen_schc_ctx_alloc(t, &k, &ctx);
	(void)lichen_schc_tombstone_put(t, &k, LICHEN_SCHC_TERMINAL_COMPLETED,
					100U, 500U);
	(void)lichen_schc_floor_put(t, &k, 100U);
}

static size_t entries_of_gen(struct lichen_schc_session_table *t,
			     uint8_t remote, uint64_t gen)
{
	struct lichen_schc_ctx_key k = mk_key(1, remote, gen, 0x78);
	size_t n = 0;

	if (lichen_schc_ctx_find(t, &k) != NULL) {
		n++;
	}
	if (lichen_schc_tombstone_find(t, &k) != NULL) {
		n++;
	}
	if (lichen_schc_floor_find(t, &k) != NULL) {
		n++;
	}
	return n;
}

static int test_install_issues_internal_generation(void)
{
	static struct lichen_schc_authority auth;
	static struct lichen_schc_session_table t;
	struct lichen_schc_identity remote = mk_id(7);
	struct lichen_schc_identity other = mk_id(8);
	lichen_schc_generation_t gen = 0;
	lichen_schc_generation_t gen2 = 0;

	lichen_schc_authority_init(&auth);
	lichen_schc_table_init(&t);

	/* NULL args rejected. */
	CHECK(lichen_schc_authority_install(NULL, &t, &remote, &gen) == -EINVAL,
	      "NULL auth rejected");
	CHECK(lichen_schc_authority_install(&auth, NULL, &remote, &gen) ==
		      -EINVAL,
	      "NULL table rejected");
	CHECK(lichen_schc_authority_install(&auth, &t, NULL, &gen) == -EINVAL,
	      "NULL remote rejected");
	CHECK(lichen_schc_authority_install(&auth, &t, &remote, NULL) ==
		      -EINVAL,
	      "NULL out rejected");

	/* Authenticated install issues a nonzero internal token. */
	CHECK(lichen_schc_authority_install(&auth, &t, &remote, &gen) == 0,
	      "install succeeds");
	CHECK(gen != 0U, "token 0 never issued");
	CHECK(lichen_schc_authority_current(&auth, &remote, gen),
	      "installed generation current");

	/* A distinct remote gets a distinct token (no shared generations). */
	CHECK(lichen_schc_authority_install(&auth, &t, &other, &gen2) == 0,
	      "second install succeeds");
	CHECK(gen2 != gen, "tokens are unique per install");
	CHECK(auth.count == 2, "two records");
	return 1;
}

static int test_currentness_gate(void)
{
	static struct lichen_schc_authority auth;
	static struct lichen_schc_session_table t;
	struct lichen_schc_identity remote = mk_id(7);
	struct lichen_schc_identity unknown = mk_id(9);
	lichen_schc_generation_t gen = 0;

	lichen_schc_authority_init(&auth);
	lichen_schc_table_init(&t);
	CHECK(lichen_schc_authority_install(&auth, &t, &remote, &gen) == 0,
	      "install");

	CHECK(lichen_schc_authority_current(&auth, &remote, gen),
	      "current token validates");
	CHECK(!lichen_schc_authority_current(&auth, &remote, gen + 1U),
	      "future token not current");
	CHECK(!lichen_schc_authority_current(&auth, &remote, 0U),
	      "token 0 never current");
	CHECK(!lichen_schc_authority_current(&auth, &unknown, gen),
	      "unknown remote not current");
	CHECK(!lichen_schc_authority_current(NULL, &remote, gen),
	      "NULL auth not current");
	CHECK(!lichen_schc_authority_current(&auth, NULL, gen),
	      "NULL remote not current");

	/* The gate: only authenticated + current admits. */
	CHECK(lichen_schc_authority_gate(&auth, &remote, gen, true) ==
		      LICHEN_SCHC_GATE_ADMIT,
	      "authenticated current admits");
	CHECK(lichen_schc_authority_gate(&auth, &remote, gen + 1U, true) ==
		      LICHEN_SCHC_GATE_DROP_STALE,
	      "future generation stale");
	CHECK(lichen_schc_authority_gate(&auth, &unknown, gen, true) ==
		      LICHEN_SCHC_GATE_DROP_STALE,
	      "unknown remote stale");
	CHECK(lichen_schc_authority_gate(NULL, &remote, gen, true) ==
		      LICHEN_SCHC_GATE_DROP_SILENT,
	      "NULL auth drops silently");
	return 1;
}

static int test_revoke_reinstall_generation_isolation(void)
{
	static struct lichen_schc_authority auth;
	static struct lichen_schc_session_table t;
	struct lichen_schc_identity remote = mk_id(7);
	lichen_schc_generation_t gen1 = 0;
	lichen_schc_generation_t gen2 = 0;

	lichen_schc_authority_init(&auth);
	lichen_schc_table_init(&t);
	CHECK(lichen_schc_authority_install(&auth, &t, &remote, &gen1) == 0,
	      "install gen1");
	populate_all(&t, 7, gen1);
	CHECK(entries_of_gen(&t, 7, gen1) == 3, "gen1 state present");

	/* Same-key revoke: every gen1 entry retired, record removed. */
	int invalidated = lichen_schc_authority_revoke(&auth, &t, &remote);

	CHECK(invalidated == 3, "revoke invalidated all three classes");
	CHECK(entries_of_gen(&t, 7, gen1) == 0, "gen1 state unreachable");
	CHECK(!lichen_schc_authority_current(&auth, &remote, gen1),
	      "gen1 no longer current");
	CHECK(lichen_schc_authority_gate(&auth, &remote, gen1, true) ==
		      LICHEN_SCHC_GATE_DROP_STALE,
	      "gen1 fragments dropped stale");

	/* Idempotent: a replayed revocation is a harmless no-op. */
	CHECK(lichen_schc_authority_revoke(&auth, &t, &remote) == 0,
	      "double revoke no-op");

	/* Reinstall of the SAME key: fresh isolated generation. */
	CHECK(lichen_schc_authority_install(&auth, &t, &remote, &gen2) == 0,
	      "reinstall succeeds");
	CHECK(gen2 != gen1, "reinstall never resumes retired generation");
	CHECK(lichen_schc_authority_gate(&auth, &remote, gen1, true) ==
		      LICHEN_SCHC_GATE_DROP_STALE,
	      "old generation still stale after reinstall");
	CHECK(lichen_schc_authority_gate(&auth, &remote, gen2, true) ==
		      LICHEN_SCHC_GATE_ADMIT,
	      "new generation admits");
	return 1;
}

static int test_replacement_install_invalidates_atomically(void)
{
	static struct lichen_schc_authority auth;
	static struct lichen_schc_session_table t;
	struct lichen_schc_identity remote = mk_id(7);
	struct lichen_schc_identity bystander = mk_id(8);
	lichen_schc_generation_t gen1 = 0;
	lichen_schc_generation_t gen2 = 0;
	lichen_schc_generation_t genb = 0;

	lichen_schc_authority_init(&auth);
	lichen_schc_table_init(&t);
	CHECK(lichen_schc_authority_install(&auth, &t, &remote, &gen1) == 0,
	      "install remote gen1");
	CHECK(lichen_schc_authority_install(&auth, &t, &bystander, &genb) ==
		      0,
	      "install bystander");
	populate_all(&t, 7, gen1);
	populate_all(&t, 8, genb);

	/* Replacement = reinstall of the same key WITHOUT an explicit
	 * revoke: all-or-nothing retirement of gen1 state; bystander
	 * generation untouched. */
	CHECK(lichen_schc_authority_install(&auth, &t, &remote, &gen2) == 0,
	      "replacement install");
	CHECK(gen2 != gen1, "fresh generation issued");
	CHECK(entries_of_gen(&t, 7, gen1) == 0,
	      "retired generation fully invalidated");
	CHECK(entries_of_gen(&t, 8, genb) == 3, "bystander state untouched");
	CHECK(t.context_count == 1 && t.tombstone_count == 1 &&
		      t.floor_count == 1,
	      "only bystander entries remain");
	return 1;
}

static int test_unauthenticated_fragment_drops_without_mutation(void)
{
	static struct lichen_schc_authority auth;
	static struct lichen_schc_session_table t;
	struct lichen_schc_identity remote = mk_id(7);
	lichen_schc_generation_t gen = 0;

	lichen_schc_authority_init(&auth);
	lichen_schc_table_init(&t);
	CHECK(lichen_schc_authority_install(&auth, &t, &remote, &gen) == 0,
	      "install");
	populate_all(&t, 7, gen);

	size_t ctx_before = t.context_count;
	size_t tomb_before = t.tombstone_count;
	size_t floor_before = t.floor_count;

	/* A forged (unauthenticated) control at the CURRENT generation:
	 * silently dropped, no control response, no state mutation. */
	CHECK(lichen_schc_authority_gate(&auth, &remote, gen, false) ==
		      LICHEN_SCHC_GATE_DROP_SILENT,
	      "forged control silently dropped");
	CHECK(t.context_count == ctx_before && t.tombstone_count == tomb_before &&
		      t.floor_count == floor_before,
	      "no state mutated by the drop");
	CHECK(entries_of_gen(&t, 7, gen) == 3, "gen state intact");

	/* A forged fragment at an UNKNOWN generation: same silent drop. */
	CHECK(lichen_schc_authority_gate(&auth, &remote, 0xdeadU, false) ==
		      LICHEN_SCHC_GATE_DROP_SILENT,
	      "forged unknown-generation fragment dropped");
	CHECK(t.context_count == ctx_before, "still no mutation");

	/* Authenticated but stale generation: dropped, no response, and no
	 * mutation (retired-generation state must stay unreachable). */
	CHECK(lichen_schc_authority_revoke(&auth, &t, &remote) == 3,
	      "revoke retires generation");
	CHECK(lichen_schc_authority_gate(&auth, &remote, gen, true) ==
		      LICHEN_SCHC_GATE_DROP_STALE,
	      "stale authenticated fragment dropped");
	CHECK(t.context_count == 0 && t.tombstone_count == 0 &&
		      t.floor_count == 0,
	      "drop cannot resurrect retired state");
	return 1;
}

static int test_authority_capacity_fails_closed(void)
{
	static struct lichen_schc_authority auth;
	static struct lichen_schc_session_table t;
	lichen_schc_generation_t gen = 0;

	lichen_schc_authority_init(&auth);
	lichen_schc_table_init(&t);

	for (uint8_t i = 0; i < LICHEN_SCHC_MAX_AUTHORITIES; i++) {
		struct lichen_schc_identity remote = mk_id((uint8_t)(i + 1));

		CHECK(lichen_schc_authority_install(&auth, &t, &remote,
						    &gen) == 0,
		      "install within capacity");
	}
	struct lichen_schc_identity overflow = mk_id(0xff);

	CHECK(lichen_schc_authority_install(&auth, &t, &overflow, &gen) ==
		      -ENOBUFS,
	      "33rd trust record fails closed");
	CHECK(auth.count == LICHEN_SCHC_MAX_AUTHORITIES,
	      "no live record evicted");
	/* Existing records still function after the refused install. */
	struct lichen_schc_identity first = mk_id(1);

	CHECK(lichen_schc_authority_gate(&auth, &first, 1U, true) ==
		      LICHEN_SCHC_GATE_ADMIT,
	      "existing record still admits");
	return 1;
}

int main(void)
{
	printf("schc_session_authority tests (spec 5.6, l1qw.3.7.6.3)\n");
	RUN_TEST(test_install_issues_internal_generation);
	RUN_TEST(test_currentness_gate);
	RUN_TEST(test_revoke_reinstall_generation_isolation);
	RUN_TEST(test_replacement_install_invalidates_atomically);
	RUN_TEST(test_unauthenticated_fragment_drops_without_mutation);
	RUN_TEST(test_authority_capacity_fails_closed);
	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
