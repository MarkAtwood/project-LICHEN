/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Unit tests for the SCHC session control authority (spec 5.6; bead
 *        l1qw.3.7.6.5): control authorization gating, ACK-REQ/ACK
 *        classification, 4-ACK-then-abort, tombstone idempotent replay
 *        within the hold-down, floor persistence after expiry, and atomic
 *        output/state on every error.
 */

#include <lichen/schc_session_control.h>

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

#define NOW 1000U

static struct lichen_schc_identity mk_id(uint8_t first)
{
	struct lichen_schc_identity id;

	memset(&id.pubkey[0], 0, LICHEN_SCHC_IDENTITY_LEN);
	id.pubkey[0] = first;
	return id;
}

/* A control authority with remote (9) installed; key + generation filled. */
static void setup(struct lichen_schc_control *ctl,
		  struct lichen_schc_ctx_key *key,
		  lichen_schc_generation_t *gen)
{
	struct lichen_schc_identity remote = mk_id(9);

	lichen_schc_control_init(ctl);
	*gen = 0;
	(void)lichen_schc_control_install(ctl, &remote, gen);
	key->local = mk_id(1);
	key->remote = remote;
	key->generation = *gen;
	key->rule_id = LICHEN_SCHC_RULE_B_TO_A;
}

/* ── ACK-REQ / C=0-ACK ambiguity classification ────────────────────────────*/

static int test_classification_from_authenticated_role(void)
{
	/* Data sender A (rule 0x78): a blob from A is an ACK REQ, the same
	 * blob from B is the C=0 ACK. */
	CHECK(lichen_schc_control_classify(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_ENDPOINT_A, 0x78) ==
		      LICHEN_SCHC_CLASS_ACK_REQ,
	      "sender==data sender -> ACK REQ");
	CHECK(lichen_schc_control_classify(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_ENDPOINT_B, 0x78) ==
		      LICHEN_SCHC_CLASS_ACK,
	      "sender==receiver -> ACK");
	/* Data sender B (rule 0x79): mirror image. */
	CHECK(lichen_schc_control_classify(LICHEN_SCHC_ENDPOINT_B,
					   LICHEN_SCHC_ENDPOINT_B, 0x79) ==
		      LICHEN_SCHC_CLASS_ACK_REQ,
	      "B-sender ACK REQ");
	CHECK(lichen_schc_control_classify(LICHEN_SCHC_ENDPOINT_B,
					   LICHEN_SCHC_ENDPOINT_A, 0x79) ==
		      LICHEN_SCHC_CLASS_ACK,
	      "A-receiver ACK");
	/* Rule/direction mismatches reject before any decode. */
	CHECK(lichen_schc_control_classify(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_ENDPOINT_A, 0x79) ==
		      LICHEN_SCHC_CLASS_INVALID,
	      "wrong rule rejects");
	CHECK(lichen_schc_control_classify(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_ENDPOINT_A, 0x00) ==
		      LICHEN_SCHC_CLASS_INVALID,
	      "foreign rule rejects");
	/* Out-of-range roles reject (fails closed). */
	CHECK(lichen_schc_control_classify(
		      (enum lichen_schc_endpoint)9, LICHEN_SCHC_ENDPOINT_A,
		      0x78) == LICHEN_SCHC_CLASS_INVALID,
	      "bad data-sender role rejects");
	CHECK(lichen_schc_control_classify(LICHEN_SCHC_ENDPOINT_A,
					   (enum lichen_schc_endpoint)9,
					   0x78) == LICHEN_SCHC_CLASS_INVALID,
	      "bad sender role rejects");
	return 1;
}

/* ── Control authorization gating ──────────────────────────────────────────*/

static int test_control_requires_authenticated_current_generation(void)
{
	static struct lichen_schc_control ctl;
	struct lichen_schc_ctx_key key;
	lichen_schc_generation_t gen;
	enum lichen_schc_control_response resp;

	setup(&ctl, &key, &gen);

	/* A control at the WRONG generation is dropped without response and
	 * without state mutation. */
	struct lichen_schc_ctx_key stale = key;

	stale.generation = gen + 1U;
	CHECK(lichen_schc_control_open(&ctl, &stale, 0, 62, 10, &resp) == 0,
	      "stale-generation open returns success");
	CHECK(resp == LICHEN_SCHC_RESP_NONE, "stale open dropped silently");
	CHECK(!lichen_schc_control_session_active(&ctl, &stale),
	      "no session created");
	CHECK(ctl.table.context_count == 0, "no context allocated");

	/* ACK REQ with no session and no tombstone: silent drop. */
	CHECK(lichen_schc_control_ack_request(&ctl, &key, 10, NOW, &resp) == 0,
	      "ACK REQ without session succeeds");
	CHECK(resp == LICHEN_SCHC_RESP_NONE, "dropped silently");
	return 1;
}

/* ── Open admission ────────────────────────────────────────────────────────*/

static int test_open_admission_rules(void)
{
	static struct lichen_schc_control ctl;
	struct lichen_schc_ctx_key key;
	lichen_schc_generation_t gen;
	enum lichen_schc_control_response resp;

	setup(&ctl, &key, &gen);

	/* Non-opener FCNs never open a session. */
	CHECK(lichen_schc_control_open(&ctl, &key, 0, 61, 10, &resp) == 0 &&
		      resp == LICHEN_SCHC_RESP_NONE,
	      "FCN 61 does not open");
	CHECK(lichen_schc_control_open(&ctl, &key, 0, 63, 10, &resp) == 0 &&
		      resp == LICHEN_SCHC_RESP_NONE,
	      "All-1 never opens");
	CHECK(lichen_schc_control_open(&ctl, &key, 1, 62, 10, &resp) == 0 &&
		      resp == LICHEN_SCHC_RESP_NONE,
	      "W=1 opener never opens");
	CHECK(!lichen_schc_control_session_active(&ctl, &key), "no session");

	/* Canonical opener opens; opening counter pins the high-water. */
	CHECK(lichen_schc_control_open(&ctl, &key, 0, 62, 10, &resp) == 0 &&
		      resp == LICHEN_SCHC_RESP_NONE,
	      "canonical opener opens (no response owed)");
	CHECK(lichen_schc_control_session_active(&ctl, &key),
	      "session active");
	uint32_t hw = 0;

	CHECK(lichen_schc_control_high_water(&ctl, &key, &hw) && hw == 10,
	      "opening counter is the high-water");

	/* A second opener for the same session is a duplicate, not a new
	 * session, and mutates nothing. */
	CHECK(lichen_schc_control_open(&ctl, &key, 0, 62, 11, &resp) == 0 &&
		      resp == LICHEN_SCHC_RESP_NONE,
	      "duplicate opener dropped");
	CHECK(lichen_schc_control_high_water(&ctl, &key, &hw) && hw == 10,
	      "high-water unmoved by duplicate");
	return 1;
}

/* ── 4-ACK-then-abort ──────────────────────────────────────────────────────*/

static int test_four_acks_then_receiver_abort_and_holddown(void)
{
	static struct lichen_schc_control ctl;
	struct lichen_schc_ctx_key key;
	lichen_schc_generation_t gen;
	enum lichen_schc_control_response resp;

	setup(&ctl, &key, &gen);
	(void)lichen_schc_control_open(&ctl, &key, 0, 62, 10, &resp);

	/* Four ACK responses, counters strictly increasing. */
	for (uint32_t i = 1; i <= LICHEN_SCHC_MAX_ACK_RESPONSES; i++) {
		CHECK(lichen_schc_control_ack_request(&ctl, &key, 10 + i,
						      NOW, &resp) == 0 &&
			      resp == LICHEN_SCHC_RESP_ACK,
		      "ACK emitted");
	}
	uint8_t count = 0;

	CHECK(lichen_schc_control_ack_count(&ctl, &key, &count) && count == 4,
	      "four ACKs counted");

	/* The 5th otherwise-valid All-1/ACK REQ: Receiver-Abort + terminal
	 * hold-down. */
	CHECK(lichen_schc_control_ack_request(&ctl, &key, 15, NOW, &resp) ==
		      0 && resp == LICHEN_SCHC_RESP_RECEIVER_ABORT,
	      "5th request triggers Receiver-Abort");
	CHECK(!lichen_schc_control_session_active(&ctl, &key),
	      "session retired");

	/* Hold-down: a strictly newer repeated request replays the SAME
	 * terminal response idempotently without starting a session. */
	enum lichen_schc_terminal outcome;

	CHECK(lichen_schc_control_ack_request(&ctl, &key, 16, NOW + 1,
					      &resp) == 0 &&
		      resp == LICHEN_SCHC_RESP_REPLAY,
	      "newer late request replays");
	CHECK(lichen_schc_control_late(&ctl, &key, 17, NOW + 2, &resp,
				       &outcome) == 0 &&
		      resp == LICHEN_SCHC_RESP_REPLAY &&
		      outcome == LICHEN_SCHC_TERMINAL_RECEIVER_ABORT,
	      "late path replays abort outcome");
	CHECK(!lichen_schc_control_session_active(&ctl, &key),
	      "replay does not start a session");

	/* A stale counter within the hold-down: silent drop, no replay. */
	CHECK(lichen_schc_control_late(&ctl, &key, 16, NOW + 3, &resp,
				       &outcome) == 0 &&
		      resp == LICHEN_SCHC_RESP_NONE,
	      "stale late counter dropped");
	return 1;
}

/* ── Tombstone hold-down expiry + floor persistence ────────────────────────*/

static int test_floor_persists_after_holddown_expiry(void)
{
	static struct lichen_schc_control ctl;
	struct lichen_schc_ctx_key key;
	lichen_schc_generation_t gen;
	enum lichen_schc_control_response resp;

	setup(&ctl, &key, &gen);
	(void)lichen_schc_control_open(&ctl, &key, 0, 62, 10, &resp);
	(void)lichen_schc_control_accept(&ctl, &key, 42);
	CHECK(lichen_schc_control_terminate(
		      &ctl, &key, LICHEN_SCHC_TERMINAL_COMPLETED, NOW) == 0,
	      "terminate succeeds");

	/* Tombstone replays within the window... */
	enum lichen_schc_terminal outcome;

	CHECK(lichen_schc_control_late(&ctl, &key, 43, NOW + 59, &resp,
				       &outcome) == 0 &&
		      resp == LICHEN_SCHC_RESP_REPLAY &&
		      outcome == LICHEN_SCHC_TERMINAL_COMPLETED,
	      "replay at NOW+59");

	/* ...and after 60s the high-water remains as the durable admission
	 * floor while late messages no longer replay. */
	CHECK(lichen_schc_control_late(&ctl, &key, 44, NOW + 60, &resp,
				       &outcome) == 0 &&
		      resp == LICHEN_SCHC_RESP_NONE,
	      "no replay after hold-down");
	uint32_t floor = 0;

	CHECK(lichen_schc_control_floor(&ctl, &key, &floor) && floor == 43,
	      "floor persists the generation high-water");

	/* The floor gates the NEXT session: an opener at/below it is stale. */
	CHECK(lichen_schc_control_open(&ctl, &key, 0, 62, 43, &resp) == 0 &&
		      resp == LICHEN_SCHC_RESP_NONE &&
		      !lichen_schc_control_session_active(&ctl, &key),
	      "opener at floor stale");
	CHECK(lichen_schc_control_open(&ctl, &key, 0, 62, 44, &resp) == 0 &&
		      lichen_schc_control_session_active(&ctl, &key),
	      "opener above floor starts next session");
	return 1;
}

/* ── Atomicity on error paths ──────────────────────────────────────────────*/

static int test_errors_are_atomic(void)
{
	static struct lichen_schc_control ctl;
	struct lichen_schc_ctx_key key;
	lichen_schc_generation_t gen;
	enum lichen_schc_control_response resp;

	setup(&ctl, &key, &gen);

	/* NULL-arg errors mutate nothing. */
	CHECK(lichen_schc_control_open(NULL, &key, 0, 62, 10, &resp) ==
		      -EINVAL,
	      "NULL ctl rejected");
	CHECK(lichen_schc_control_open(&ctl, NULL, 0, 62, 10, &resp) ==
		      -EINVAL,
	      "NULL key rejected");
	CHECK(lichen_schc_control_open(&ctl, &key, 0, 62, 10, NULL) ==
		      -EINVAL,
	      "NULL resp rejected");
	CHECK(ctl.table.context_count == 0 && ctl.session_count == 0,
	      "no mutation on arg errors");
	CHECK(lichen_schc_control_terminate(&ctl, &key,
					    LICHEN_SCHC_TERMINAL_COMPLETED,
					    NOW) == -ENOENT,
	      "terminate without session");
	CHECK(lichen_schc_control_accept(&ctl, &key, 11) == -EAGAIN,
	      "accept without session");

	/* Stale counter on an active session mutates nothing. */
	(void)lichen_schc_control_open(&ctl, &key, 0, 62, 10, &resp);
	uint32_t before = 0;

	(void)lichen_schc_control_high_water(&ctl, &key, &before);
	CHECK(lichen_schc_control_accept(&ctl, &key, 10) == -EAGAIN,
	      "stale accept rejected");
	CHECK(lichen_schc_control_accept(&ctl, &key,
					 LICHEN_SCHC_COUNTER_MAX + 1U) ==
		      -EAGAIN,
	      "out-of-space counter rejected");
	uint32_t after = 0;

	(void)lichen_schc_control_high_water(&ctl, &key, &after);
	CHECK(before == after, "high-water untouched by rejects");
	return 1;
}

/* ── Revocation retires sessions atomically ────────────────────────────────*/

static int test_revoke_retires_session_state(void)
{
	static struct lichen_schc_control ctl;
	struct lichen_schc_ctx_key key;
	lichen_schc_generation_t gen;
	enum lichen_schc_control_response resp;

	setup(&ctl, &key, &gen);
	(void)lichen_schc_control_open(&ctl, &key, 0, 62, 10, &resp);
	(void)lichen_schc_control_terminate(&ctl, &key,
					    LICHEN_SCHC_TERMINAL_COMPLETED,
					    NOW);

	/* Revoke: trust record, session record, tombstone, and floor all
	 * retire atomically. */
	CHECK(lichen_schc_control_revoke(&ctl, &key.remote) >= 0,
	      "revoke runs");
	uint32_t scratch = 0;

	CHECK(!lichen_schc_control_floor(&ctl, &key, &scratch),
	      "floor retired");
	CHECK(!lichen_schc_control_high_water(&ctl, &key, &scratch),
	      "tombstone retired");
	/* Old-generation control: dropped. */
	CHECK(lichen_schc_control_ack_request(&ctl, &key, 50, NOW + 1,
					      &resp) == 0 &&
		      resp == LICHEN_SCHC_RESP_NONE,
	      "retired-generation control dropped");
	return 1;
}

int main(void)
{
	printf("schc_session_control tests (spec 5.6, l1qw.3.7.6.5)\n");
	RUN_TEST(test_classification_from_authenticated_role);
	RUN_TEST(test_control_requires_authenticated_current_generation);
	RUN_TEST(test_open_admission_rules);
	RUN_TEST(test_four_acks_then_receiver_abort_and_holddown);
	RUN_TEST(test_floor_persists_after_holddown_expiry);
	RUN_TEST(test_errors_are_atomic);
	RUN_TEST(test_revoke_retires_session_state);
	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
