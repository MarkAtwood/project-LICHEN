/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Unit tests for the SCHC session authority identity/direction core
 *        (spec/03-adaptation.md 5.6; bead l1qw.3.7.6.1).
 */

#include <lichen/schc_session.h>

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

/* Build a deterministic identity whose first byte is `first` and whose
 * remaining bytes are `fill`. */
static struct lichen_schc_identity mk_id(uint8_t first, uint8_t fill)
{
	struct lichen_schc_identity id;

	id.pubkey[0] = first;
	memset(&id.pubkey[1], fill, LICHEN_SCHC_IDENTITY_LEN - 1U);
	return id;
}

static int test_identity_cmp_ordering(void)
{
	struct lichen_schc_identity lo = mk_id(0x00, 0x11);
	struct lichen_schc_identity hi = mk_id(0xff, 0x11);
	struct lichen_schc_identity lo2 = mk_id(0x00, 0x11);

	CHECK(lichen_schc_identity_cmp(&lo, &hi) < 0, "lo < hi");
	CHECK(lichen_schc_identity_cmp(&hi, &lo) > 0, "hi > lo");
	CHECK(lichen_schc_identity_cmp(&lo, &lo2) == 0, "lo == lo2");
	return 1;
}

static int test_identity_cmp_msb_first(void)
{
	/* Differ only in the LAST byte: lexicographic compare is MSB-first,
	 * so the leading bytes dominate. */
	struct lichen_schc_identity a = mk_id(0x00, 0x00);
	struct lichen_schc_identity b = mk_id(0x00, 0x00);

	a.pubkey[LICHEN_SCHC_IDENTITY_LEN - 1U] = 0x01;
	b.pubkey[LICHEN_SCHC_IDENTITY_LEN - 1U] = 0x02;
	CHECK(lichen_schc_identity_cmp(&a, &b) < 0, "last-byte 0x01 < 0x02");
	CHECK(lichen_schc_identity_cmp(&b, &a) > 0, "last-byte 0x02 > 0x01");

	/* First byte beats any later byte. */
	a.pubkey[0] = 0x00;
	b.pubkey[0] = 0x01;
	a.pubkey[LICHEN_SCHC_IDENTITY_LEN - 1U] = 0xff;
	b.pubkey[LICHEN_SCHC_IDENTITY_LEN - 1U] = 0x00;
	CHECK(lichen_schc_identity_cmp(&a, &b) < 0, "MSB dominates trailing");
	return 1;
}

static int test_identity_cmp_null_safe(void)
{
	struct lichen_schc_identity id = mk_id(0x42, 0x42);

	CHECK(lichen_schc_identity_cmp(NULL, NULL) == 0, "NULL == NULL");
	CHECK(lichen_schc_identity_cmp(NULL, &id) != 0, "NULL != id");
	CHECK(lichen_schc_identity_cmp(&id, NULL) != 0, "id != NULL");
	return 1;
}

static int test_endpoint_role_a_is_smaller(void)
{
	struct lichen_schc_identity small = mk_id(0x01, 0xaa);
	struct lichen_schc_identity large = mk_id(0xfe, 0xbb);
	enum lichen_schc_endpoint role;

	/* Local is the smaller key -> endpoint A. */
	CHECK(lichen_schc_endpoint_role(&small, &large, &role) == 0,
	      "role succeeds");
	CHECK(role == LICHEN_SCHC_ENDPOINT_A, "smaller local is A");

	/* Local is the larger key -> endpoint B. */
	CHECK(lichen_schc_endpoint_role(&large, &small, &role) == 0,
	      "role succeeds");
	CHECK(role == LICHEN_SCHC_ENDPOINT_B, "larger local is B");
	return 1;
}

static int test_endpoint_role_rejects_equal_keys(void)
{
	struct lichen_schc_identity a = mk_id(0x55, 0x55);
	struct lichen_schc_identity b = mk_id(0x55, 0x55);
	enum lichen_schc_endpoint role;

	CHECK(lichen_schc_endpoint_role(&a, &b, &role) == -EINVAL,
	      "equal keys rejected");
	return 1;
}

static int test_endpoint_role_rejects_null(void)
{
	struct lichen_schc_identity a = mk_id(0x01, 0x01);
	struct lichen_schc_identity b = mk_id(0x02, 0x02);
	enum lichen_schc_endpoint role;

	CHECK(lichen_schc_endpoint_role(NULL, &b, &role) == -EINVAL,
	      "NULL local rejected");
	CHECK(lichen_schc_endpoint_role(&a, NULL, &role) == -EINVAL,
	      "NULL remote rejected");
	CHECK(lichen_schc_endpoint_role(&a, &b, NULL) == -EINVAL,
	      "NULL role rejected");
	return 1;
}

static int test_data_plane_rule_ids(void)
{
	uint8_t rule = 0U;

	/* Data, ACK REQ, Sender-Abort use the SENDER's directional Rule ID. */
	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_MSG_DATA, &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_A_TO_B,
	      "A data -> 0x78");
	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_MSG_ACK_REQ, &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_A_TO_B,
	      "A ACK-REQ -> 0x78");
	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_MSG_SENDER_ABORT,
					   &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_A_TO_B,
	      "A Sender-Abort -> 0x78");

	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_B,
					   LICHEN_SCHC_MSG_DATA, &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_B_TO_A,
	      "B data -> 0x79");
	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_B,
					   LICHEN_SCHC_MSG_ACK_REQ, &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_B_TO_A,
	      "B ACK-REQ -> 0x79");
	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_B,
					   LICHEN_SCHC_MSG_SENDER_ABORT,
					   &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_B_TO_A,
	      "B Sender-Abort -> 0x79");
	return 1;
}

static int test_control_plane_retains_data_rule_id(void)
{
	uint8_t rule = 0U;

	/* ACK and Receiver-Abort travel in the REVERSE direction but RETAIN
	 * the data transfer's Rule ID. For a transfer whose data sender is A,
	 * the ACK (sent by B) still carries 0x78. */
	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_MSG_ACK, &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_A_TO_B,
	      "ACK retains A->B 0x78");
	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_MSG_RECEIVER_ABORT,
					   &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_A_TO_B,
	      "Receiver-Abort retains A->B 0x78");

	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_B,
					   LICHEN_SCHC_MSG_ACK, &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_B_TO_A,
	      "ACK retains B->A 0x79");
	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_B,
					   LICHEN_SCHC_MSG_RECEIVER_ABORT,
					   &rule) == 0 &&
	      rule == LICHEN_SCHC_RULE_B_TO_A,
	      "Receiver-Abort retains B->A 0x79");
	return 1;
}

static int test_directional_rule_rejects_bad_args(void)
{
	uint8_t rule = 0U;

	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_MSG_DATA, NULL) == -EINVAL,
	      "NULL out rejected");
	CHECK(lichen_schc_directional_rule((enum lichen_schc_endpoint)7,
					   LICHEN_SCHC_MSG_DATA, &rule) == -EINVAL,
	      "out-of-range role rejected");
	CHECK(lichen_schc_directional_rule(LICHEN_SCHC_ENDPOINT_A,
					   (enum lichen_schc_msg_class)99,
					   &rule) == -EINVAL,
	      "out-of-range class rejected");
	return 1;
}

static int test_direction_valid_accepts_matching(void)
{
	CHECK(lichen_schc_direction_valid(LICHEN_SCHC_ENDPOINT_A,
					  LICHEN_SCHC_MSG_DATA,
					  LICHEN_SCHC_RULE_A_TO_B),
	      "A data 0x78 valid");
	CHECK(lichen_schc_direction_valid(LICHEN_SCHC_ENDPOINT_B,
					  LICHEN_SCHC_MSG_DATA,
					  LICHEN_SCHC_RULE_B_TO_A),
	      "B data 0x79 valid");
	CHECK(lichen_schc_direction_valid(LICHEN_SCHC_ENDPOINT_A,
					  LICHEN_SCHC_MSG_ACK,
					  LICHEN_SCHC_RULE_A_TO_B),
	      "A ACK 0x78 valid");
	return 1;
}

static int test_direction_valid_rejects_mismatched(void)
{
	/* Mismatched direction: B's data arriving with A's Rule ID. */
	CHECK(!lichen_schc_direction_valid(LICHEN_SCHC_ENDPOINT_B,
					   LICHEN_SCHC_MSG_DATA,
					   LICHEN_SCHC_RULE_A_TO_B),
	      "B data with 0x78 rejected");
	CHECK(!lichen_schc_direction_valid(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_MSG_DATA,
					   LICHEN_SCHC_RULE_B_TO_A),
	      "A data with 0x79 rejected");
	/* An unrelated Rule ID never validates. */
	CHECK(!lichen_schc_direction_valid(LICHEN_SCHC_ENDPOINT_A,
					   LICHEN_SCHC_MSG_DATA, 0x00),
	      "rule 0x00 rejected");
	/* Out-of-range class never validates. */
	CHECK(!lichen_schc_direction_valid(LICHEN_SCHC_ENDPOINT_A,
					   (enum lichen_schc_msg_class)42,
					   LICHEN_SCHC_RULE_A_TO_B),
	      "bad class rejected");
	return 1;
}

int main(void)
{
	printf("SCHC session authority (identity/direction) tests\n");
	printf("=================================================\n");

	RUN_TEST(test_identity_cmp_ordering);
	RUN_TEST(test_identity_cmp_msb_first);
	RUN_TEST(test_identity_cmp_null_safe);
	RUN_TEST(test_endpoint_role_a_is_smaller);
	RUN_TEST(test_endpoint_role_rejects_equal_keys);
	RUN_TEST(test_endpoint_role_rejects_null);
	RUN_TEST(test_data_plane_rule_ids);
	RUN_TEST(test_control_plane_retains_data_rule_id);
	RUN_TEST(test_directional_rule_rejects_bad_args);
	RUN_TEST(test_direction_valid_accepts_matching);
	RUN_TEST(test_direction_valid_rejects_mismatched);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
