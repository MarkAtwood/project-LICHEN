/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief DAO origin authorization at the RPL root (spec/05-routing.md 8.7)
 *
 * Mirrors the contract pinned by rust/lichen-rpl/tests/dao_prefix_authoriza-
 * tion.rs (commit 79224e95ed): a self-/128 Target equal to the authenticated
 * DAO origin is accepted and applied; a foreign /128 host route is rejected
 * before any snapshot or routing-table mutation; an absent or unauthenticated
 * origin fails closed. /0 and broad prefixes die at the .44.7 wire profile
 * (Target options shorter than 18 data bytes, prefix length != 128).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lichen/rpl_messages.h>
#include <lichen/rpl_routing.h>

static int tests_run;
static int tests_passed;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", \
		       msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
	if (memcmp((a), (b), (len)) != 0) { \
		printf("  FAIL: %s\n", msg); \
		return 0; \
	} \
} while (0)

/* For void helpers: a failed setup prerequisite aborts the whole run. */
#define REQUIRE(cond, msg) do { \
	if (!(cond)) { \
		printf("  FAIL: %s\n", msg); \
		exit(1); \
	} \
} while (0)

static uint8_t root[16];
static uint8_t dodag[16];
static struct lichen_rpl_dao_manager manager;
static struct lichen_rpl_dao_root_state root_state;

static void address(uint8_t out[16], uint8_t id)
{
	memset(out, 0, 16);
	out[0] = 0xfd;
	out[15] = id;
}

static void fresh_manager(void)
{
	REQUIRE(lichen_rpl_dao_manager_init_root(&manager, root, 1, dodag) ==
		LICHEN_RPL_OK, "root init");
	REQUIRE(lichen_rpl_dao_manager_bind_root_state(&manager, &root_state) ==
		LICHEN_RPL_OK, "root state bind");
}

static size_t dao_begin(uint8_t *buf, uint8_t sequence)
{
	struct lichen_rpl_dao dao = {
		.rpl_instance_id = 1,
		.has_dodag_id = true,
		.dao_sequence = sequence,
	};

	memcpy(dao.dodag_id, dodag, 16);
	int len = lichen_rpl_dao_write(&dao, buf, 512);

	REQUIRE(len > 0, "DAO base write");
	return (size_t)len;
}

static void add_target(uint8_t *buf, size_t *len, uint8_t id)
{
	struct lichen_rpl_target target = { .prefix_len = 128 };

	address(target.prefix, id);
	int written = lichen_rpl_target_write(&target, &buf[*len], 512 - *len);

	REQUIRE(written > 0, "target write");
	*len += (size_t)written;
}

static void add_transit(uint8_t *buf, size_t *len, uint8_t parent,
			uint8_t control, uint8_t sequence, uint8_t lifetime)
{
	struct lichen_rpl_transit_info transit = {
		.path_control = control,
		.path_sequence = sequence,
		.path_lifetime = lifetime,
	};

	address(transit.parent_address, parent);
	int written = lichen_rpl_transit_info_write(&transit, &buf[*len],
						    512 - *len);

	REQUIRE(written > 0, "transit write");
	*len += (size_t)written;
}

static bool route_present(uint8_t id)
{
	uint8_t target[16];

	address(target, id);
	return lichen_rpl_routing_table_lookup(&root_state.routing_table,
					       target) != NULL;
}

/* One matrix row per dao_prefix_authorization.rs allow/deny case. */
static const struct {
	const char *name;
	uint8_t target;
	uint8_t origin_id;	/* 0 = absent origin (NULL) */
	bool authenticated;
	enum lichen_rpl_dao_process_result expected;
	bool route_installed;
} origin_cases[] = {
	{"self_host_route_allowed", 2, 2, true, LICHEN_RPL_DAO_APPLIED, true},
	{"foreign_host_route_rejected", 2, 3, true,
	 LICHEN_RPL_DAO_REJECTED, false},
	{"unauthenticated_origin_fail_closed", 2, 2, false,
	 LICHEN_RPL_DAO_REJECTED, false},
	{"absent_origin_fail_closed", 2, 0, true,
	 LICHEN_RPL_DAO_REJECTED, false},
};

static int test_dao_origin_authorization_matrix(void)
{
	uint8_t dao[512];
	uint8_t origin[16];
	size_t len;

	for (size_t i = 0; i < sizeof(origin_cases) / sizeof(origin_cases[0]);
	     i++) {
		const uint8_t *case_origin = NULL;

		fresh_manager();
		if (origin_cases[i].origin_id != 0) {
			address(origin, origin_cases[i].origin_id);
			case_origin = origin;
		}
		len = dao_begin(dao, 1);
		add_target(dao, &len, origin_cases[i].target);
		add_transit(dao, &len, 1, 0x40, 1, 255);
		struct lichen_rpl_dao_root_state saved = root_state;

		enum lichen_rpl_dao_process_result result =
			lichen_rpl_dao_manager_process_dao_ex(
				&manager, dao, len, 1, case_origin,
				origin_cases[i].authenticated, NULL, 0);

		ASSERT_EQ(result, origin_cases[i].expected, origin_cases[i].name);
		ASSERT_EQ(route_present(origin_cases[i].target),
			  origin_cases[i].route_installed,
			  origin_cases[i].name);
		if (result != LICHEN_RPL_DAO_APPLIED) {
			ASSERT_MEM_EQ(&root_state, &saved, sizeof(root_state),
				      "rejected DAO mutated routing state");
		}
		tests_run++;
	}
	tests_passed++;
	printf("ok - %s (%zu rows)\n", __func__,
	       sizeof(origin_cases) / sizeof(origin_cases[0]));
	return 1;
}

/* Foreign /128 must also be rejected when a self-route already exists,
 * leaving the installed route byte-identical (zero mutation). */
static int test_foreign_host_route_preserves_installed_route(void)
{
	uint8_t dao[512];
	uint8_t origin[16];
	size_t len;

	fresh_manager();
	len = dao_begin(dao, 1);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	address(origin, 2);
	ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, true, NULL, 0),
		  LICHEN_RPL_DAO_APPLIED, "self route install");
	ASSERT_EQ(route_present(2), true, "self route present");

	struct lichen_rpl_dao_root_state saved = root_state;

	len = dao_begin(dao, 2);
	add_target(dao, &len, 3);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 2,
							origin, true, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "foreign route accepted");
	ASSERT_EQ(route_present(3), false, "foreign route installed");
	ASSERT_MEM_EQ(&root_state, &saved, sizeof(root_state),
		      "foreign route mutated routing state");

	tests_run++;
	tests_passed++;
	printf("ok - %s\n", __func__);
	return 1;
}

/* /0 and broad prefixes die at the .44.7 wire profile: a Target option
 * without exactly 18 data bytes and prefix length 128 is rejected before
 * origin policy (mirrors the Rust matrix slash_zero and /64 rows). */
static int test_wire_profile_rejects_non_host_prefixes(void)
{
	uint8_t dao[512];
	uint8_t origin[16];
	size_t len;

	fresh_manager();
	address(origin, 2);
	struct lichen_rpl_dao_root_state saved = root_state;

	len = dao_begin(dao, 1);
	dao[len++] = LICHEN_RPL_OPT_RPL_TARGET;
	dao[len++] = 10;	/* 2 + 8 prefix octets */
	dao[len++] = 0;
	dao[len++] = 64;
	memset(&dao[len], 0x02, 8);
	len += 8;
	add_transit(dao, &len, 1, 0x40, 1, 255);
	ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, true, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "broad prefix accepted");
	ASSERT_MEM_EQ(&root_state, &saved, sizeof(root_state),
		      "broad prefix mutated routing state");

	len = dao_begin(dao, 1);
	dao[len++] = LICHEN_RPL_OPT_RPL_TARGET;
	dao[len++] = 2;		/* flags + prefix length only */
	dao[len++] = 0;
	dao[len++] = 0;
	add_transit(dao, &len, 1, 0x40, 1, 255);
	ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, true, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "default route accepted");
	ASSERT_MEM_EQ(&root_state, &saved, sizeof(root_state),
		      "default route mutated routing state");

	tests_run++;
	tests_passed++;
	printf("ok - %s\n", __func__);
	return 1;
}

int main(void)
{
	address(root, 1);
	address(dodag, 0x99);

	int ok = test_dao_origin_authorization_matrix() &&
		 test_foreign_host_route_preserves_installed_route() &&
		 test_wire_profile_rejects_non_host_prefixes();

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return ok ? 0 : 1;
}
