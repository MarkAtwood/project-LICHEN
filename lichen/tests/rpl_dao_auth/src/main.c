/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief DAO origin authorization at the RPL root (spec/05-routing.md 8.7)
 *
 * Mirrors the contract pinned by rust/lichen-rpl/tests/dao_prefix_authoriza-
 * tion.rs: a self-/128 Target equal to the authenticated DAO origin is
 * accepted and applied; every other Target must carry an exact static prefix
 * delegation to the origin (spec 8.7.2); generalized Target bodies
 * (prefix_len 1..=128, spec 8.7.1) are canonicalized before the delegation
 * lookup — reserved flags and bits beyond the Prefix Length are ignored.
 * ::/0, truncated bodies, and prefix_len > 128 fail closed, and every denial
 * happens before any snapshot, routing-table, or replay mutation.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lichen/rpl_addr.h>
#include <lichen/rpl_messages.h>
#include <lichen/rpl_routing.h>
/* The origin-signature helper below uses the monocypher SHA-512 and the
 * Schnorr48 APIs directly; include them explicitly rather than relying on
 * transitive includes that only exist in the Zephyr build. */
#include <monocypher-ed25519.h>
#include <lichen/schnorr48.h>

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

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
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

static uint8_t origin_priv[32];
static uint8_t origin_pub[32];
/* Spec 09 14.2: sequence 0 is not a legal wire seq (the tx-persist parser
 * rejects it), so the test counter starts at 1. */
static uint64_t origin_seq_ctr = 1;

/* Spec/05-routing.md 8.6 transcript: append the 0x12 DAO Origin Signature
 * option (seq BE u64 + Schnorr48 over SHA-512(domain || origin || dodagid ||
 * seq_be || unsigned DAO bytes)) using the suite's test signing key. */
static void sign_origin(uint8_t *dao, size_t *len,
				 const uint8_t origin[16])
{
	crypto_sha512_ctx ctx;
	uint8_t digest[64];
	uint8_t seq_be[8];
	uint8_t sig[48];
	static const uint8_t domain[] = "LICHEN-DAO-ORIGIN-v1";

	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, domain, sizeof(domain) - 1U);
	crypto_sha512_update(&ctx, origin, 16U);
	crypto_sha512_update(&ctx, dodag, 16U);
	for (int i = 7; i >= 0; i--) {
		seq_be[7 - i] = (uint8_t)(origin_seq_ctr >> (8 * i));
	}
	crypto_sha512_update(&ctx, seq_be, sizeof(seq_be));
	crypto_sha512_update(&ctx, dao, *len);
	crypto_sha512_final(&ctx, digest);
	int sign_ret =
		schnorr48_sign(origin_priv, origin_pub, digest, sizeof(digest), sig);
	if (sign_ret != 0) {
		fprintf(stderr, "schnorr48_sign failed (%d)\n", sign_ret);
		abort();
	}
	dao[(*len)++] = 0x12;
	dao[(*len)++] = 56;
	memcpy(&dao[*len], seq_be, 8);
	memcpy(&dao[*len + 8], sig, 48);
	*len += 56;
	origin_seq_ctr++;
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

static bool route_present_bytes(const uint8_t *target)
{
	return lichen_rpl_routing_table_lookup(&root_state.routing_table,
					       target) != NULL;
}

static const struct lichen_rpl_dao_snapshot *find_snapshot(
	const uint8_t *target)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (root_state.snapshots[i].valid &&
		    rpl_addr_eq(root_state.snapshots[i].target, target)) {
			return &root_state.snapshots[i];
		}
	}
	return NULL;
}

/* Raw generalized RPL Target option: [5, 2+n, flags, prefix_len, prefix...].
 * Writes prefix_len and exactly n prefix octets so non-canonical bodies
 * (extra host bits) can exercise the 8.7.1 rules, and nonzero reserved
 * flags can exercise the 8.6 R-05-035 reject. */
static void add_raw_target(uint8_t *buf, size_t *len, uint8_t flags,
			   uint8_t prefix_len, const uint8_t *prefix,
			   size_t prefix_bytes)
{
	REQUIRE(2 + prefix_bytes <= 255, "target option too long");
	buf[*len] = LICHEN_RPL_OPT_RPL_TARGET;
	buf[*len + 1] = (uint8_t)(2 + prefix_bytes);
	buf[*len + 2] = flags;
	buf[*len + 3] = prefix_len;
	if (prefix_bytes > 0) {
		memcpy(&buf[*len + 4], prefix, prefix_bytes);
	}
	*len += 4 + prefix_bytes;
}

/* 2001:0db8:00aa:0000::/64 (8 prefix octets, like the Rust matrix). */
static const uint8_t slash64[8] = {
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0xaa, 0x00, 0x00
};

/* The same prefix as a full 16-byte address, as the delegation API and
 * canonical routing keys expect. Initialized in main(). */
static uint8_t slash64_full[16];

/* One matrix row per dao_prefix_authorization.rs allow/deny case.
 * `authenticated` selects the origin pubkey handed to process_dao_ex:
 * true -> the key matching the origin signature (verified), false -> a
 * mismatched key (the Schnorr48 verification fails, which is the
 * API's unauthenticated-origin fail-closed path since 65ca175106). */
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

/* The denial guarantee covers routing_table, parent_map, and snapshots -
 * the workspace is transient staging scratch used (and dirtied) during
 * parsing, so it is excluded from the "rejected DAO mutated nothing"
 * comparison. The three meaningful members precede the workspace in the
 * struct layout. */
static int root_state_differs(const struct lichen_rpl_dao_root_state *a,
			      const struct lichen_rpl_dao_root_state *b)
{
	size_t meaningful = offsetof(struct lichen_rpl_dao_root_state, workspace);
	return memcmp(a, b, meaningful) != 0;
}

static int test_dao_origin_authorization_matrix(void)
{
	uint8_t dao[512];
	uint8_t origin[16];
	uint8_t wrong_pub[32];
	size_t len;

	memset(wrong_pub, 0xA5, sizeof(wrong_pub));

	for (size_t i = 0; i < sizeof(origin_cases) / sizeof(origin_cases[0]);
	     i++) {
		const uint8_t *case_origin = NULL;
		const uint8_t *case_pubkey = origin_pub;

		fresh_manager();
		if (origin_cases[i].origin_id != 0) {
			address(origin, origin_cases[i].origin_id);
			case_origin = origin;
		}
		if (!origin_cases[i].authenticated) {
			case_pubkey = wrong_pub;
		}
		len = dao_begin(dao, 1);
		add_target(dao, &len, origin_cases[i].target);
		add_transit(dao, &len, 1, 0x40, 1, 255);
		/* Spec 05 8.6: every DAO must carry exactly one 0x12 Origin
		 * Signature option, signed with the suite key (row 3 expects
		 * the verification to fail via the mismatched pubkey). */
		sign_origin(dao, &len, origin);
		struct lichen_rpl_dao_root_state saved = root_state;

		enum lichen_rpl_dao_process_result result =
			lichen_rpl_dao_manager_process_dao_ex(
				&manager, dao, len, 1, case_origin,
				case_pubkey, NULL, 0);

		ASSERT_EQ(result, origin_cases[i].expected, origin_cases[i].name);
		ASSERT_EQ(route_present(origin_cases[i].target),
			  origin_cases[i].route_installed,
			  origin_cases[i].name);
		if (result != LICHEN_RPL_DAO_APPLIED) {
			ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
				      "rejected DAO mutated routing state");
		}
		tests_run++;
		tests_passed++;
	}
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
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_APPLIED, "self route install");
	ASSERT_EQ(route_present(2), true, "self route present");

	struct lichen_rpl_dao_root_state saved = root_state;

	len = dao_begin(dao, 2);
	add_target(dao, &len, 3);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 2,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "foreign route accepted");
	ASSERT_EQ(route_present(3), false, "foreign route installed");
	ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
		      "foreign route mutated routing state");

	tests_run++;
	tests_passed++;
	printf("ok - %s\n", __func__);
	return 1;
}

/* With generalized Target parsing (spec 8.7.1), well-formed sub-/128 bodies
 * pass the wire profile and fail closed at the authorization gate instead;
 * truncated bodies, prefix_len > 128, and ::/0 fail closed everywhere.
 * (Mirrors the Rust matrix slash_zero_gate_denied and
 * undelegated_broad_prefix_gate_denied rows plus the malformed rows.) */
static int test_gate_denies_undelegated_and_malformed_targets(void)
{
	uint8_t dao[512];
	uint8_t origin[16];
	uint8_t truncated[7] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0xaa, 0x00};
	uint8_t oversized[17];
	size_t len;

	fresh_manager();
	lichen_rpl_prefix_delegations_reset();
	address(origin, 2);
	memset(oversized, 0x20, sizeof(oversized));
	struct lichen_rpl_dao_root_state saved = root_state;

	/* Well-formed /64 delegated to nobody: gate denial, zero mutation. */
	len = dao_begin(dao, 1);
	add_raw_target(dao, &len, 0, 64, slash64, sizeof(slash64));
	add_transit(dao, &len, 2, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "foreign /64 accepted");
	ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
		      "foreign /64 mutated routing state");

	/* ::/0: the canonical default route is never authorizable. */
	len = dao_begin(dao, 1);
	add_raw_target(dao, &len, 0, 0, NULL, 0);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "default route accepted");
	ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
		      "default route mutated routing state");

	/* Truncated /64 body: 7 < ceil(64/8) prefix octets. */
	len = dao_begin(dao, 1);
	add_raw_target(dao, &len, 0, 64, truncated, sizeof(truncated));
	add_transit(dao, &len, 1, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "truncated target accepted");
	ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
		      "truncated target mutated routing state");

	/* Prefix length over the 128-bit bound. */
	len = dao_begin(dao, 1);
	add_raw_target(dao, &len, 0, 129, oversized, sizeof(oversized));
	add_transit(dao, &len, 1, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "prefix_len 129 accepted");
	ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
		      "prefix_len 129 mutated routing state");

	/* Target option body shorter than the fixed 2-byte header. */
	len = dao_begin(dao, 1);
	dao[len++] = LICHEN_RPL_OPT_RPL_TARGET;
	dao[len++] = 1;
	dao[len++] = 0;
	add_transit(dao, &len, 1, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "short target body accepted");
	ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
		      "short target body mutated routing state");

	/* No Target option at all. */
	len = dao_begin(dao, 1);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "targetless DAO accepted");
	ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
		      "targetless DAO mutated routing state");

	tests_run++;
	tests_passed++;
	printf("ok - %s (6 rows)\n", __func__);
	return 1;
}

/* Operator delegation API fail-closed behavior (mirrors rust
 * delegation_api_fails_closed_on_default_route_and_capacity and the
 * exact-match semantics of PrefixDelegations). */
static int test_delegation_api_fails_closed(void)
{
	uint8_t origin[16];
	uint8_t foreign[16];
	uint8_t canonical[16];
	uint8_t canonical72[16];
	uint8_t with_host_bits[16];
	uint8_t extra[16];

	address(origin, 2);
	address(foreign, 3);
	lichen_rpl_prefix_delegations_reset();
	memset(canonical, 0, sizeof(canonical));
	memcpy(canonical, slash64, sizeof(slash64));
	memcpy(canonical72, canonical, 16);
	canonical72[8] = 0x80;

	/* ::/0 and prefix_len > 128 are never delegable. */
	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, canonical, 0),
		  LICHEN_RPL_ERR_INVALID, "/0 delegable");
	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, canonical, 129),
		  LICHEN_RPL_ERR_INVALID, "/129 delegable");

	/* Host bits beyond prefix_len are cleared on registration; the
	 * non-canonical value fails closed at lookup. */
	memcpy(with_host_bits, canonical, 16);
	with_host_bits[15] = 1;
	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, with_host_bits, 64),
		  LICHEN_RPL_OK, "delegate with host bits");
	ASSERT_TRUE(lichen_rpl_prefix_delegation_authorizes(origin, 64,
							    canonical),
		    "canonical /64 not authorized");
	ASSERT_TRUE(!lichen_rpl_prefix_delegation_authorizes(origin, 64,
							     with_host_bits),
		    "non-canonical lookup authorized");

	/* Delegation is exact: /63, /72, /56, and other origins fail. */
	ASSERT_TRUE(!lichen_rpl_prefix_delegation_authorizes(origin, 63,
							     canonical),
		    "/63 authorized by /64");
	ASSERT_TRUE(!lichen_rpl_prefix_delegation_authorizes(origin, 72,
							     canonical72),
		    "/72 authorized by /64");
	ASSERT_TRUE(!lichen_rpl_prefix_delegation_authorizes(origin, 56,
							     canonical),
		    "/56 authorized by /64");
	ASSERT_TRUE(!lichen_rpl_prefix_delegation_authorizes(foreign, 64,
							     canonical),
		    "foreign origin authorized");

	/* Re-delegation is idempotent and does not consume capacity. */
	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, slash64_full, 64),
		  LICHEN_RPL_OK, "re-delegate");

	/* Revoke matches the canonical key; revoking absent entries is a
	 * no-op. */
	lichen_rpl_prefix_revoke(foreign, canonical, 64);
	ASSERT_TRUE(lichen_rpl_prefix_delegation_authorizes(origin, 64,
							    canonical),
		    "foreign revoke removed entry");
	lichen_rpl_prefix_revoke(origin, with_host_bits, 64);
	ASSERT_TRUE(!lichen_rpl_prefix_delegation_authorizes(origin, 64,
							     canonical),
		    "revoke left entry");
	lichen_rpl_prefix_revoke(origin, canonical, 64);

	/* Bounded table: 64 entries fit, the 65th fails, and idempotent
	 * re-registration still succeeds at capacity. */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PREFIX_DELEGATIONS; i++) {
		uint8_t p[16];

		memset(p, 0, sizeof(p));
		p[0] = 0x20;
		p[1] = 0x01;
		p[2] = (uint8_t)i;
		ASSERT_EQ(lichen_rpl_prefix_delegate(origin, p, 64),
			  LICHEN_RPL_OK, "capacity seed");
		ASSERT_EQ(lichen_rpl_prefix_delegate(origin, p, 64),
			  LICHEN_RPL_OK, "idempotent seed");
	}
	memset(extra, 0, sizeof(extra));
	extra[0] = 0x20;
	extra[1] = 0x01;
	extra[2] = 0xff;
	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, extra, 64),
		  LICHEN_RPL_ERR_FULL, "capacity exceeded");
	extra[2] = 0;
	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, extra, 64), LICHEN_RPL_OK,
		  "idempotent at capacity");

	/* Operator reset clears every entry. */
	lichen_rpl_prefix_delegations_reset();
	ASSERT_TRUE(!lichen_rpl_prefix_delegation_authorizes(origin, 64, extra),
		    "reset left entries");

	tests_run++;
	tests_passed++;
	printf("ok - %s\n", __func__);
	return 1;
}

/* Full pipeline for a delegated sub-/128 egress Target (mirrors rust
 * delegated_slash64_dao_installs_end_to_end): the generalized body passes
 * the wire profile, the gate denies before any mutation until the /64 is
 * delegated, and the canonical /64 is installed once delegated. */
static int test_delegated_slash64_end_to_end(void)
{
	uint8_t dao[512];
	uint8_t origin[16];
	uint8_t installed[16];
	size_t len;

	fresh_manager();
	lichen_rpl_prefix_delegations_reset();
	address(origin, 2);
	memset(installed, 0, sizeof(installed));
	memcpy(installed, slash64, sizeof(slash64));

	/* Group 1: origin's own /128 via root; group 2: the /64 with the
	 * origin as egress. */
	len = dao_begin(dao, 1);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	add_raw_target(dao, &len, 0, 64, slash64, sizeof(slash64));
	add_transit(dao, &len, 2, 0x40, 1, 255);

	struct lichen_rpl_dao_root_state saved = root_state;

	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "undelegated /64 applied");
	ASSERT_EQ(route_present_bytes(installed), false, "/64 route installed");
	ASSERT_EQ(route_present(2), false, "self route installed");
	ASSERT_TRUE(find_snapshot(installed) == NULL, "/64 snapshot installed");
	ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
		      "denial mutated routing state");

	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, slash64_full, 64),
		  LICHEN_RPL_OK, "delegate /64");
	/* Rebuild the DAO after delegating: a DAO may carry exactly one
	 * 0x12 Origin Signature option, and the previous buffer already
	 * has one appended. */
	len = dao_begin(dao, 1);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	add_raw_target(dao, &len, 0, 64, slash64, sizeof(slash64));
	add_transit(dao, &len, 2, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_APPLIED, "delegated /64 rejected");
	ASSERT_EQ(route_present_bytes(installed), true, "canonical /64 route");
	ASSERT_EQ(route_present(2), true, "self route missing");
	const struct lichen_rpl_dao_snapshot *snap = find_snapshot(installed);

	REQUIRE(snap != NULL, "canonical /64 snapshot");
	ASSERT_EQ(snap->active, true, "/64 snapshot inactive");
	ASSERT_EQ(snap->path_sequence, 1, "/64 path sequence");

	/* An exact /128 delegation of a foreign host route also applies
	 * (rust delegated_prefix_is_allowed_and_denial_leaves_no_state_muta-
	 * tion, second half). */
	uint8_t foreign_host[16];

	address(foreign_host, 3);
	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, foreign_host, 128),
		  LICHEN_RPL_OK, "delegate foreign /128");
	len = dao_begin(dao, 2);
	add_target(dao, &len, 2);
	add_transit(dao, &len, 1, 0x40, 2, 255);
	add_target(dao, &len, 3);
	add_transit(dao, &len, 2, 0x40, 2, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 2,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_APPLIED, "delegated foreign /128 rejected");
	ASSERT_EQ(route_present(3), true, "delegated foreign route missing");

	tests_run++;
	tests_passed++;
	printf("ok - %s\n", __func__);
	return 1;
}

/* Generalized-body wire cases at the gate (mirrors rust
 * gate_prefix_literals_self_foreign_default_and_delegated): non-canonical
 * encodings are canonicalized, the /127 boundary encoding works, and a /63
 * is not the exact /64 delegation. */
static int test_gate_generalized_body_literals(void)
{
	uint8_t dao[512];
	uint8_t origin[16];
	uint8_t padded[10];
	uint8_t installed[16];
	uint8_t slash127_wire[16];
	uint8_t slash127_canonical[16];
	size_t len;

	lichen_rpl_prefix_delegations_reset();
	address(origin, 2);
	memset(installed, 0, sizeof(installed));
	memcpy(installed, slash64, sizeof(slash64));

	/* Non-canonical /64 body: host bytes beyond ceil(64/8) are ignored
	 * and the canonical /64 is what gets installed. */
	memcpy(padded, slash64, sizeof(slash64));
	padded[8] = 0xff;
	padded[9] = 0xff;
	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, slash64_full, 64),
		  LICHEN_RPL_OK, "delegate /64");
	fresh_manager();
	len = dao_begin(dao, 1);
	/* The canonical self /128 target is required (mirrors Rust
	 * sender_is_authorized: >=1 target == origin, project-LICHEN-
	 * worker6-nie1); the delegated /64 then tests canonicalization. */
	add_target(dao, &len, 2);
	add_raw_target(dao, &len, 0, 64, padded, sizeof(padded));
	add_transit(dao, &len, 1, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_APPLIED, "non-canonical body rejected");
	ASSERT_EQ(route_present_bytes(installed), true, "canonical /64 route");
	ASSERT_TRUE(find_snapshot(installed) != NULL, "canonical /64 snapshot");

	/* Nonzero reserved flags reject the DAO (spec 8.6 R-05-035) with
	 * zero state mutation. The 8.7.1 ignore-rule belongs to the future
	 * .44.9 generalized model, not current conformance. */
	fresh_manager();
	len = dao_begin(dao, 1);
	add_raw_target(dao, &len, 0x1f, 128, origin, 16);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	/* Merge reconciliation: keep the 8dt9 rework's signed DAO — the
	 * R-05-035 reject must fire even with a valid origin signature
	 * (vector reject_target_flags_nonzero) — but keep main's REJECTED
	 * expectation and zero-mutation pin; the incoming branch's 8.7.1
	 * APPLIED oracle predates the R-05-035 fix (49ec393182, b7z9.3.2)
	 * landed on main. */
	sign_origin(dao, &len, origin);
	struct lichen_rpl_dao_root_state flags_saved = root_state;

	ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "nonzero Target flags accepted");
	ASSERT_MEM_EQ(&root_state, &flags_saved, sizeof(root_state),
		      "nonzero flags DAO mutated routing state");

	/* /127 boundary encoding: the low bit of the final octet is ignored,
	 * then the canonical /127 is installed. */
	memset(slash127_wire, 0, sizeof(slash127_wire));
	memcpy(slash127_wire, slash64, sizeof(slash64));
	slash127_wire[15] = 0x01;
	memcpy(slash127_canonical, slash127_wire, 16);
	ASSERT_TRUE(lichen_rpl_prefix_canonicalize(slash127_canonical, 127),
		    "canonicalize /127");
	ASSERT_EQ(lichen_rpl_prefix_delegate(origin, slash127_canonical, 127),
		  LICHEN_RPL_OK, "delegate /127");
	fresh_manager();
	len = dao_begin(dao, 1);
	/* Self /128 required (found_origin, nie1); the /127 delegated target
	 * below exercises canonicalization. */
	add_target(dao, &len, 2);
	add_raw_target(dao, &len, 0, 127, slash127_wire, 16);
	add_transit(dao, &len, 1, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_APPLIED, "/127 boundary rejected");
	ASSERT_EQ(route_present_bytes(slash127_canonical), true,
		  "canonical /127 route");
	const struct lichen_rpl_dao_snapshot *snap =
		find_snapshot(slash127_canonical);

	REQUIRE(snap != NULL, "canonical /127 snapshot");
	ASSERT_EQ(snap->path_sequence, 1, "/127 path sequence");

	/* A /63 is not the exact /64 delegation: denied pre-mutation. */
	fresh_manager();
	struct lichen_rpl_dao_root_state saved = root_state;

	len = dao_begin(dao, 1);
	add_target(dao, &len, 2);
	add_raw_target(dao, &len, 0, 63, slash64, sizeof(slash64));
	add_transit(dao, &len, 1, 0x40, 1, 255);
	sign_origin(dao, &len, origin);
		ASSERT_EQ(lichen_rpl_dao_manager_process_dao_ex(&manager, dao, len, 1,
							origin, origin_pub, NULL, 0),
		  LICHEN_RPL_DAO_REJECTED, "/63 accepted by /64 delegation");
	ASSERT_EQ(root_state_differs(&root_state, &saved), 0,
		      "/63 denial mutated routing state");

	tests_run++;
	tests_passed++;
	printf("ok - %s (4 rows)\n", __func__);
	return 1;
}

int main(void)
{
	uint8_t test_seed[32];

	for (int i = 0; i < 32; i++) {
		test_seed[i] = (uint8_t)(0x70 + i);
	}
	schnorr48_derive_keypair(test_seed, origin_priv, origin_pub);
	address(root, 1);
	address(dodag, 0x99);
	memset(slash64_full, 0, sizeof(slash64_full));
	memcpy(slash64_full, slash64, sizeof(slash64));

	int ok = test_dao_origin_authorization_matrix() &&
		 test_foreign_host_route_preserves_installed_route() &&
		 test_gate_denies_undelegated_and_malformed_targets() &&
		 test_delegation_api_fails_closed() &&
		 test_delegated_slash64_end_to_end() &&
		 test_gate_generalized_body_literals();

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return ok ? 0 : 1;
}
