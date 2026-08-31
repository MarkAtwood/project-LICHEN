/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/routing/router.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __ZEPHYR__
#include <zephyr/ztest.h>
#endif

#include "route_selection_vectors.h"

#define REQUIRE(condition) do { if (!(condition)) return __LINE__; } while (0)

static const uint8_t node_address[16] = {0x02, 0x00, [15] = 0x01};
static const uint8_t source_address[16] = {0x02, 0x00, [15] = 0xaa};
static const uint8_t gradient_hop[16] = {0xfe, 0x80, [15] = 0x10};
static const uint8_t parent_hop[16] = {0xfe, 0x80, [15] = 0x20};

struct accessor_state {
	bool joined;
	bool discovery_succeeds;
	unsigned int discovery_calls;
};

static bool is_joined(void *user_data)
{
	return ((struct accessor_state *)user_data)->joined;
}

static int get_parent(void *user_data, uint8_t out_parent[16])
{
	struct accessor_state *state = user_data;

	if (!state->joined) {
		return -ENOENT;
	}
	memcpy(out_parent, parent_hop, 16U);
	return 0;
}

static int discover(void *user_data, const uint8_t destination_iid[8])
{
	struct accessor_state *state = user_data;

	(void)destination_iid;
	state->discovery_calls++;
	return state->discovery_succeeds ? 0 : -ENOENT;
}

static void configure_router(struct lichen_router *router,
			     struct accessor_state *state)
{
	struct lichen_rpl_accessor rpl = {
		.is_joined = is_joined,
		.get_preferred_parent = get_parent,
		.user_data = state,
	};
	struct lichen_loadng_accessor loadng = {
		.discover = discover,
		.user_data = state,
	};

	(void)lichen_router_init(router, node_address);
	lichen_router_set_rpl(router, &rpl);
	lichen_router_set_loadng(router, &loadng);
}

static size_t make_udp_packet(uint8_t *packet, size_t capacity,
			      const uint8_t source[16], const uint8_t destination[16],
			      uint8_t hop_limit)
{
	if (capacity < 48U) {
		return 0U;
	}
	memset(packet, 0, 48U);
	packet[0] = 0x60U;
	packet[5] = 8U;
	packet[6] = 17U;
	packet[7] = hop_limit;
	memcpy(&packet[8], source, 16U);
	memcpy(&packet[24], destination, 16U);
	packet[40] = 0x16U;
	packet[41] = 0x33U;
	packet[42] = 0x16U;
	packet[43] = 0x33U;
	packet[45] = 8U;
	return 48U;
}

static int install_gradient(struct lichen_router *router,
			    const uint8_t destination[16],
			    const uint8_t next_hop[16],
			    enum lichen_gradient_source source)
{
	struct lichen_gradient_entry entry = {
		.hop_count = 1U,
		.seq_num = 1U,
		.source = source,
		.expires_ms = 10000U,
		.valid = true,
	};

	memcpy(entry.destination_iid, &destination[8], 8U);
	memcpy(entry.next_hop, next_hop, 16U);
	return lichen_gradient_update(&router->gradient_table, &entry, 1U);
}

static int test_shared_route_vectors(void)
{
	for (size_t i = 0U; i < ROUTE_SELECTION_VECTOR_COUNT; i++) {
		const struct route_selection_vector *vector = &route_selection_vectors[i];
		struct accessor_state state = {
			.joined = vector->rpl_parent,
			.discovery_succeeds = vector->local_discovery,
		};
		struct lichen_router router;
		struct lichen_packet_route_result result;
		struct lichen_route_packet input;
		uint8_t packet[48];

		configure_router(&router, &state);
		if (vector->local_route) {
			REQUIRE(install_gradient(&router, vector->destination,
						 gradient_hop, LICHEN_GRADIENT_ANNOUNCE) == 0);
		}
		(void)make_udp_packet(packet, sizeof(packet), source_address,
				      vector->destination, 8U);
		input = (struct lichen_route_packet) {
			.data = packet,
			.len = sizeof(packet),
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 2U, &result) == 0);
		REQUIRE(result.route.decision == vector->expected_decision);
		if (result.route.decision == LICHEN_ROUTE_FORWARD) {
			REQUIRE(memcmp(result.route.next_hop, vector->expected_next_hop, 16U) == 0);
			REQUIRE(result.forward_hop_limit == 8U);
		}
		if (result.route.decision == LICHEN_ROUTE_QUEUE) {
			REQUIRE(router.pending_count == 1U);
			REQUIRE(state.discovery_calls == 1U);
		}
	}
	return 0;
}

static int test_validation_and_atomic_output(void)
{
	struct accessor_state state = {0};
	struct lichen_router router;
	struct lichen_route_packet input;
	struct lichen_packet_route_result result;
	struct lichen_packet_route_result sentinel;
	uint8_t destination[16] = {0x03, 0x00, [15] = 1U};
	uint8_t packet[48];

	configure_router(&router, &state);
	(void)make_udp_packet(packet, sizeof(packet), source_address, destination, 8U);
	memset(&sentinel, 0xa5, sizeof(sentinel));
	input = (struct lichen_route_packet) {
		.data = packet,
		.len = sizeof(packet),
		.ingress = LICHEN_ROUTE_INGRESS_MESH,
	};

#define EXPECT_ERROR(expected) do { \
	result = sentinel; \
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == (expected)); \
	REQUIRE(memcmp(&result, &sentinel, sizeof(result)) == 0); \
} while (0)

	input.len = 39U;
	EXPECT_ERROR(-EINVAL);
	input.len = sizeof(packet);
	packet[0] = 0x40U;
	EXPECT_ERROR(-EBADMSG);
	packet[0] = 0x60U;
	packet[5] = 9U;
	EXPECT_ERROR(-EMSGSIZE);
	packet[5] = 8U;
	memset(&packet[8], 0, 16U);
	EXPECT_ERROR(-EBADMSG);
	memcpy(&packet[8], source_address, 16U);
	packet[7] = 0U;
	EXPECT_ERROR(-EHOSTUNREACH);
	packet[7] = 8U;
	packet[6] = 6U;
	EXPECT_ERROR(-EPROTONOSUPPORT);
	packet[6] = 44U;
	EXPECT_ERROR(-EPROTONOSUPPORT);
	packet[6] = 17U;
	input.len = 44U;
	packet[5] = 4U;
	EXPECT_ERROR(-EMSGSIZE);

#undef EXPECT_ERROR
	return 0;
}

static int test_hop_limit_loop_and_local_delivery(void)
{
	struct accessor_state state = {.joined = true};
	struct lichen_router router;
	struct lichen_packet_route_result result;
	struct lichen_route_packet input;
	uint8_t external[16] = {0x03, [15] = 1U};
	uint8_t packet[48];

	configure_router(&router, &state);
	(void)make_udp_packet(packet, sizeof(packet), source_address, external, 1U);
	input = (struct lichen_route_packet) {
		.data = packet, .len = sizeof(packet), .ingress = LICHEN_ROUTE_INGRESS_MESH,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DROP);

	packet[7] = 8U;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_FORWARD);
	REQUIRE(result.path == LICHEN_ROUTE_PATH_RPL_UPWARD);
	REQUIRE(result.forward_hop_limit == 7U);

	input.ingress = LICHEN_ROUTE_INGRESS_LOCAL;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.forward_hop_limit == 8U);

	memcpy(&packet[24], node_address, 16U);
	input.ingress = LICHEN_ROUTE_INGRESS_MESH;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DELIVER_LOCAL);

	memcpy(&packet[8], node_address, 16U);
	memcpy(&packet[24], external, 16U);
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DROP);
	return 0;
}

static int test_multicast_scope_and_boundary(void)
{
	struct accessor_state state = {0};
	struct lichen_router router;
	struct lichen_packet_route_result result;
	struct lichen_route_packet input;
	uint8_t multicast[16] = {0xff, 0x02, [15] = 1U};
	uint8_t packet[48];

	configure_router(&router, &state);
	(void)make_udp_packet(packet, sizeof(packet), source_address, multicast, 4U);
	input = (struct lichen_route_packet) {
		.data = packet, .len = sizeof(packet), .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DELIVER_AND_FORWARD);
	REQUIRE(result.forward_hop_limit == 4U);

	input.ingress = LICHEN_ROUTE_INGRESS_MESH;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DELIVER_LOCAL);

	packet[25] = 0x03U;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DELIVER_AND_FORWARD);
	REQUIRE(result.forward_hop_limit == 3U);
	packet[7] = 1U;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DELIVER_LOCAL);

	packet[7] = 4U;
	input.ingress = LICHEN_ROUTE_INGRESS_BACKBONE;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DROP);
	input.multicast_peering = true;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DELIVER_AND_FORWARD);
	return 0;
}

static size_t make_source_route_packet(uint8_t packet[72],
				       const uint8_t next_hop[16])
{
	memset(packet, 0, 72U);
	packet[0] = 0x60U;
	packet[5] = 32U;
	packet[6] = 43U;
	packet[7] = 8U;
	memcpy(&packet[8], source_address, 16U);
	memcpy(&packet[24], node_address, 16U);
	packet[40] = 17U;
	packet[41] = 2U;
	packet[42] = 3U;
	packet[43] = 1U;
	memcpy(&packet[48], next_hop, 16U);
	packet[64] = 0x16U;
	packet[65] = 0x33U;
	packet[66] = 0x16U;
	packet[67] = 0x33U;
	packet[69] = 8U;
	return 72U;
}

static int test_source_route_validation(void)
{
	struct accessor_state state = {0};
	struct lichen_router router;
	struct lichen_packet_route_result result;
	struct lichen_route_packet input;
	uint8_t next_hop[16] = {0x02, 0x00, [15] = 0x55};
	uint8_t packet[72];
	uint8_t original[72];

	configure_router(&router, &state);
	(void)make_source_route_packet(packet, next_hop);
	memcpy(original, packet, sizeof(packet));
	input = (struct lichen_route_packet) {
		.data = packet, .len = sizeof(packet), .ingress = LICHEN_ROUTE_INGRESS_MESH,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_FORWARD);
	REQUIRE(result.path == LICHEN_ROUTE_PATH_RPL_SOURCE_ROUTE);
	REQUIRE(memcmp(result.route.next_hop, next_hop, 16U) == 0);
	REQUIRE(result.forward_hop_limit == 7U);
	REQUIRE(result.source_route_header_offset == 40U);
	REQUIRE(result.source_route_address_offset == 48U);
	REQUIRE(result.source_route_segments_left == 0U);
	REQUIRE(memcmp(packet, original, sizeof(packet)) == 0);

	packet[42] = 4U;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == -EPROTONOSUPPORT);
	packet[42] = 3U;
	packet[44] = 1U;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == -EBADMSG);
	packet[44] = 0U;
	packet[7] = 1U;
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == -EHOSTUNREACH);
	return 0;
}

/* Build an IPv6/UDP packet carrying a Type=0x03 DTN HBH option padded to
 * a 16-byte HBH (spec 05-routing 9.8).  Returns the packet length, or 0
 * if the buffer is too small (callers must REQUIRE a non-zero length). */
static size_t make_dtn_hbh_packet(uint8_t *buf, size_t buf_len,
				  uint8_t flags, uint32_t expiry_unix)
{
	const size_t total = 64U;

	if (buf == NULL || buf_len < total) {
		return 0U;
	}
	memset(buf, 0, total);
	buf[0] = 0x60U;
	buf[4] = (uint8_t)((total - 40U) >> 8);
	buf[5] = (uint8_t)(total - 40U);
	buf[6] = 0U; /* HBH */
	buf[7] = 8U;
	memcpy(&buf[8], source_address, 16U);
	buf[24] = 0x03U; /* external 02xx-style destination, unreachable */
	buf[39] = 2U;
	buf[40] = 17U; /* next = UDP */
	buf[41] = 1U;  /* hdr_ext_len=1 → 16 bytes */
	buf[42] = 0x03U;
	buf[43] = 5U;
	buf[44] = flags;
	buf[45] = (uint8_t)(expiry_unix >> 24);
	buf[46] = (uint8_t)(expiry_unix >> 16);
	buf[47] = (uint8_t)(expiry_unix >> 8);
	buf[48] = (uint8_t)expiry_unix;
	buf[49] = 0x01U; /* PadN */
	buf[50] = 5U;
	buf[56] = 0x16U;
	buf[57] = 0x33U;
	buf[58] = 0x16U;
	buf[59] = 0x33U;
	buf[61] = 8U;
	return total;
}

static int test_queue_copy_gpsr_and_dtn(void)
{
	struct accessor_state state = {.discovery_succeeds = true};
	struct lichen_router router;
	struct lichen_packet_route_result result;
	struct lichen_route_packet input;
	uint8_t destination[16] = {0x02, 0x00, [15] = 0x77};
	uint8_t packet[48];
	uint8_t first_octet;

	configure_router(&router, &state);
	(void)make_udp_packet(packet, sizeof(packet), source_address, destination, 8U);
	first_octet = packet[0];
	input = (struct lichen_route_packet) {
		.data = packet, .len = sizeof(packet), .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_QUEUE);
	REQUIRE(router.pending_count == 1U);
	packet[0] = 0U;
	REQUIRE(router.pending[0].packet_data[0] == first_octet);

	/* GPSR wins over discovery when authenticated destination coordinates exist. */
	configure_router(&router, &state);
	(void)make_udp_packet(packet, sizeof(packet), source_address, destination, 8U);
	lichen_router_set_coords(&router, 476062000, -1223321000);
	uint8_t neighbor[16] = {0xfe, 0x80, [15] = 0x44};
	struct lichen_gradient_entry gpsr_neighbor = {
		.hop_count = 1U, .seq_num = 1U, .source = LICHEN_GRADIENT_DATA,
		.expires_ms = 10000U, .lat_e7 = 465000000, .lon_e7 = -1225000000,
		.coords_valid = true, .valid = true,
	};
	memcpy(gpsr_neighbor.destination_iid, &neighbor[8], 8U);
	memcpy(gpsr_neighbor.next_hop, neighbor, 16U);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &gpsr_neighbor, 1U) == 0);
	input.destination_coords_valid = true;
	input.destination_lat_e7 = 455152000;
	input.destination_lon_e7 = -1226784000;
	REQUIRE(lichen_router_route_packet(&router, &input, 2U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_FORWARD);
	REQUIRE(result.path == LICHEN_ROUTE_PATH_GPSR);
	REQUIRE(memcmp(result.route.next_hop, neighbor, 16U) == 0);

#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	configure_router(&router, &state);
	state.discovery_succeeds = false;
	uint8_t dtn_packet[64];
	size_t dtn_len = make_dtn_hbh_packet(dtn_packet, sizeof(dtn_packet),
					     0x80U, 200U);
	REQUIRE(dtn_len != 0U);
	input = (struct lichen_route_packet) {
		.data = dtn_packet, .len = dtn_len, .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		.now_unix = 100U,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 3U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_STORE_DTN);
	REQUIRE(result.path == LICHEN_ROUTE_PATH_DTN);
	REQUIRE(router.dtn_buffer_bytes == dtn_len);

	/* R-05-080 fail-open: an expiry==0 record (stored by a clockless
	 * ingester without a validated deadline) must survive every local
	 * expire sweep; downstream nodes with valid time enforce it. */
	configure_router(&router, &state);
	uint8_t failopen_dst[16] = {0x03, [15] = 3U};
	REQUIRE(lichen_router_dtn_buffer(&router, failopen_dst, packet,
					 sizeof(packet), 0U, 0U) == 0);
	REQUIRE(router.dtn_buffer_bytes == sizeof(packet));
	REQUIRE(lichen_router_dtn_expire(&router, 0U) == 0);
	REQUIRE(router.dtn_buffer_bytes == sizeof(packet));
	REQUIRE(lichen_router_dtn_expire(&router, 300U) == 0);
	REQUIRE(router.dtn_buffer_bytes == sizeof(packet));

	/* Positive control: an absolute-deadline record does expire. */
	uint8_t deadline_dst[16] = {0x03, [15] = 4U};
	REQUIRE(lichen_router_dtn_buffer(&router, deadline_dst, packet,
					 sizeof(packet), 250U, 0U) == 0);
	REQUIRE(router.dtn_buffer_bytes == 2U * sizeof(packet));
	REQUIRE(lichen_router_dtn_expire(&router, 300U) == 1);
	REQUIRE(router.dtn_buffer_bytes == sizeof(packet));
#endif
	return 0;
}

static int test_dtn_hbh_option_parsing(void)
{
	struct lichen_router router;
	struct accessor_state state = { .joined = false, .discovery_succeeds = false };
	struct lichen_packet_route_result result;
	struct lichen_route_packet input;
	uint8_t packet[64];
	size_t pkt_len;
	uint8_t external[16] = {0x03, [15] = 2U};

	configure_router(&router, &state);

	/* 1. Well-formed DTN option: S-flag set, expiry = 200 (0x000000C8).
	 *    16-byte HBH (hdr_ext_len=1) → 14 option bytes available.
	 */
	{
		const size_t hbh_len = 16U;
		const size_t total = 40U + hbh_len + 8U;

		REQUIRE(sizeof(packet) >= total);
		memset(packet, 0, total);
		packet[0] = 0x60U;
		packet[4] = (uint8_t)((hbh_len + 8U) >> 8);
		packet[5] = (uint8_t)(hbh_len + 8U);
		packet[6] = 0U;  /* HBH */
		packet[7] = 8U;
		memcpy(&packet[8], source_address, 16U);
		memcpy(&packet[24], external, 16U);
		packet[40] = 17U; /* next = UDP */
		packet[41] = 1U;  /* hdr_ext_len=1 → 16 bytes */
		/* DTN option at offset 42: type=0x03, len=5, flags=0x80, expiry=200 */
		packet[42] = 0x03U;
		packet[43] = 5U;
		packet[44] = 0x80U; /* S-flag */
		packet[45] = 0x00U;
		packet[46] = 0x00U;
		packet[47] = 0x00U;
		packet[48] = 0xC8U; /* 200 */
		/* PadN to fill remaining 7 bytes: type=1, len=5, 5 zero bytes */
		packet[49] = 0x01U;
		packet[50] = 5U;
		/* bytes 51..55 already zero (pad data) */
		/* UDP at offset 56 */
		packet[56] = 0x16U;
		packet[57] = 0x33U;
		packet[58] = 0x16U;
		packet[59] = 0x33U;
		packet[61] = 8U;
		pkt_len = total;
	}

#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	input = (struct lichen_route_packet) {
		.data = packet, .len = pkt_len,
		.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		.now_unix = 100U,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 5U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_STORE_DTN);
	REQUIRE(result.path == LICHEN_ROUTE_PATH_DTN);
#endif

	/* 2. S-flag clear → no store-and-forward even with valid expiry. */
	packet[44] = 0x00U; /* clear S-flag */
#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	router.dtn_buffer_bytes = 0U;
	input = (struct lichen_route_packet) {
		.data = packet, .len = pkt_len,
		.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		.now_unix = 100U,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 6U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DROP);
#endif

	/* 3. Duplicate DTN option → reject. */
	{
		const size_t hbh_len = 24U;
		const size_t total = 40U + hbh_len + 8U;
		uint8_t pkt2[80];

		REQUIRE(sizeof(pkt2) >= total);
		memset(pkt2, 0, total);
		pkt2[0] = 0x60U;
		pkt2[4] = (uint8_t)((hbh_len + 8U) >> 8);
		pkt2[5] = (uint8_t)(hbh_len + 8U);
		pkt2[6] = 0U;
		pkt2[7] = 8U;
		memcpy(&pkt2[8], source_address, 16U);
		memcpy(&pkt2[24], external, 16U);
		pkt2[40] = 17U;
		pkt2[41] = 2U; /* hdr_ext_len=2 → 24 bytes */
		/* First DTN option */
		pkt2[42] = 0x03U;
		pkt2[43] = 5U;
		pkt2[44] = 0x80U;
		pkt2[45] = 0U; pkt2[46] = 0U; pkt2[47] = 0U; pkt2[48] = 0xC8U;
		/* Second DTN option (duplicate) */
		pkt2[49] = 0x03U;
		pkt2[50] = 5U;
		pkt2[51] = 0x80U;
		pkt2[52] = 0U; pkt2[53] = 0U; pkt2[54] = 0U; pkt2[55] = 200U;
		/* Pad remaining */
		pkt2[56] = 0x01U;
		pkt2[57] = 5U;
		/* UDP */
		pkt2[64] = 0x16U; pkt2[65] = 0x33U;
		pkt2[66] = 0x16U; pkt2[67] = 0x33U;
		pkt2[69] = 8U;
		input = (struct lichen_route_packet) {
			.data = pkt2, .len = total,
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		};
		int rc = lichen_router_route_packet(&router, &input, 7U, &result);
		REQUIRE(rc == -EBADMSG);
	}

	/* 4. Wrong length for DTN option → reject. */
	packet[43] = 4U; /* should be 5, not 4 */
	input = (struct lichen_route_packet) {
		.data = packet, .len = pkt_len,
		.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 8U, &result) == -EBADMSG);
	packet[43] = 5U; /* restore */

	/* 5. Pad1 before DTN option parses correctly. */
	{
		const size_t hbh_len = 16U;
		const size_t total = 40U + hbh_len + 8U;
		uint8_t pkt3[64];

		REQUIRE(sizeof(pkt3) >= total);
		memset(pkt3, 0, total);
		pkt3[0] = 0x60U;
		pkt3[4] = (uint8_t)((hbh_len + 8U) >> 8);
		pkt3[5] = (uint8_t)(hbh_len + 8U);
		pkt3[6] = 0U;
		pkt3[7] = 8U;
		memcpy(&pkt3[8], source_address, 16U);
		memcpy(&pkt3[24], external, 16U);
		pkt3[40] = 17U;
		pkt3[41] = 1U; /* 16 bytes */
		/* Pad1 at offset 42 */
		pkt3[42] = 0x00U;
		/* DTN at offset 43 */
		pkt3[43] = 0x03U;
		pkt3[44] = 5U;
		pkt3[45] = 0x80U; /* S-flag */
		pkt3[46] = 0x00U;
		pkt3[47] = 0x00U;
		pkt3[48] = 0x01U;
		pkt3[49] = 0x00U; /* expiry = 256 */
		/* PadN to fill remaining 6 bytes: type=1 len=4 + 4 zero */
		pkt3[50] = 0x01U;
		pkt3[51] = 4U;
		/* UDP */
		pkt3[56] = 0x16U; pkt3[57] = 0x33U;
		pkt3[58] = 0x16U; pkt3[59] = 0x33U;
		pkt3[61] = 8U;

#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
		router.dtn_buffer_bytes = 0U;
		input = (struct lichen_route_packet) {
			.data = pkt3, .len = total,
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
			.now_unix = 100U,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 9U, &result) == 0);
		REQUIRE(result.route.decision == LICHEN_ROUTE_STORE_DTN);
#endif
	}

	/* 6. Unrecognized option with action=00 (skip) followed by DTN. */
	{
		const size_t hbh_len = 16U;
		const size_t total = 40U + hbh_len + 8U;
		uint8_t pkt4[64];

		REQUIRE(sizeof(pkt4) >= total);
		memset(pkt4, 0, total);
		pkt4[0] = 0x60U;
		pkt4[4] = (uint8_t)((hbh_len + 8U) >> 8);
		pkt4[5] = (uint8_t)(hbh_len + 8U);
		pkt4[6] = 0U;
		pkt4[7] = 8U;
		memcpy(&pkt4[8], source_address, 16U);
		memcpy(&pkt4[24], external, 16U);
		pkt4[40] = 17U;
		pkt4[41] = 1U;
		/* Unknown option type 0x1e (action=00 → skip), len=3 */
		pkt4[42] = 0x1eU;
		pkt4[43] = 3U;
		/* 3 bytes data (44,45,46) */
		/* DTN at offset 47 */
		pkt4[47] = 0x03U;
		pkt4[48] = 5U;
		pkt4[49] = 0x80U;
		pkt4[50] = 0U; pkt4[51] = 0U; pkt4[52] = 0U; pkt4[53] = 0xC8U;
		/* Pad1 at 54, Pad1 at 55 to fill */
		/* UDP */
		pkt4[56] = 0x16U; pkt4[57] = 0x33U;
		pkt4[58] = 0x16U; pkt4[59] = 0x33U;
		pkt4[61] = 8U;

#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
		router.dtn_buffer_bytes = 0U;
		input = (struct lichen_route_packet) {
			.data = pkt4, .len = total,
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
			.now_unix = 100U,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 10U, &result) == 0);
		REQUIRE(result.route.decision == LICHEN_ROUTE_STORE_DTN);
#endif
	}

	/* 7. Unrecognized option with action=10 (discard) → reject. */
	{
		const size_t hbh_len = 8U;
		const size_t total = 40U + hbh_len + 8U;
		uint8_t pkt5[64];

		REQUIRE(sizeof(pkt5) >= total);
		memset(pkt5, 0, total);
		pkt5[0] = 0x60U;
		pkt5[5] = (uint8_t)(hbh_len + 8U);
		pkt5[6] = 0U;
		pkt5[7] = 8U;
		memcpy(&pkt5[8], source_address, 16U);
		memcpy(&pkt5[24], external, 16U);
		pkt5[40] = 17U;
		pkt5[41] = 0U; /* 8 bytes */
		/* Unknown type 0x8e: action bits = 10 → discard silently */
		pkt5[42] = 0x8eU;
		pkt5[43] = 4U;
		/* UDP */
		pkt5[48] = 0x16U; pkt5[49] = 0x33U;
		pkt5[50] = 0x16U; pkt5[51] = 0x33U;
		pkt5[53] = 8U;
		input = (struct lichen_route_packet) {
			.data = pkt5, .len = total,
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 11U, &result)
			== -EPROTONOSUPPORT);
	}

	/* 8. Expired DTN option at valid wall-clock → drop silently. */
#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	{
		uint8_t pkt6[64];
		size_t pkt6_len = make_dtn_hbh_packet(pkt6, sizeof(pkt6),
						      0x80U, 50U);
		REQUIRE(pkt6_len != 0U);

		router.dtn_buffer_bytes = 0U;
		input = (struct lichen_route_packet) {
			.data = pkt6, .len = pkt6_len,
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
			.now_unix = 100U,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 12U, &result) == 0);
		REQUIRE(result.route.decision == LICHEN_ROUTE_DROP);
		REQUIRE(router.dtn_buffer_bytes == 0U);
	}
#endif

	/* 9. R-05-080 fail-open: no valid wall-clock → store despite expiry=0. */
#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	{
		uint8_t pkt7[64];
		size_t pkt7_len = make_dtn_hbh_packet(pkt7, sizeof(pkt7),
						      0x80U, 0U);
		REQUIRE(pkt7_len != 0U);

		router.dtn_buffer_bytes = 0U;
		input = (struct lichen_route_packet) {
			.data = pkt7, .len = pkt7_len,
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 13U, &result) == 0);
		REQUIRE(result.route.decision == LICHEN_ROUTE_STORE_DTN);
		REQUIRE(router.dtn_buffer_bytes == pkt7_len);

		/* dtn_expire flushes the expiry==0 fail-open store once valid
		 * wall-clock arrives (documented bpyr interplay: the record is
		 * purged, not re-queued for downstream enforcement). */
		REQUIRE(lichen_router_dtn_expire(&router, 100U) == 1);
		REQUIRE(router.dtn_buffer_bytes == 0U);
	}
#endif

	/* 10. uint32 unix-time wraparound: expiry just past the 2^32 boundary
	 * vs now just before it — the wrap-safe signed comparison (same form
	 * as lichen_router_dtn_expire) must treat expiry as in the future. */
#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	{
		uint8_t pkt8[64];
		size_t pkt8_len = make_dtn_hbh_packet(pkt8, sizeof(pkt8),
						      0x80U, 5U);
		REQUIRE(pkt8_len != 0U);

		/* Fresh buffer: earlier cases exhausted the 4 DTN slots. */
		configure_router(&router, &state);
		state.discovery_succeeds = false;
		input = (struct lichen_route_packet) {
			.data = pkt8, .len = pkt8_len,
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
			.now_unix = UINT32_MAX - 10U,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 14U, &result) == 0);
		REQUIRE(result.route.decision == LICHEN_ROUTE_STORE_DTN);
		REQUIRE(router.dtn_buffer_bytes == pkt8_len);
	}
#endif

	/* 11. S-flag with expiry==0 at a VALID clock: the zero deadline is
	 * already past (0 <= now) → silent drop, nothing stored. */
#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	{
		uint8_t pkt9[64];
		size_t pkt9_len = make_dtn_hbh_packet(pkt9, sizeof(pkt9),
						      0x80U, 0U);
		REQUIRE(pkt9_len != 0U);

		configure_router(&router, &state);
		state.discovery_succeeds = false;
		input = (struct lichen_route_packet) {
			.data = pkt9, .len = pkt9_len,
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
			.now_unix = 100U,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 15U, &result) == 0);
		REQUIRE(result.route.decision == LICHEN_ROUTE_DROP);
		REQUIRE(router.dtn_buffer_bytes == 0U);
	}
#endif

	/* 12. lichen_router_dtn_expire boundary matrix: not-due keeps the
	 * record, expiry==now flushes it (signed diff <= 0). */
#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	{
		uint8_t pkt10[64];
		size_t pkt10_len = make_dtn_hbh_packet(pkt10, sizeof(pkt10),
						       0x80U, 200U);
		REQUIRE(pkt10_len != 0U);

		configure_router(&router, &state);
		state.discovery_succeeds = false;
		input = (struct lichen_route_packet) {
			.data = pkt10, .len = pkt10_len,
			.ingress = LICHEN_ROUTE_INGRESS_LOCAL,
			.now_unix = 100U,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 16U, &result) == 0);
		REQUIRE(result.route.decision == LICHEN_ROUTE_STORE_DTN);

		REQUIRE(lichen_router_dtn_expire(&router, 199U) == 0);
		REQUIRE(router.dtn_buffer_bytes == pkt10_len);
		REQUIRE(lichen_router_dtn_expire(&router, 200U) == 1);
		REQUIRE(router.dtn_buffer_bytes == 0U);
	}
#endif

	return 0;
}

/* Spec 05-routing 8.9 (R-05-063): egress decapsulation of IPv6-in-IPv6
 * tunnels (post-SRH-consumption outer, nh=41) with fail-closed inner
 * verification against this node's authorized primary address. */
static int test_ipv6_in_ipv6_egress_decap(void)
{
	struct lichen_router router;
	struct accessor_state state = { .joined = false, .discovery_succeeds = false };
	struct lichen_packet_route_result result;
	struct lichen_route_packet input;
	uint8_t inner[48];
	uint8_t outer[88];

	configure_router(&router, &state);
	state.discovery_succeeds = false;

	/* 1. Valid tunnel: inner addressed to this node delivers locally. */
	(void)make_udp_packet(inner, sizeof(inner), source_address, node_address, 64U);
	memset(outer, 0, sizeof(outer));
	outer[0] = 0x60U;
	outer[5] = 48U; /* payload_len = inner length */
	outer[6] = 41U;
	outer[7] = 64U;
	outer[8] = 0x02U;
	outer[9] = 0x00U;
	outer[15] = 0x02U;
	memcpy(&outer[24], node_address, 16U);
	memcpy(&outer[40], inner, sizeof(inner));

	input = (struct lichen_route_packet) {
		.data = outer, .len = sizeof(outer), .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 1U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DELIVER_LOCAL);

	/* 2. Inner destination is not the authorized primary -> fail closed. */
	{
		uint8_t foreign[16];
		uint8_t inner2[48];
		uint8_t outer2[88];

		memcpy(foreign, node_address, 16U);
		foreign[15] = 0xffU;
		(void)make_udp_packet(inner2, sizeof(inner2), source_address, foreign, 64U);
		memcpy(outer2, outer, 40U);
		memcpy(&outer2[40], inner2, sizeof(inner2));
		input = (struct lichen_route_packet) {
			.data = outer2, .len = sizeof(outer2), .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 2U, &result) == -EBADMSG);
	}

	/* 3. Inner payload-length inconsistent with the actual inner length. */
	{
		uint8_t outer3[88];

		memcpy(outer3, outer, sizeof(outer3));
		outer3[45] = 9U; /* inner payload_len = 9, actual 8 -> inconsistent */
		input = (struct lichen_route_packet) {
			.data = outer3, .len = sizeof(outer3), .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 3U, &result) == -EBADMSG);
	}

	/* 4. Nested tunnel (nh=41 inside nh=41) -> outside bounded profile. */
	{
		uint8_t inner_tunnel[88];
		uint8_t outer4[128];

		memcpy(inner_tunnel, outer, sizeof(outer));
		memset(outer4, 0, sizeof(outer4));
		outer4[0] = 0x60U;
		outer4[5] = sizeof(inner_tunnel);
		outer4[6] = 41U;
		outer4[7] = 64U;
		outer4[8] = 0x02U;
		outer4[9] = 0x00U;
		outer4[15] = 0x02U;
		memcpy(&outer4[24], node_address, 16U);
		memcpy(&outer4[40], inner_tunnel, sizeof(inner_tunnel));
		input = (struct lichen_route_packet) {
			.data = outer4, .len = sizeof(outer4), .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 4U, &result) == -EBADMSG);
	}

	/* 5. Truncated inner (inner_len < 40) -> fail closed. */
	{
		uint8_t outer5[60];

		memcpy(outer5, outer, 40U);
		memset(&outer5[40], 0, 20U);
		outer5[5] = 20U; /* payload_len = 20: inner is only 20 bytes */
		input = (struct lichen_route_packet) {
			.data = outer5, .len = sizeof(outer5), .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		};
		REQUIRE(lichen_router_route_packet(&router, &input, 5U, &result) == -EBADMSG);
	}

	return 0;
}

static int run_all_tests(void)
{
	int ret;

	ret = test_shared_route_vectors();
	if (ret != 0) return ret;
	ret = test_validation_and_atomic_output();
	if (ret != 0) return ret;
	ret = test_hop_limit_loop_and_local_delivery();
	if (ret != 0) return ret;
	ret = test_multicast_scope_and_boundary();
	if (ret != 0) return ret;
	ret = test_source_route_validation();
	if (ret != 0) return ret;
	ret = test_queue_copy_gpsr_and_dtn();
	if (ret != 0) return ret;
	ret = test_dtn_hbh_option_parsing();
	if (ret != 0) return ret;
	ret = test_ipv6_in_ipv6_egress_decap();
	if (ret != 0) return ret;
	return 0;
}

#ifdef __ZEPHYR__
ZTEST(routing_dispatch, test_complete_dispatcher)
{
	zassert_equal(run_all_tests(), 0, "routing dispatcher regression");
}

ZTEST_SUITE(routing_dispatch, NULL, NULL, NULL, NULL, NULL);
#else
int main(void)
{
	int ret = run_all_tests();

	if (ret != 0) {
		fprintf(stderr, "routing dispatcher failed at line %d\n", ret);
		return 1;
	}
	puts("routing dispatcher tests passed");
	return 0;
}
#endif
