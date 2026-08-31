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
	uint8_t external[16] = {0x03, [15] = 2U};
	(void)make_udp_packet(packet, sizeof(packet), source_address, external, 8U);
	input = (struct lichen_route_packet) {
		.data = packet, .len = sizeof(packet), .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		.dtn_expiry_unix = 200U, .now_unix = 100U,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 3U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_STORE_DTN);
	REQUIRE(result.path == LICHEN_ROUTE_PATH_DTN);
	REQUIRE(router.dtn_buffer_bytes == sizeof(packet));
#endif
	return 0;
}

static int test_dtn_expiry_zero_drop_and_expire(void)
{
#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	struct accessor_state state = {.discovery_succeeds = false};
	struct lichen_router router;
	struct lichen_packet_route_result result;
	struct lichen_route_packet input;
	uint8_t destination[16] = {0x03, [15] = 9U};
	uint8_t packet[48];

	/* S-flag store-and-forward with expiry==0 at a valid clock: the
	 * router DTN fallback requires a nonzero expiry, so the packet is
	 * silently dropped rather than buffered (the R-05-080 fail-open
	 * interplay for clockless nodes is tracked in bead 6dh4). */
	configure_router(&router, &state);
	(void)make_udp_packet(packet, sizeof(packet), source_address, destination, 8U);
	input = (struct lichen_route_packet) {
		.data = packet, .len = sizeof(packet), .ingress = LICHEN_ROUTE_INGRESS_LOCAL,
		.dtn_expiry_unix = 0U, .now_unix = 100U,
	};
	REQUIRE(lichen_router_route_packet(&router, &input, 10U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_DROP);
	REQUIRE(router.dtn_buffer_bytes == 0U);

	/* A stored message survives until its expiry, then flushes exactly
	 * once via lichen_router_dtn_expire. */
	configure_router(&router, &state);
	input.dtn_expiry_unix = 200U;
	REQUIRE(lichen_router_route_packet(&router, &input, 11U, &result) == 0);
	REQUIRE(result.route.decision == LICHEN_ROUTE_STORE_DTN);
	REQUIRE(result.path == LICHEN_ROUTE_PATH_DTN);
	REQUIRE(router.dtn_buffer_bytes == sizeof(packet));

	REQUIRE(lichen_router_dtn_expire(&router, 150U) == 0);
	REQUIRE(router.dtn_buffer_bytes == sizeof(packet));
	REQUIRE(lichen_router_dtn_expire(&router, 200U) == 1);
	REQUIRE(router.dtn_buffer_bytes == 0U);
	REQUIRE(lichen_router_dtn_expire(&router, 300U) == 0);
	REQUIRE(lichen_router_dtn_expire(NULL, 300U) == 0);
#endif
	return 0;
}

static int test_adaptive_sf_density_threshold(void)
{
#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)
	struct accessor_state state = {.discovery_succeeds = true};
	struct lichen_router router;
	uint8_t destination[16] = {0x02, 0x00, [15] = 0x33};
	uint8_t neighbor[16] = {0xfe, 0x80, [15] = 0x55};
	struct lichen_gradient_entry entry = {
		.hop_count = 1U,
		.seq_num = 1U,
		.source = LICHEN_GRADIENT_DATA,
		.expires_ms = 100000U,
	};
	memcpy(entry.destination_iid, &destination[8], 8U);
	memcpy(entry.next_hop, neighbor, 16U);
	entry.sf.current_sf = 9U;

	uint8_t sf = 0U;
	bool tx_allowed = false;

	/* Spec 2a.8 step 3: Density > 8 (strictly) triggers SF +2. The old
	 * code used 10 — the 9-boundary case pins the spec value. */
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 9U, 0U, 0U, 0U,
					  1000U, &sf, &tx_allowed) == 0);
	REQUIRE(sf == 11U);
	REQUIRE(tx_allowed == true);

	/* Density == 8 is not > 8: no step-3 bump. */
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 8U, 0U, 0U, 0U,
					  1001U, &sf, &tx_allowed) == 0);
	REQUIRE(sf == 9U);

	/* Utilization > 150 still bumps +2 with low density. */
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 0U, 151U, 0U, 0U,
					  1002U, &sf, &tx_allowed) == 0);
	REQUIRE(sf == 11U);
#endif
	return 0;
}

static int test_adaptive_sf_floors(void)
{
#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)
	struct accessor_state state = {.discovery_succeeds = true};
	struct lichen_router router;
	uint8_t destination[16] = {0x02, 0x00, [15] = 0x34};
	uint8_t neighbor[16] = {0xfe, 0x80, [15] = 0x56};
	struct lichen_gradient_entry entry = {
		.hop_count = 1U,
		.seq_num = 1U,
		.source = LICHEN_GRADIENT_DATA,
		.expires_ms = 100000U,
	};
	memcpy(entry.destination_iid, &destination[8], 8U);
	memcpy(entry.next_hop, neighbor, 16U);

	uint8_t sf = 0U;
	bool tx_allowed = false;

	/* Spec 2a.8 post-step-6 floors, in order a-d. Each case re-seeds a
	 * fresh router/entry so the previous floor's stored SF cannot leak.
	 * density=8 and utilization=0 keep steps 3 and 5 out of the way. */

	/* Floor a: EMA_SNR < -5 forces SF = 12. */
	entry.sf.current_sf = 9U;
	entry.sf.snr_ewma = -6;
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 8U, 0U, 0U, 0U,
					  2000U, &sf, &tx_allowed) == 0);
	REQUIRE(sf == 12U);

	/* Floor b: -5 <= EMA_SNR < 0 raises SF to at least 11. */
	entry.sf.current_sf = 9U;
	entry.sf.snr_ewma = -1;
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 8U, 0U, 0U, 0U,
					  2001U, &sf, &tx_allowed) == 0);
	REQUIRE(sf == 11U);

	/* Boundary: EMA_SNR = 0 triggers neither a nor b. */
	entry.sf.current_sf = 9U;
	entry.sf.snr_ewma = 0;
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 8U, 0U, 0U, 0U,
					  2002U, &sf, &tx_allowed) == 0);
	REQUIRE(sf == 9U);

	/* Floor c: Density > 8 raises SF to at least 11. Start at 7: step 3
	 * raises 7 -> 9, then the floor raises 9 -> 11. */
	entry.sf.current_sf = 7U;
	entry.sf.snr_ewma = 5;
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 9U, 0U, 0U, 0U,
					  2003U, &sf, &tx_allowed) == 0);
	REQUIRE(sf == 11U);

	/* Density == 8 with positive SNR: no step-3 bump, no floor c. */
	entry.sf.current_sf = 7U;
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 8U, 0U, 0U, 0U,
					  2004U, &sf, &tx_allowed) == 0);
	REQUIRE(sf == 7U);

	/* Floor d: LoadFactor >= 0.8 raises SF to at least 11. */
	entry.sf.current_sf = 7U;
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 8U, 0U, 0U,
					  52429U, 2005U, &sf,
					  &tx_allowed) == 0);
	REQUIRE(sf == 11U);

	/* Load factor just below 0.8 (52428 = 0.79998) applies no floor. */
	entry.sf.current_sf = 7U;
	configure_router(&router, &state);
	REQUIRE(lichen_gradient_update(&router.gradient_table, &entry, 1U) == 0);
	REQUIRE(lichen_gradient_sf_select(&router.gradient_table,
					  &destination[8], 8U, 0U, 0U,
					  52428U, 2006U, &sf,
					  &tx_allowed) == 0);
	REQUIRE(sf == 7U);
#endif
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
	ret = test_dtn_expiry_zero_drop_and_expire();
	if (ret != 0) return ret;
	ret = test_adaptive_sf_density_threshold();
	if (ret != 0) return ret;
	return test_adaptive_sf_floors();
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
