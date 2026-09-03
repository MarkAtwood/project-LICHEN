/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/beacon.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Vector beacon_wire_example from ccp_beacon_format.json (independent
 * oracle: committed header_hex, not code-under-test output). */
static const uint8_t WIRE[] = {
	0x00, 0x00, 0x00, 0x01, /* epoch 1 */
	0x10,                   /* num_slots 16 */
	0x00, 0x00, 0x30, 0x39, /* sfn 12345 */
	0x65, 0x92, 0x00, 0x80, /* timestamp 1704067200 */
	0x00,                   /* flags 0 */
	0x01,                   /* rx_chains 1 */
	0x00, 0x14,             /* setup_window 20 */
	0x08, 0xfc,             /* occupied_time 2300 */
	0x32,                   /* guard 50 */
	0x00, 0x00, 0x00, 0x01  /* channel_mask 1 */
};

static void test_parse_vector(void)
{
	struct lichen_beacon_header h;
	assert(lichen_beacon_header_parse(WIRE, sizeof(WIRE), &h) ==
	       LICHEN_BEACON_OK);
	assert(h.epoch == 1);
	assert(h.num_slots == 16);
	assert(h.sfn == 12345);
	assert(h.timestamp == 1704067200U);
	assert(h.flags == 0);
	assert(h.rx_chains == 1);
	assert(h.setup_window == 20);
	assert(h.occupied_time == 2300);
	assert(h.guard == 50);
	assert(h.channel_mask == 1);
}

static void test_serialize_roundtrip(void)
{
	struct lichen_beacon_header h;
	uint8_t out[24];

	assert(lichen_beacon_header_parse(WIRE, 24, &h) == LICHEN_BEACON_OK);
	assert(lichen_beacon_header_serialize(&h, out, sizeof(out)) ==
	       LICHEN_BEACON_OK);
	assert(memcmp(out, WIRE, 24) == 0);
}

static void test_reserved_flag_rejected(void)
{
	uint8_t bad_wire[24];
	struct lichen_beacon_header h;

	memcpy(bad_wire, WIRE, 24);
	bad_wire[13] = 0x10; /* reserved bit 4 */
	assert(lichen_beacon_header_parse(bad_wire, 24, &h) ==
	       LICHEN_BEACON_RESERVED_FLAG_SET);

	struct lichen_beacon_header bad = { .flags = 0x20 };
	uint8_t tmp[24];
	assert(lichen_beacon_header_serialize(&bad, tmp, sizeof(tmp)) ==
	       LICHEN_BEACON_RESERVED_FLAG_SET);
}

static void test_short_buffer_rejected(void)
{
	struct lichen_beacon_header h;
	uint8_t full[72];
	size_t signed_len = 0;

	memcpy(full, WIRE, sizeof(WIRE));
	memset(&full[sizeof(WIRE)], 0, sizeof(full) - sizeof(WIRE));
	assert(lichen_beacon_header_parse(WIRE, 23, &h) ==
	       LICHEN_BEACON_TOO_SHORT);
	assert(lichen_beacon_signature_bytes(full, sizeof(full) - 1) == NULL);
	assert(lichen_beacon_signature_bytes(full, sizeof(full)) != NULL);
	assert(lichen_beacon_signed_data(full, sizeof(full), &signed_len) ==
		       &full[0] &&
	       signed_len == sizeof(WIRE));
}

static void test_null_guards(void)
{
	struct lichen_beacon_header h;
	uint8_t tmp[24];
	assert(lichen_beacon_header_parse(NULL, 24, &h) ==
	       LICHEN_BEACON_TOO_SHORT);
	assert(lichen_beacon_header_parse(WIRE, 24, NULL) ==
	       LICHEN_BEACON_TOO_SHORT);
	assert(lichen_beacon_header_serialize(NULL, tmp, sizeof(tmp)) ==
	       LICHEN_BEACON_TOO_SHORT);
	assert(lichen_beacon_signature_bytes(NULL, 72) == NULL);
}

static void test_intersect_channel_mask(void)
{
	/* R-02a-006: local intersection of the beacon's advertised
	 * channel_mask with the permitted mask. Expectations mirror the
	 * intersect_channel_mask cases in
	 * test/vectors/ccp4_regional_channel_plans.json (EU868: 8 channels,
	 * permitted 0xFF); the JSON is the committed independent oracle. */
	uint32_t eu868_permitted = 0xFFU;

	assert(lichen_beacon_intersect_channel_mask(eu868_permitted, 0x03U) ==
	       0x03U); /* intersect_channel_mask_eu868_subset */
	assert(lichen_beacon_intersect_channel_mask(eu868_permitted,
						    0xFFFFU) == 0xFFU);
	/* intersect_channel_mask_eu868_superset */
	assert(lichen_beacon_intersect_channel_mask(eu868_permitted,
						    0xF000U) == 0x00U);
	/* intersect_channel_mask_eu868_disjoint: caller MUST reject */
	assert(lichen_beacon_intersect_channel_mask(eu868_permitted, 0xFFU) ==
	       0xFFU); /* intersect_channel_mask_eu868_full */

	/* Hardware with fewer channels than the plan narrows permitted. */
	assert(lichen_beacon_intersect_channel_mask(0x0FU, 0xFFU) == 0x0FU);
	/* Empty intersection on either side yields 0. */
	assert(lichen_beacon_intersect_channel_mask(0x00U, 0xFFU) == 0x00U);
	assert(lichen_beacon_intersect_channel_mask(0xFFU, 0x00U) == 0x00U);
}

static bool stub_verify(const uint8_t *signed_data, size_t signed_len,
			const uint8_t *sig, size_t sig_len, void *user)
{
	(void)signed_data;
	(void)signed_len;
	(void)sig;
	(void)sig_len;
	return user != NULL;
}

static void test_verify_gate(void)
{
	/* Spec 8 / ccp_beacon_sig_gate.json: verify-gate contract. */
	uint8_t beacon[LICHEN_BEACON_MIN_SIZE];
	memset(beacon, 0xAB, sizeof(beacon));

	CHECK(lichen_beacon_verify_gate(beacon, sizeof(beacon), stub_verify,
					(void *)1),
	      "verify gate accepts when stub verify passes");
	CHECK(!lichen_beacon_verify_gate(beacon, LICHEN_BEACON_MIN_SIZE - 1U,
					 stub_verify, (void *)1),
	      "too-short beacon fails closed");
	CHECK(!lichen_beacon_verify_gate(NULL, LICHEN_BEACON_MIN_SIZE,
					 stub_verify, (void *)1),
	      "NULL beacon fails closed");
	CHECK(!lichen_beacon_verify_gate(beacon, LICHEN_BEACON_MIN_SIZE,
					 stub_verify, NULL),
	      "verify reject propagates");
}

int main(void)
{
	test_parse_vector();
	test_serialize_roundtrip();
	test_reserved_flag_rejected();
	test_short_buffer_rejected();
	test_null_guards();
	test_intersect_channel_mask();
	test_verify_gate();
	printf("tdma_beacon tests passed\n");
	return 0;
}
