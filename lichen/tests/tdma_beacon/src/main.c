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
	assert(lichen_beacon_parse_header(WIRE, sizeof(WIRE), &h) == 0);
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

	assert(lichen_beacon_parse_header(WIRE, 24, &h) == 0);
	assert(lichen_beacon_serialize_header(&h, out) == 24);
	assert(memcmp(out, WIRE, 24) == 0);
}

static void test_reserved_flag_rejected(void)
{
	uint8_t bad_wire[24];
	struct lichen_beacon_header h;

	memcpy(bad_wire, WIRE, 24);
	bad_wire[13] = 0x10; /* reserved bit 4 */
	assert(lichen_beacon_parse_header(bad_wire, 24, &h) ==
	       LICHEN_BEACON_ERR_RESERVED);

	struct lichen_beacon_header bad = { .flags = 0x20 };
	uint8_t tmp[24];
	assert(lichen_beacon_serialize_header(&bad, tmp) ==
	       LICHEN_BEACON_ERR_RESERVED);
}

static void test_short_buffer_rejected(void)
{
	struct lichen_beacon_header h;
	assert(lichen_beacon_parse_header(WIRE, 23, &h) ==
	       LICHEN_BEACON_ERR_SHORT);
	assert(lichen_beacon_signature_bytes(WIRE, 71) == NULL);
	assert(lichen_beacon_signature_bytes(WIRE, 72) != NULL);
	assert(lichen_beacon_signed_data(WIRE, 72) != NULL);
}

static void test_null_guards(void)
{
	struct lichen_beacon_header h;
	uint8_t tmp[24];
	assert(lichen_beacon_parse_header(NULL, 24, &h) ==
	       LICHEN_BEACON_ERR_SHORT);
	assert(lichen_beacon_parse_header(WIRE, 24, NULL) ==
	       LICHEN_BEACON_ERR_SHORT);
	assert(lichen_beacon_serialize_header(NULL, tmp) ==
	       LICHEN_BEACON_ERR_SHORT);
	assert(lichen_beacon_signature_bytes(NULL, 72) == NULL);
}

int main(void)
{
	test_parse_vector();
	test_serialize_roundtrip();
	test_reserved_flag_rejected();
	test_short_buffer_rejected();
	test_null_guards();
	printf("tdma_beacon tests passed\n");
	return 0;
}
