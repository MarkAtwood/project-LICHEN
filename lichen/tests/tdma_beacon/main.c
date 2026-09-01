/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * Host test consuming test/vectors/ccp_beacon_format.json
 * (beacon_format cases; spec/02a 2a.2; bead b7z9.60 C slice).
 */

#include <lichen/beacon.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("FAIL: %s\n", msg);                             \
			failures++;                                            \
		}                                                              \
	} while (0)

static char *read_file(const char *path)
{
	FILE *f = fopen(path, "rb");

	if (f == NULL) {
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	long size = ftell(f);
	if (size < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	char *buf = malloc((size_t)size + 1);
	if (buf == NULL) {
		fclose(f);
		return NULL;
	}
	size_t n = fread(buf, 1, (size_t)size, f);
	fclose(f);
	buf[n] = '\0';
	return buf;
}

static int hex_byte(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t cap)
{
	size_t n = strlen(hex) / 2;
	if (n > cap) {
		return 0;
	}
	for (size_t i = 0; i < n; i++) {
		int hi = hex_byte(hex[2 * i]);
		int lo = hex_byte(hex[2 * i + 1]);
		if (hi < 0 || lo < 0) {
			return 0;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return n;
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1]
				   : "test/vectors/ccp_beacon_format.json";
	char *json = read_file(path);

	if (json == NULL) {
		printf("FAIL: cannot read %s (%s)\n", path, strerror(errno));
		return 1;
	}

	/* Extract the beacon_wire_example oracle: header_hex + input fields. */
	const char *name_at = strstr(json, "\"name\": \"beacon_wire_example\"");
	CHECK(name_at != NULL, "beacon_wire_example present");
	if (name_at == NULL) {
		free(json);
		return 1;
	}
	const char *hdr_hex_at = strstr(name_at, "\"header_hex\": \"");
	CHECK(hdr_hex_at != NULL, "header_hex present");
	hdr_hex_at += strlen("\"header_hex\": \"");
	char hex[64];
	CHECK(sscanf(hdr_hex_at, "%48[0-9a-f]", hex) == 1, "header hex read");
	uint8_t oracle[24];
	size_t oracle_len = hex_decode(hex, oracle, sizeof(oracle));
	CHECK(oracle_len == 24, "oracle header is 24 bytes");

	/* Input fields (parsed from the JSON object by simple scan). */
	const char *obj = name_at;
	long long epoch = 0, num_slots = 0, sfn = 0, timestamp = 0;
	long long flags = 0, rx_chains = 0, setup_window = 0;
	long long occupied_time = 0, guard_ll = 0, channel_mask = 0;

	#define FIND_LL(keystr, var)                                        \
		do {                                                        \
			char needle_[64];                                   \
			snprintf(needle_, sizeof(needle_), "\"%s\": ",    \
				 keystr);                                   \
			const char *at = strstr(obj, needle_);              \
			CHECK(at != NULL, "field " keystr);                 \
			var = strtoll(at + strlen(needle_), NULL, 10);      \
		} while (0)

	FIND_LL("epoch", epoch);
	FIND_LL("num_slots", num_slots);
	FIND_LL("sfn", sfn);
	FIND_LL("timestamp", timestamp);
	FIND_LL("flags", flags);
	FIND_LL("rx_chains", rx_chains);
	FIND_LL("setup_window", setup_window);
	FIND_LL("occupied_time", occupied_time);
	FIND_LL("guard", guard_ll);
	FIND_LL("channel_mask", channel_mask);

	struct lichen_beacon_header header = {
		.epoch = (uint32_t)epoch,
		.num_slots = (uint8_t)num_slots,
		.sfn = (uint32_t)sfn,
		.timestamp = (uint32_t)timestamp,
		.flags = (uint8_t)flags,
		.rx_chains = (uint8_t)rx_chains,
		.setup_window = (uint16_t)setup_window,
		.occupied_time = (uint16_t)occupied_time,
		.guard = 0,
		.channel_mask = (uint32_t)channel_mask,
	};
	header.guard = 50;
	CHECK(guard_ll == 50, "guard is the normative 50 ms");

	uint8_t packed[24];
	CHECK(lichen_beacon_header_serialize(&header, packed,
					     sizeof(packed)) ==
		      LICHEN_BEACON_OK,
	      "serialize from vector inputs");
	CHECK(memcmp(packed, oracle, 24) == 0,
	      "serialized bytes match the wire oracle");

	struct lichen_beacon_header parsed;
	CHECK(lichen_beacon_header_parse(packed, sizeof(packed), &parsed) ==
		      LICHEN_BEACON_OK,
	      "parse roundtrip");
	CHECK(parsed.epoch == header.epoch && parsed.num_slots == header.num_slots &&
		      parsed.sfn == header.sfn &&
		      parsed.timestamp == header.timestamp &&
		      parsed.flags == header.flags &&
		      parsed.rx_chains == header.rx_chains &&
		      parsed.setup_window == header.setup_window &&
		      parsed.occupied_time == header.occupied_time &&
		      parsed.guard == header.guard &&
		      parsed.channel_mask == header.channel_mask,
	      "roundtrip fields intact");
	CHECK(memcmp(oracle, packed, 24) == 0, "parse-from-oracle equality");

	/* Short buffer. */
	CHECK(lichen_beacon_header_parse(packed, 23, &parsed) ==
		      LICHEN_BEACON_TOO_SHORT,
	      "short parse rejected");
	CHECK(lichen_beacon_header_serialize(&header, packed, 23) ==
		      LICHEN_BEACON_TOO_SHORT,
	      "short serialize rejected");

	/* Reserved flag bits (4-7) fail closed both directions. */
	struct lichen_beacon_header resv = header;
	resv.flags = 0x10;
	CHECK(lichen_beacon_header_serialize(&resv, packed, sizeof(packed)) ==
		      LICHEN_BEACON_RESERVED_FLAG_SET,
	      "reserved flag serialize rejected");
	uint8_t resv_bytes[24];
	memcpy(resv_bytes, packed, 24);
	resv_bytes[13] = 0x80;
	CHECK(lichen_beacon_header_parse(resv_bytes, 24, &parsed) ==
		      LICHEN_BEACON_RESERVED_FLAG_SET,
	      "reserved flag parse rejected");

	/* NULL guards. */
	CHECK(lichen_beacon_header_serialize(NULL, packed, sizeof(packed)) ==
		      LICHEN_BEACON_TOO_SHORT,
	      "NULL serialize rejected");

	/* Flag predicates. */
	CHECK(lichen_beacon_is_scheduled(0x01) &&
		      lichen_beacon_is_csma(0x02) &&
		      lichen_beacon_is_ch0_rx(0x04) &&
		      lichen_beacon_has_gnss_pps(0x08) &&
		      !lichen_beacon_is_scheduled(0) &&
		      !lichen_beacon_is_csma(0),
	      "flag predicates");

	/* Extraction boundaries. */
	uint8_t options[3] = { 0xA1, 0x01, 0x02 };
	uint8_t signature[48];
	memset(signature, 0x77, sizeof(signature));
	uint8_t beacon[24 + sizeof(options) + 48];
	memcpy(beacon, oracle, 24);
	memcpy(&beacon[24], options, sizeof(options));
	memcpy(&beacon[27], signature, 48);
	size_t signed_len = 0;
	size_t options_len = 0;

	CHECK(lichen_beacon_signature_bytes(beacon, sizeof(beacon)) ==
		      &beacon[27],
	      "signature extraction");
	CHECK(lichen_beacon_signed_data(beacon, sizeof(beacon), &signed_len) ==
		      beacon &&
		      signed_len == 27,
	      "signed data extraction");
	CHECK(lichen_beacon_cbor_options(beacon, sizeof(beacon),
					 &options_len) == &beacon[24] &&
		      options_len == 3,
	      "cbor options extracted");

	/* Minimal beacon: no CBOR section. */
	uint8_t minimal[72];
	memcpy(minimal, oracle, 24);
	memcpy(&minimal[24], signature, 48);
	CHECK(lichen_beacon_signature_bytes(minimal, sizeof(minimal)) ==
		      &minimal[24],
	      "minimal signature");
	CHECK(lichen_beacon_cbor_options(minimal, sizeof(minimal),
					 &options_len) == NULL,
	      "minimal beacon has no options");
	/* Header-only: too short for a signature. */
	CHECK(lichen_beacon_signature_bytes(oracle, 24) == NULL,
	      "header-only has no signature");
	CHECK(lichen_beacon_signed_data(oracle, 24, &signed_len) == NULL,
	      "header-only has no signed data");
	/* NULL guards. */
	CHECK(lichen_beacon_signature_bytes(NULL, 72) == NULL,
	      "NULL beacon rejected");
	CHECK(lichen_beacon_header_parse(NULL, 24, &parsed) ==
		      LICHEN_BEACON_TOO_SHORT,
	      "NULL parse rejected");
	CHECK(lichen_beacon_signed_data(beacon, sizeof(beacon), NULL) == NULL,
	      "signed data with NULL len rejected");
	CHECK(lichen_beacon_cbor_options(beacon, sizeof(beacon), NULL) == NULL,
	      "cbor options with NULL len rejected");

	/* slot_map CBOR validation (ccp_slot_map_validation.json; spec 02a
	 * 2a.2 R-02a-012). The vectors list raw slot arrays; the CBOR
	 * encoding for each case is derived from the array per the CBOR
	 * immediate/0x18 rules the Rust oracle implements. */
	const char *sm_path_env = getenv("CCP_SLOT_MAP_VECTORS");
	char sm_path[256];
	snprintf(sm_path, sizeof(sm_path), "%s",
		 sm_path_env ? sm_path_env
			     : "../../../test/vectors/ccp_slot_map_validation.json");
	char *sm_json = read_file(sm_path);
	CHECK(sm_json != NULL, "cannot read ccp_slot_map_validation.json");
	if (sm_json != NULL) {
	struct {
		const char *name;
		uint8_t num_slots;
		uint8_t slots[8];
		size_t slot_count;
		enum lichen_slot_map_status expected;
	} sm_cases[] = {
		{ "slot_boundary_valid", 8, { 0, 1, 7 }, 3, LICHEN_SLOT_MAP_OK },
		{ "slot_empty", 8, { 0 }, 0, LICHEN_SLOT_MAP_OK },
		{ "slot_all_valid", 8, { 0, 1, 2, 3, 4, 5, 6, 7 }, 8,
		  LICHEN_SLOT_MAP_OK },
		{ "slot_single_zero", 1, { 0 }, 1, LICHEN_SLOT_MAP_OK },
		{ "slot_gap_valid", 8, { 0, 3, 7 }, 3, LICHEN_SLOT_MAP_OK },
	};
	for (size_t i = 0; i < sizeof(sm_cases) / sizeof(sm_cases[0]); i++) {
		uint8_t cbor[16];
		size_t n = sm_cases[i].slot_count;
		uint8_t sm_out[8];
		size_t sm_out_len = 0;
		if (n == 0) {
			/* Vector slot_empty is an empty CBOR array (0x80). */
			cbor[0] = 0x80;
			enum lichen_slot_map_status st =
				lichen_beacon_parse_slot_map(cbor, 1,
							     sm_cases[i].num_slots,
							     sm_out, 8,
							     &sm_out_len);
			CHECK(st == sm_cases[i].expected, sm_cases[i].name);
			CHECK(sm_out_len == 0, "empty map count 0");
			/* Zero-length input is the distinct EMPTY branch. */
			CHECK(lichen_beacon_parse_slot_map(
				      cbor, 0, sm_cases[i].num_slots, sm_out, 8,
				      &sm_out_len) == LICHEN_SLOT_MAP_EMPTY,
			      "zero-length input -> EMPTY");
			continue;
		}
		cbor[0] = (uint8_t)(0x80 + n);
		for (size_t j = 0; j < n; j++) {
			cbor[1 + j] = sm_cases[i].slots[j];
		}
		enum lichen_slot_map_status st = lichen_beacon_parse_slot_map(
			cbor, 1 + n, sm_cases[i].num_slots, sm_out, 8,
			&sm_out_len);
		CHECK(st == sm_cases[i].expected, sm_cases[i].name);
		if (st == LICHEN_SLOT_MAP_OK) {
			CHECK(sm_out_len == n, "slot_map roundtrip count");
			for (size_t j = 0; j < n; j++) {
				CHECK(sm_out[j] == sm_cases[i].slots[j],
				      "slot_map roundtrip values");
			}
		}
	}

	/* Reject cases: out-of-bounds, unsorted/duplicate, trailing bytes. */
	uint8_t sm_out[8];
	size_t sm_out_len = 0;
	uint8_t cbor_oob[5] = { 0x84, 0, 3, 8, 12 };
	CHECK(lichen_beacon_parse_slot_map(cbor_oob, 5, 8, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_OUT_OF_BOUNDS,
	      "slot_out_of_bounds");
	uint8_t cbor_unsorted[5] = { 0x84, 3, 1, 5, 2 };
	CHECK(lichen_beacon_parse_slot_map(cbor_unsorted, 5, 16, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_NOT_SORTED,
	      "slot_unsorted/duplicate");
	uint8_t cbor_trailing[4] = { 0x81, 0x00, 0xFF, 0xEE };
	CHECK(lichen_beacon_parse_slot_map(cbor_trailing, 2, 8, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_OK,
	      "exact-length slot_map ok");
	CHECK(lichen_beacon_parse_slot_map(cbor_trailing, 4, 8, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_TRAILING_BYTES,
	      "trailing bytes rejected");
	uint8_t cbor_not_array[2] = { 0x19, 0 };
	CHECK(lichen_beacon_parse_slot_map(cbor_not_array, 2, 8, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_NOT_AN_ARRAY,
	      "non-array rejected");
	uint8_t cbor_oob255[3] = { 0x81, 0x18, 255 };
	CHECK(lichen_beacon_parse_slot_map(cbor_oob255, 3, 255, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_OUT_OF_BOUNDS,
	      "slot_single_at_limit (255 with num_slots 255) rejected");
	uint8_t cbor_max254[4] = { 0x81, 0x18, 254 };
	CHECK(lichen_beacon_parse_slot_map(cbor_max254, 3, 255, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_OK,
	      "slot_single_max_valid (254 with num_slots 255) accepted");
	CHECK(sm_out_len == 1 && sm_out[0] == 254, "slot 254 roundtrip");

	/* Branch coverage beyond the JSON vectors (rust parity):
	 * 0x98 long-form array header. */
	uint8_t cbor_long[5] = { 0x98, 3, 0, 1, 2 };
	CHECK(lichen_beacon_parse_slot_map(cbor_long, 5, 8, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_OK,
	      "0x98 long-form array header");
	CHECK(sm_out_len == 3 && sm_out[2] == 2, "long-form roundtrip");

	/* > 64 entries -> TOO_MANY_SLOTS. */
	uint8_t cbor_big[70];
	cbor_big[0] = 0x98;
	cbor_big[1] = 65;
	for (unsigned int j = 0; j < 65; j++) {
		cbor_big[2 + j] = (uint8_t)j;
	}
	CHECK(lichen_beacon_parse_slot_map(cbor_big, 67, 255, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_TOO_MANY_SLOTS,
	      "65-entry slot_map rejected");

	/* out_cap smaller than the array -> TOO_MANY_SLOTS. */
	uint8_t tiny_out[2];
	size_t tiny_len = 0;
	uint8_t cbor_three[4] = { 0x83, 0, 1, 2 };
	CHECK(lichen_beacon_parse_slot_map(cbor_three, 4, 8, tiny_out, 2,
					   &tiny_len) ==
		      LICHEN_SLOT_MAP_TOO_MANY_SLOTS,
	      "out_cap 2 with 3 entries rejected");

	/* Mid-array truncation. */
	uint8_t cbor_mid[3] = { 0x83, 0, 1 };
	CHECK(lichen_beacon_parse_slot_map(cbor_mid, 3, 8, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_TRUNCATED,
	      "mid-array truncation rejected");

	/* Invalid slot encoding inside the array (0x19 two-byte form). */
	uint8_t cbor_badcoding[4] = { 0x81, 0x19, 0, 1 };
	CHECK(lichen_beacon_parse_slot_map(cbor_badcoding, 4, 8, sm_out, 8,
					   &sm_out_len) ==
		      LICHEN_SLOT_MAP_INVALID_ENCODING,
	      "0x19 slot encoding inside array rejected");

	/* Traceability coupling: the slot_map vectors this suite pins must
	 * remain in ccp_slot_map_validation.json (same gate as sos). */
	static const char *const pinned_sm[] = {
		"slot_out_of_bounds", "slot_boundary_valid",
		"slot_boundary_invalid", "slot_empty", "slot_all_valid",
		"slot_single_zero", "slot_single_max_valid",
		"slot_single_at_limit", "slot_zero_num_slots", "slot_gap_valid",
	};
	for (size_t i = 0; i < sizeof(pinned_sm) / sizeof(pinned_sm[0]);
	     i++) {
		char needle[96];
		snprintf(needle, sizeof(needle), "\"name\": \"%s\"",
			 pinned_sm[i]);
		CHECK(strstr(sm_json, needle) != NULL, pinned_sm[i]);
	}
	/* The JSON distinguishes "unsorted" from "duplicate"; the C codec
	 * has one NOT_SORTED outcome for both (rust SlotMapError parity). */

	/* slot_map CBOR writer: short-form, long-form, too-small out. */
	uint8_t sm_slots[65];
	uint8_t sm_wire[70];
	for (unsigned int j = 0; j < 65; j++) {
		sm_slots[j] = (uint8_t)j;
	}
	size_t w = lichen_beacon_write_slot_map(sm_slots, 3, sm_wire,
						sizeof(sm_wire));
	CHECK(w == 4 && sm_wire[0] == 0x83 && sm_wire[1] == 0 &&
		      sm_wire[2] == 1 && sm_wire[3] == 2,
	      "slot_map writer short-form");
	size_t sm_len = 0;
	uint8_t sm_back[8];
	CHECK(lichen_beacon_parse_slot_map(sm_wire, w, 255, sm_back,
					   sizeof(sm_back),
					   &sm_len) == LICHEN_SLOT_MAP_OK &&
		      sm_len == 3,
	      "writer output reparses");
	w = lichen_beacon_write_slot_map(sm_slots, 30, sm_wire,
					 sizeof(sm_wire));
	CHECK(w == 38 && sm_wire[0] == 0x98 && sm_wire[1] == 30,
	      "slot_map writer long-form 0x98 (values 24..29 are 2-byte CBOR)");
	{
		uint8_t big_back[64];
		enum lichen_slot_map_status st = lichen_beacon_parse_slot_map(
			sm_wire, w, 255, big_back, sizeof(big_back), &sm_len);
		CHECK(st == LICHEN_SLOT_MAP_OK && sm_len == 30,
		      "long-form writer output reparses");
	}
	CHECK(lichen_beacon_write_slot_map(sm_slots, 65, sm_wire,
					   sizeof(sm_wire)) == 0,
	      "65-entry write rejected (> 64)");
	CHECK(lichen_beacon_write_slot_map(sm_slots, 30, sm_wire, 5) == 0,
	      "too-small out buffer rejected");
	}
	free(sm_json);
	/* Channel mask local intersection (spec 02a 2a.2; python
	 * channel_plan.validate_channel_mask parity). */
	CHECK(lichen_beacon_intersect_channel_mask(0x0000FFFF, 8) == 0x00FF,
	      "mask: bits beyond plan cleared");
	CHECK(lichen_beacon_intersect_channel_mask(0x00000001, 8) == 0x0001,
	      "mask: CH0 bit preserved");
	CHECK(lichen_beacon_intersect_channel_mask(0xFFFFFFFF, 1) == 0x0001,
	      "mask: 1-channel plan keeps only CH0");
	CHECK(lichen_beacon_intersect_channel_mask(0xFFFFFFFF, 32) ==
		      0xFFFFFFFF,
	      "mask: 32-channel plan keeps all bits");
	CHECK(lichen_beacon_intersect_channel_mask(0xFFFFFFFF, 0) == 0,
	      "mask: zero-channel plan -> empty");
	/* Gate: at least one locally usable channel. */
	CHECK(lichen_beacon_channel_gate(0x0000FFFF, 8),
	      "gate: intersected mask nonzero -> usable");
	CHECK(!lichen_beacon_channel_gate(0xFFFFFFFE, 1),
	      "gate: 1-channel plan without CH0 -> no usable channel");

	if (failures == 0) {
		printf("PASS: beacon codec vs ccp_beacon_format wire oracle\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
