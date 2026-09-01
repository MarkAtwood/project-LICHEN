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

	free(json);
	if (failures == 0) {
		printf("PASS: beacon codec vs ccp_beacon_format wire oracle\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
