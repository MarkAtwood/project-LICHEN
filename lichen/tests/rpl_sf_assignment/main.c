/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * Host test consuming test/vectors/sf_assignment.json (bead skab.1
 * slice 1): drives the C SF-assignment module (0x14 TLV codec,
 * effective-SF priority) and cross-checks lichen_hash_32 against the
 * vector's independent hash oracle. Rust oracle: lichen-core
 * sf_assignment.rs; spec/02-physical-link.md 3.4.
 */

#include <lichen/rpl_sf_assignment.h>
#include <lichen/link.h>

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

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
	if (strlen(hex) != out_len * 2) {
		return false;
	}
	for (size_t i = 0; i < out_len; i++) {
		unsigned int byte;
		if (sscanf(&hex[i * 2], "%2x", &byte) != 1) {
			return false;
		}
		out[i] = (uint8_t)byte;
	}
	return true;
}

static bool find_ll(const char *obj, const char *end, const char *key,
		    long long *out);

/* Parse one vector object into fields; optional fields skipped. */
static void run_case(const char *obj, const char *end)
{
	char name[64] = { 0 };
	char iid_hex[32] = { 0 };
	char hash_hex[16] = { 0 };
	long long assigned_sf = -1;
	long long assigned_sf_dio = -1;
	long long joined = -1;
	long long effective_sf = -1;
	long long hash_sf = -1;
	uint8_t iid[8];
	uint32_t expected_hash;
	struct lichen_rpl_sf_assignment state;
	uint8_t sf;

	if (sscanf(strstr(obj, "\"name\": \"") + 9, "%63[^\"]", name) != 1 ||
	    sscanf(strstr(obj, "\"iid_hex\": \"") + 12, "%31[^\"]",
		   iid_hex) != 1 ||
	    sscanf(strstr(obj, "\"hash_32\": \"") + 12, "%15[^\"]",
		   hash_hex) != 1) {
		CHECK(false, "case: required fields present");
		return;
	}
	(void)find_ll(obj, end, "assigned_sf", &assigned_sf);
	(void)find_ll(obj, end, "assigned_sf_dio", &assigned_sf_dio);
	(void)find_ll(obj, end, "joined", &joined);
	(void)find_ll(obj, end, "effective_sf", &effective_sf);
	(void)find_ll(obj, end, "hash_sf", &hash_sf);

	CHECK(hex_to_bytes(iid_hex, iid, sizeof(iid)), "case: iid hex");

	/* Independent hash cross-check against the vector's hash_32. */
	expected_hash = (uint32_t)strtoul(&hash_hex[2], NULL, 16);
	CHECK((uint32_t)lichen_hash_32(iid, 8) == expected_hash,
	      "hash_32 matches vector oracle");

	if (assigned_sf >= 0) {
		/* Hash-fallback case: joined, no DIO assignment. */
		lichen_rpl_sf_assignment_init(&state);
		state.joined = true;
		sf = lichen_rpl_sf_effective(&state, iid);
		CHECK(sf == (uint8_t)assigned_sf, name);
	} else if (assigned_sf_dio >= 0) {
		/* Gateway-assigned precedence case. */
		lichen_rpl_sf_assignment_init(&state);
		state.joined = true;
		state.assigned_sf_dio = (uint8_t)assigned_sf_dio;
		sf = lichen_rpl_sf_effective(&state, iid);
		CHECK(effective_sf >= 0 && sf == (uint8_t)effective_sf, name);
		CHECK(hash_sf >= 0, "precedence case pins the hash sf");
	} else if (joined == 0) {
		/* Join fallback: SF10. */
		lichen_rpl_sf_assignment_init(&state);
		CHECK(lichen_rpl_sf_effective(&state, iid) == 10, name);
	}
}

static bool find_ll(const char *obj, const char *end, const char *key,
		    long long *out)
{
	char needle[96];

	snprintf(needle, sizeof(needle), "\"%s\":", key);
	const char *at = strstr(obj, needle);

	if (at == NULL || at >= end) {
		return false;
	}
	*out = strtoll(at + strlen(needle), NULL, 10);
	return true;
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1]
				   : "test/vectors/sf_assignment.json";
	char *json = read_file(path);

	if (json == NULL) {
		printf("FAIL: cannot read %s (%s)\n", path, strerror(errno));
		return 1;
	}

	/* Walk every object in the vectors array. */
	const char *vectors = strstr(json, "\"vectors\":");
	const char *array_end = NULL;

	CHECK(vectors != NULL, "vectors array present");
	if (vectors == NULL) {
		free(json);
		return 1;
	}
	const char *p = strchr(vectors, '[');

	if (p != NULL) {
		int depth = 0;

		for (const char *q = p; *q != '\0'; q++) {
			if (*q == '[') {
				depth++;
			} else if (*q == ']') {
				depth--;
				if (depth == 0) {
					array_end = q;
					break;
				}
			}
		}
	}
	CHECK(array_end != NULL, "vectors array closed");
	if (array_end == NULL) {
		free(json);
		return 1;
	}

	unsigned int cases = 0;
	const char *cursor = strstr(vectors, "\"name\": \"");

	while (cursor != NULL && cursor < array_end) {
		const char *brace = cursor;
		const char *end = NULL;

		while (brace > vectors && *brace != '{') {
			brace--;
		}
		int depth = 0;

		for (const char *q = brace; q < array_end; q++) {
			if (*q == '{') {
				depth++;
			} else if (*q == '}') {
				depth--;
				if (depth == 0) {
					end = q;
					break;
				}
			}
		}
		if (end == NULL) {
			break;
		}
		run_case(brace + 1, end);
		cases++;
		cursor = strstr(end, "\"name\": \"");
	}
	CHECK(cases >= 8, "consumed the expected number of vectors");

	/* TLV codec boundaries (Rust make/parse_assigned_sf_option). */
	uint8_t tlv[3];

	CHECK(!lichen_rpl_sf_assignment_make(6, tlv), "SF6 make rejected");
	CHECK(!lichen_rpl_sf_assignment_make(13, tlv), "SF13 make rejected");
	CHECK(lichen_rpl_sf_assignment_make(9, tlv), "SF9 make accepted");
	CHECK(tlv[0] == 0x14 && tlv[1] == 1 && tlv[2] == 9,
	      "TLV layout [0x14,1,sf]");
	CHECK(lichen_rpl_sf_assignment_parse(tlv, 3) == 9, "TLV parse SF9");
	CHECK(lichen_rpl_sf_assignment_parse(tlv, 2) == 0,
	      "short TLV rejected");
	uint8_t bad_type[3] = { 0x15, 1, 9 };
	uint8_t bad_len[3] = { 0x14, 2, 9 };
	uint8_t bad_sf[3] = { 0x14, 1, 6 };

	CHECK(lichen_rpl_sf_assignment_parse(bad_type, 3) == 0,
	      "wrong type rejected");
	CHECK(lichen_rpl_sf_assignment_parse(bad_len, 3) == 0,
	      "wrong length rejected");
	CHECK(lichen_rpl_sf_assignment_parse(bad_sf, 3) == 0,
	      "invalid SF rejected");
	CHECK(lichen_rpl_sf_assignment_parse(NULL, 3) == 0, "NULL rejected");

	/* Effective-SF precedence: assigned 7..=12 wins; invalid stored
	 * assignment falls through. */
	struct lichen_rpl_sf_assignment s;

	lichen_rpl_sf_assignment_init(&s);
	s.joined = true;
	s.assigned_sf_dio = 9;
	uint8_t iid_any[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	CHECK(lichen_rpl_sf_effective(&s, iid_any) == 9,
	      "assigned SF wins");
	s.assigned_sf_dio = 13;
	CHECK(lichen_rpl_sf_effective(&s, iid_any) == 10,
	      "invalid stored assignment ignored (not joined -> 10)");
	s.assigned_sf_dio = 13;
	s.joined = true;
	{
		uint8_t iid[8] = { 0 };
		uint8_t sf2 = lichen_rpl_sf_effective(&s, iid);

		CHECK(sf2 >= 7 && sf2 <= 12, "invalid assignment -> hash range");
	}
	CHECK(!lichen_rpl_sf_is_valid(6) && !lichen_rpl_sf_is_valid(13) &&
		      lichen_rpl_sf_is_valid(7) && lichen_rpl_sf_is_valid(12),
	      "sf validity bounds");

	free(json);
	if (failures == 0) {
		printf("PASS: rpl_sf_assignment vs sf_assignment vectors\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
