/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * Host test consuming test/vectors/ccp16.json SF-threshold cases (bead
 * b7z9.30.5): drives lichen_rf_health_adaptive_sf with the vector
 * (density, snr_db, load_factor) inputs and pins the expected SF per the
 * threshold table (spec 02a 2a.8). Oracle: ccp16.json independent
 * derivation, consumed by the python/rust implementations as well.
 */

#include <lichen/rf_health.h>

#include <errno.h>
#include <stdint.h>
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

/* --- minimal JSON vector access (same pattern as tests/desync_fsm) --- */

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

/* Locate the object holding "name": "<name>"; *end receives the closing
 * brace. The name field sits inside the object, so scan backwards to its
 * opening brace. */
static const char *find_case(const char *json, const char *name,
			     const char **end)
{
	char needle[128];

	snprintf(needle, sizeof(needle), "\"name\": \"%s\"", name);
	const char *at = strstr(json, needle);

	if (at == NULL) {
		return NULL;
	}
	const char *brace = at;

	while (brace > json && *brace != '{') {
		brace--;
	}
	if (brace == json) {
		return NULL;
	}
	int depth = 0;

	for (const char *p = brace; *p != '\0'; p++) {
		if (*p == '{') {
			depth++;
		} else if (*p == '}') {
			depth--;
			if (depth == 0) {
				*end = p;
				return brace + 1;
			}
		}
	}
	return NULL;
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

static bool find_double(const char *obj, const char *end, const char *key,
			double *out)
{
	char needle[96];

	snprintf(needle, sizeof(needle), "\"%s\":", key);
	const char *at = strstr(obj, needle);

	if (at == NULL || at >= end) {
		return false;
	}
	*out = strtod(at + strlen(needle), NULL);
	return true;
}

static void run_sf_case(const char *obj, const char *end, const char *name)
{
	long long density = 0;
	long long snr = 0;
	double load = 0.0;
	long long expected_sf = 0;

	if (!find_ll(obj, end, "density", &density) ||
	    !find_ll(obj, end, "snr_db", &snr) ||
	    !find_ll(obj, end, "sf", &expected_sf)) {
		CHECK(false, name);
		return;
	}
	/* load_factor is optional (absent means 0.0). */
	(void)find_double(obj, end, "load_factor", &load);

	struct lichen_rf_health h;

	lichen_rf_health_init(&h);
	lichen_rf_health_record_density(&h, (uint8_t)density);
	h.snr.avg_fp = (int32_t)snr * 65536;
	h.snr.count = 1;
	lichen_rf_health_record_load_factor(
		&h, (uint32_t)(load * 65536.0 + 0.5));

	uint8_t sf = lichen_rf_health_adaptive_sf(&h);

	if (sf != (uint8_t)expected_sf) {
		printf("FAIL: %s: density=%lld snr=%lld load=%.2f -> sf %u, "
		       "expected %lld\n",
		       name, density, snr, load, sf, expected_sf);
		failures++;
	} else {
		printf("ok: %s -> sf %u\n", name, sf);
	}
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1]
				   : "test/vectors/ccp16.json";
	char *json = read_file(path);

	if (json == NULL) {
		printf("FAIL: cannot read %s (%s)\n", path, strerror(errno));
		return 1;
	}
	static const char *const cases[] = {
		"select_channel_sf12_high_density",
		"select_channel_sf12_low_snr",
		"select_channel_sf11_snr_threshold",
		"select_channel_sf11_load_threshold",
		"select_channel_sf9_low_density_high_snr",
		"select_channel_default_sf10",
		"select_channel_sfn_wrap_now",
		"select_channel_timing_test",
		"select_channel_density_high_ch0",
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const char *end;
		const char *obj = find_case(json, cases[i], &end);

		CHECK(obj != NULL, cases[i]);
		if (obj != NULL) {
			run_sf_case(obj, end, cases[i]);
		}
	}
	free(json);

	if (failures == 0) {
		printf("PASS: rf_health adaptive SF vs ccp16 vectors\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
