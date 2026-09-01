/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * Host test consuming test/vectors/ccp16-desync.json (bead b7z9.12.3):
 * drives the C desync FSM (lichen_desync_on_sfn_wrap / on_beacon), the CCP
 * FSM version-change path, and the drift guard against the vector file.
 * on_missed_superframe is exercised by tests/tdma_guard_budget.
 * Oracles: python timing.sfn DesyncFSM and rust desync.rs DesyncFSM
 * (spec/09 14.7).
 */

#include <lichen/link.h>

#include <ctype.h>
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

/* tdma.c also contains slot selection; this test does not depend on a
 * particular hash result, but the translation unit requires the symbol. */
uint32_t lichen_hash_32(const uint8_t *data, size_t len)
{
	(void)data;
	(void)len;
	return 0U;
}

/* --- minimal JSON vector access ------------------------------------- */

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

/* Locate the object holding "name": "<name>" and return a pointer just
 * past the opening brace; *end receives the matching closing brace. */
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

	/* The name field sits inside the case object; walk back to its
	 * opening brace, then match braces forward. */
	while (brace > json && *brace != '{') {
		brace--;
	}
	if (brace == json) {
		return NULL;
	}
	int depth = 0;
	const char *p = brace;

	for (; *p != '\0'; p++) {
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

static bool find_int(const char *obj, const char *end, const char *key,
		     long long *out)
{
	char needle[96];

	snprintf(needle, sizeof(needle), "\"%s\":", key);
	const char *at = strstr(obj, needle);

	if (at == NULL || at >= end) {
		return false;
	}
	const char *p = at + strlen(needle);

	while (*p == ' ') {
		p++;
	}
	*out = strtoll(p, NULL, 10);
	return true;
}

static bool find_expected(const char *obj, const char *end, char *out,
			  size_t cap)
{
	const char *at = strstr(obj, "\"expected\": \"");
	const char *quote;

	if (at == NULL || at >= end) {
		return false;
	}
	at += strlen("\"expected\": \"");
	quote = strchr(at, '"');
	if (quote == NULL || (size_t)(quote - at) >= cap) {
		return false;
	}
	memcpy(out, at, (size_t)(quote - at));
	out[quote - at] = '\0';
	return true;
}

/* --- vector cases ---------------------------------------------------- */

static void case_sfn_wrap(const char *obj, const char *end)
{
	long long current = 0;
	long long last = 0;
	char expected[32];

	CHECK(find_int(obj, end, "current_sfn", &current) &&
		      find_int(obj, end, "last_sfn", &last),
	      "sfn_wrap: vector fields present");
	CHECK(find_expected(obj, end, expected, sizeof(expected)) &&
		      strcmp(expected, "desync_recovery") == 0,
	      "sfn_wrap: expected field");
	(void)current;
	(void)last;
	CHECK(last == 65535 && current == 0,
	      "sfn_wrap: wrap arithmetic (0 - 65535) underflow is the trigger");

	/* C oracle: a SYNCED node whose time provider is invalid at the
	 * wrap drops to DESYNCED and must re-recover (spec/09 14.7). */
	struct lichen_tdma_ctx tdma;
	struct lichen_link_ctx link_ctx;

	memset(&link_ctx, 0, sizeof(link_ctx));
	CHECK(lichen_tdma_init(&tdma, &link_ctx) == 0, "sfn_wrap: tdma init");
	lichen_desync_on_beacon(&tdma, true);
	lichen_desync_on_beacon(&tdma, true);
	lichen_desync_on_beacon(&tdma, true);
	CHECK(lichen_desync_on_sfn_wrap(&tdma, false) ==
		      LICHEN_DESYNC_DESYNCED,
	      "sfn_wrap: wrap with invalid provider -> DESYNCED");

	/* ...and the first valid beacon afterwards re-enters RECOVERING;
	 * bounded recovery timeout drops back to DESYNCED after 3 missed
	 * superframes (14.7, LICHEN_TDMA_BEACON_TIMEOUT_SUPERFRAMES). */
	CHECK(lichen_desync_on_beacon(&tdma, true) ==
		      LICHEN_DESYNC_RECOVERING,
	      "sfn_wrap: recovery begins after wrap desync");
	lichen_desync_on_missed_superframe(&tdma);
	lichen_desync_on_missed_superframe(&tdma);
	CHECK(lichen_desync_on_missed_superframe(&tdma) ==
		      LICHEN_DESYNC_DESYNCED,
	      "sfn_wrap: 3 missed superframes end recovery");
}

static void case_multi_root_version_conflict(const char *obj, const char *end)
{
	long long version = 0;
	long long alternate = 0;
	char expected[32];

	CHECK(find_int(obj, end, "version", &version) &&
		      find_int(obj, end, "alternate_version", &alternate),
	      "multi_root: vector fields present");
	CHECK(find_expected(obj, end, expected, sizeof(expected)) &&
		      strcmp(expected, "desync") == 0,
	      "multi_root: expected field");
	CHECK(version != alternate, "multi_root: versions actually conflict");

	/* C oracle: an RPL version change on a SYNCED node forces DRIFTING
	 * with SFN reset (spec 2a.5.4, R-02a-045). */
	struct lichen_tdma_ctx tdma;
	struct lichen_link_ctx link_ctx;

	memset(&link_ctx, 0, sizeof(link_ctx));
	CHECK(lichen_tdma_init(&tdma, &link_ctx) == 0,
	      "multi_root: tdma init");
	CHECK(lichen_ccp_fsm_event(&tdma, LICHEN_CCP_EVENT_INIT, 0) == 0,
	      "multi_root: INIT");
	CHECK(lichen_ccp_fsm_event(&tdma, LICHEN_CCP_EVENT_VALID_BEACON,
				   0) == 0,
	      "multi_root: VALID_BEACON");
	CHECK(tdma.ccp_state == LICHEN_CCP_SYNCED, "multi_root: SYNCED");
	CHECK(lichen_link_set_slot(&link_ctx, &tdma, 2, 8, 777) == 0,
	      "multi_root: non-zero SFN installed");
	CHECK(lichen_ccp_fsm_event(&tdma, LICHEN_CCP_EVENT_RPL_VERSION,
				   0) == 0,
	      "multi_root: version event");
	CHECK(tdma.ccp_state == LICHEN_CCP_DRIFTING && !tdma.synced,
	      "multi_root: version conflict -> desync (DRIFTING, unsynced)");
	CHECK(tdma.superframe == 0U, "multi_root: SFN reset per 2a.5.4");
}

static void case_clock_drift(const char *obj, const char *end)
{
	long long drift = 0;
	long long guard = 0;
	long long superframe_ms = 0;
	char expected[32];

	CHECK(find_int(obj, end, "drift_ppm", &drift) &&
		      find_int(obj, end, "guard_ppm", &guard) &&
		      find_int(obj, end, "superframe_ms", &superframe_ms),
	      "drift: vector fields present");
	CHECK(find_expected(obj, end, expected, sizeof(expected)) &&
		      strcmp(expected, "enter_desync_recovery") == 0,
	      "drift: expected field");

	/* C oracle: |measured drift| > guard => holdover expired. */
	CHECK(lichen_drift_holdover_expired(drift, (uint32_t)guard),
	      "drift: 12000 ppm > 5000 ppm guard -> enter recovery");
	/* Boundary: at or under guard the node holds over. */
	CHECK(!lichen_drift_holdover_expired(guard, (uint32_t)guard),
	      "drift: exactly-guard drift holds over");
	CHECK(!lichen_drift_holdover_expired(-((long long)guard),
					     (uint32_t)guard),
	      "drift: magnitude comparison (negative within guard)");
}

static void case_recovery_revalidate(const char *obj, const char *end)
{
	long long sfn = 0;
	char expected[32];

	CHECK(find_int(obj, end, "sfn", &sfn), "recovery: vector fields");
	CHECK(find_expected(obj, end, expected, sizeof(expected)) &&
		      strcmp(expected, "recovering") == 0,
	      "recovery: expected field");

	/* C oracle: after desync, first valid beacon -> RECOVERING; 3
	 * consecutive valid beacons required for SYNCED (14.7). */
	struct lichen_tdma_ctx tdma;
	struct lichen_link_ctx link_ctx;

	memset(&link_ctx, 0, sizeof(link_ctx));
	CHECK(lichen_tdma_init(&tdma, &link_ctx) == 0, "recovery: tdma init");
	/* Establish the post-desync state: SYNCED node loses its time
	 * provider at a wrap -> DESYNCED (the vector's "after desync"). */
	CHECK(lichen_desync_on_sfn_wrap(&tdma, false) ==
		      LICHEN_DESYNC_DESYNCED,
	      "recovery: desynced before revalidation");
	CHECK(lichen_desync_on_beacon(&tdma, true) ==
		      LICHEN_DESYNC_RECOVERING,
	      "recovery: first valid beacon re-enters RECOVERING");
	CHECK(tdma.desync_consecutive_valid == 1U,
	      "recovery: consecutive counter restarted");
	(void)sfn;
}

int main(int argc, char **argv)
{
	const char *path = argc > 1
				   ? argv[1]
				   : "test/vectors/ccp16-desync.json";
	char *json = read_file(path);

	if (json == NULL) {
		printf("SKIP: cannot read %s (%s)\n", path, strerror(errno));
		return 77;
	}
	const char *obj;
	const char *end;

	obj = find_case(json, "desync_on_sfn_wrap", &end);
	CHECK(obj != NULL, "vector desync_on_sfn_wrap found");
	if (obj != NULL) {
		case_sfn_wrap(obj, end);
	}
	obj = find_case(json, "multi_root_version_conflict_desync", &end);
	CHECK(obj != NULL, "vector multi_root_version_conflict_desync found");
	if (obj != NULL) {
		case_multi_root_version_conflict(obj, end);
	}
	obj = find_case(json, "excessive_clock_drift_desync", &end);
	CHECK(obj != NULL, "vector excessive_clock_drift_desync found");
	if (obj != NULL) {
		case_clock_drift(obj, end);
	}
	obj = find_case(json, "desync_recovery_beacon_revalidate", &end);
	CHECK(obj != NULL, "vector desync_recovery_beacon_revalidate found");
	if (obj != NULL) {
		case_recovery_revalidate(obj, end);
	}
	free(json);

	if (failures == 0) {
		printf("PASS: desync_fsm ccp16-desync vectors\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
