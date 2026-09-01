/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * Host test consuming test/vectors/sos_rate_limiting.json (spec 12-apps
 * 18.4.3: 10-min cooldown, 3/hr, burst 2; bead l1qw.25 slice 1). The
 * vector history fields pre-populate the rate-limit state, matching the
 * vector's semantics; the oracle is the spec limits table.
 */

#include <lichen/sos_ratelimit.h>

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

static void state_with_history(struct sos_ratelimit_state *state,
			       long long history_count, long long last_ms)
{
	sos_ratelimit_state_init(state);
	/* The implementation stores oldest-to-newest; record in that
	 * order. Entries spread inside the hour ending at last_ms. */
	for (long long i = 0; i < history_count; i++) {
		sos_ratelimit_record(state,
				     last_ms - 1000LL * (history_count - 1 - i));
	}
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1]
				   : "test/vectors/sos_rate_limiting.json";
	char *json = read_file(path);

	if (json == NULL) {
		printf("FAIL: cannot read %s (%s)\n", path, strerror(errno));
		return 1;
	}

	/* Coupling gate: every vector this suite pins must still exist in
	 * the file, so renames/removals fail here instead of silently. */
	static const char *const pinned[] = {
		"first_sos_accepted",
		"burst_second_accepted",
		"third_before_cooldown_rejected",
		"third_after_cooldown_accepted",
		"fourth_in_hour_rejected",
		"hourly_window_slides",
		"different_nodes_independent",
		"cooldown_resets_on_accept",
	};
	for (size_t i = 0; i < sizeof(pinned) / sizeof(pinned[0]); i++) {
		char needle[96];
		snprintf(needle, sizeof(needle), "\"name\": \"%s\"",
			 pinned[i]);
		CHECK(strstr(json, needle) != NULL, pinned[i]);
	}

	struct sos_ratelimit_config config;

	sos_ratelimit_config_init(&config);
	struct sos_ratelimit_state state;
	enum sos_ratelimit_result result;
	uint32_t remaining = 0;

	/* first_sos_accepted: empty history -> ALLOWED. */
	sos_ratelimit_state_init(&state);
	result = sos_ratelimit_check(&state, 1000, &config, &remaining);
	CHECK(result == SOS_RATELIMIT_ALLOWED, "first SOS allowed");
	CHECK(remaining == 0, "no retry-after on first");

	/* burst_second_accepted: one recent alert, burst allows a second. */
	state_with_history(&state, 1, 2000);
	result = sos_ratelimit_check(&state, 2000, &config, &remaining);
	CHECK(result == SOS_RATELIMIT_ALLOWED, "second within burst allowed");

	/* third_before_cooldown_rejected: burst exhausted (2 in window),
	 * third at +300 s hits the 10-minute cooldown (remaining 300 s). */
	state_with_history(&state, 2, 2000);
	result = sos_ratelimit_check(&state, 2000 + 300000, &config,
				     &remaining);
	CHECK(result == SOS_RATELIMIT_COOLDOWN_ACTIVE,
	      "third within cooldown rejected");
	CHECK(remaining == 300000U, "cooldown remaining is 300 s");

	/* third_after_cooldown_accepted: burst-2 state aged past cooldown. */
	state_with_history(&state, 2, 2000);
	result = sos_ratelimit_check(&state, 2000 + 600000, &config,
				     &remaining);
	CHECK(result == SOS_RATELIMIT_ALLOWED,
	      "third after cooldown elapsed allowed");

	/* fourth_in_hour_rejected: 3 alerts already in the hour window. */
	sos_ratelimit_state_init(&state);
	sos_ratelimit_record(&state, 1000);
	sos_ratelimit_record(&state, 2000);
	sos_ratelimit_record(&state, 3000);
	result = sos_ratelimit_check(&state, 4000, &config, &remaining);
	CHECK(result == SOS_RATELIMIT_HOURLY_EXCEEDED,
	      "fourth in hour rejected");
	CHECK(remaining > 0 && remaining <= SOS_RATELIMIT_HOUR_MS,
	      "hourly remaining is bounded by the window");

	/* hourly_window_slides (vector replay): history {0, 1000, 2000},
	 * check at 3601000. Window cutoff is 1000; the inclusive boundary
	 * retains 2 entries (sos_in_window=2) and acceptance comes via the
	 * cooldown-elapsed path. */
	sos_ratelimit_state_init(&state);
	sos_ratelimit_record(&state, 0);
	sos_ratelimit_record(&state, 1000);
	sos_ratelimit_record(&state, 2000);
	result = sos_ratelimit_check(&state, 3601000, &config, &remaining);
	CHECK(result == SOS_RATELIMIT_ALLOWED,
	      "window slide re-allows after an hour");

	/* different_nodes_independent: separate states never interact. */
	struct sos_ratelimit_state node_b;

	sos_ratelimit_state_init(&node_b);
	result = sos_ratelimit_check(&node_b, 4000, &config, &remaining);
	CHECK(result == SOS_RATELIMIT_ALLOWED,
	      "node B unaffected by node A exhaustion");

	/* cooldown_resets_on_accept: the accepted post-cooldown alert is
	 * itself recorded, so the next immediate alert is denied — with
	 * three records now inside the hour window the hourly cap
	 * dominates the cooldown rule (both are spec limits 18.4.3). */
	sos_ratelimit_state_init(&state);
	sos_ratelimit_record(&state, 3600000);
	sos_ratelimit_record(&state, 3601000);
	result = sos_ratelimit_check(&state, 3601000 + 600000, &config,
				     &remaining);
	CHECK(result == SOS_RATELIMIT_ALLOWED, "post-cooldown accept");
	sos_ratelimit_record(&state, 3601000 + 600000);
	result = sos_ratelimit_check(&state, 3601000 + 600000, &config,
				     &remaining);
	CHECK(result == SOS_RATELIMIT_HOURLY_EXCEEDED,
	      "accepted alert counts toward the hourly cap");

	/* NULL guards preserve the defensive-allow contract. */
	CHECK(sos_ratelimit_check(NULL, 0, &config, NULL) ==
		      SOS_RATELIMIT_ALLOWED,
	      "NULL state defensive-allow");
	CHECK(sos_ratelimit_check(&state, 0, NULL, NULL) ==
		      SOS_RATELIMIT_ALLOWED,
	      "NULL config defensive-allow");

	free(json);
	if (failures == 0) {
		printf("PASS: sos_ratelimit vs sos_rate_limiting vectors\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
