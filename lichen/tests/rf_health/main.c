/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rf_health.h>

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

static void fill_loss(struct lichen_rf_health *h, uint32_t tx, uint32_t fails)
{
	lichen_rf_health_init(h);
	for (uint32_t i = 0; i < tx; i++) {
		lichen_rf_health_record_tx(h);
	}
	for (uint32_t i = 0; i < fails; i++) {
		lichen_rf_health_record_tx_fail(h);
	}
}

/* --- minimal JSON access for the CCP-15 interference corpus -------- */

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
	size_t n = fread(buf, 1U, (size_t)size, f);

	fclose(f);
	buf[n] = '\0';
	return buf;
}

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

static bool find_long(const char *obj, const char *end, const char *key,
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

static bool find_double(const char *obj, const char *end, const char *key,
			double *out)
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
	*out = strtod(p, NULL);
	return true;
}

/* EMA corpus (ccp_ema_update_integer.json): single-update cases carry
 * {"avg": i, "sample": i} -> {"new_avg_int_round_half_up": i}; sequence
 * cases carry {"initial_avg": i, "samples": [..]} ->
 * {"final_avg_int_round_half_up": i}. Round-half-up int semantics match
 * lichen_rf_health_snr_avg's (avg + FP_ROUND) >> 16. */
static void case_ema_single(const char *obj, const char *end)
{
	long long avg = 0;
	long long sample = 0;
	long long expected = 0;

	CHECK(find_long(obj, end, "avg", &avg) &&
		      find_long(obj, end, "sample", &sample) &&
		      find_long(obj, end, "new_avg_int_round_half_up",
				&expected),
	      "ema_single: vector fields present");

	struct lichen_rf_health h;

	lichen_rf_health_init(&h);
	/* Pre-seed the accumulator with the corpus avg (values are int8
	 * range), then the corpus sample is one EMA step. */
	lichen_rf_health_record_rx(&h, (int8_t)avg);
	lichen_rf_health_record_rx(&h, (int8_t)sample);
	CHECK(lichen_rf_health_snr_avg(&h) == (int8_t)expected,
	      "ema_single: round-half-up result matches the oracle");
	(void)end;
}

static void case_ema_sequence(const char *obj, const char *end)
{
	long long initial = 0;
	long long expected = 0;

	CHECK(find_long(obj, end, "initial_avg", &initial) &&
		      find_long(obj, end, "final_avg_int_round_half_up",
				&expected),
	      "ema_sequence: vector fields present");

	struct lichen_rf_health h;

	lichen_rf_health_init(&h);
	/* Always seed (even 0): count==0 makes record_rx SET the average,
	 * but the corpus semantics EMA-step from initial_avg. */
	lichen_rf_health_record_rx(&h, (int8_t)initial);
	/* Walk the samples array. */
	const char *arr = strstr(obj, "\"samples\"");

	CHECK(arr != NULL && arr < end, "ema_sequence: samples present");
	const char *p = strchr(arr, '[');

	CHECK(p != NULL && p < end, "ema_sequence: samples array open");
	int8_t samples[64];
	size_t count = 0U;

	p++;
	for (; *p != '\0' && *p != ']' && p < end && count < 64U; p++) {
		if (*p == '-' || (*p >= '0' && *p <= '9')) {
			char *stop = NULL;
			long v = strtol(p, &stop, 10);

			samples[count++] = (int8_t)v;
			p = stop - 1;
		}
	}
	for (size_t i = 0; i < count; i++) {
		lichen_rf_health_record_rx(&h, samples[i]);
	}
	CHECK(lichen_rf_health_snr_avg(&h) == (int8_t)expected,
	      "ema_sequence: final round-half-up result matches the oracle");
}

static void case_interference(const char *obj, const char *end)
{
	double busy_pct = 0.0;
	double per = 0.0;
	double expected = 0.0;

	CHECK(find_double(obj, end, "busy_pct", &busy_pct) &&
		      find_double(obj, end, "per", &per) &&
		      find_double(obj, end, "interference_score", &expected),
	      "interference: vector fields present");

	uint8_t busy_percent = (uint8_t)(busy_pct + 0.5);
	uint16_t permille = (uint16_t)(per * 1000.0 + 0.5);
	int16_t tenths = lichen_rf_health_interference_score_tenths(
		busy_percent, permille);
	CHECK(tenths == (int16_t)(expected * 10.0 + 0.5),
	      "interference: score matches the committed oracle");
}

int main(int argc, char **argv)
{
	struct lichen_rf_health h;

	/* Exactly 25% loss must NOT rebalance (spec: EMA_Loss > 0.25). */
	fill_loss(&h, 4, 1);
	CHECK(h.packets_tx == 4, "tx count");
	CHECK(lichen_rf_health_packet_loss_rate_pct(&h) == 25, "loss pct is 25");
	CHECK(!lichen_rf_health_should_rebalance(&h),
	      "25% loss alone does not rebalance");

	/* 26% loss must rebalance. */
	fill_loss(&h, 50, 13);
	CHECK(lichen_rf_health_packet_loss_rate_pct(&h) == 26, "loss pct is 26");
	CHECK(lichen_rf_health_should_rebalance(&h),
	      "26% loss alone rebalances (R-02a-112, LOSS_HIGH 0.25)");

	/* Zero loss, zero density, zero load: no rebalance. */
	lichen_rf_health_init(&h);
	CHECK(!lichen_rf_health_should_rebalance(&h),
	      "clean metrics do not rebalance");

	/* Loss below threshold with density trigger still rebalances. */
	fill_loss(&h, 4, 1);
	lichen_rf_health_record_density(&h, LICHEN_RF_DENSITY_HIGH + 1);
	CHECK(lichen_rf_health_should_rebalance(&h),
	      "density > 10 rebalances regardless of loss");

	/* Fractional loss above 0.25 (25 fails / 99 tx = 0.2525) must
	 * rebalance per ccp16_ema_loss_threshold.json
	 * ema_loss_0.251_minimal_above; a whole-percent compare would miss
	 * it (pct truncates to 25).
	 */
	fill_loss(&h, 99, 25);
	CHECK(lichen_rf_health_packet_loss_rate_pct(&h) == 25, "pct truncates to 25");
	CHECK(lichen_rf_health_should_rebalance(&h),
	      "fractional loss 0.2525 > 0.25 rebalances");

	/* Fractional loss at exactly 0.25 (25 fails / 100 tx) must not. */
	fill_loss(&h, 100, 25);
	CHECK(lichen_rf_health_should_rebalance(&h) == false,
	      "loss exactly 0.25 does not rebalance");

	/* Permille view consistent: 250 permille = 25%. */
	fill_loss(&h, 4, 1);
	CHECK(lichen_rf_health_packet_loss_permille(&h) == 250, "250 permille");

	/* Density estimation (CCP-16 2a.10.3, R-02a-117): vectors from
	 * ccp16_load_balance.json density_estimate cases. */
	CHECK(lichen_rf_health_estimate_density(5, 50, -70) == 5,
	      "density: no modifiers");
	CHECK(lichen_rf_health_estimate_density(5, 150, -70) == 7,
	      "density: high loss +2");
	CHECK(lichen_rf_health_estimate_density(5, 50, -95) == 6,
	      "density: weak RSSI +1");
	CHECK(lichen_rf_health_estimate_density(5, 200, -100) == 8,
	      "density: both bonuses");
	CHECK(lichen_rf_health_estimate_density(5, 100, -70) == 5,
	      "density: loss at boundary (strict >)");
	CHECK(lichen_rf_health_estimate_density(5, 50, -90) == 5,
	      "density: RSSI at boundary (strict <)");
	CHECK(lichen_rf_health_estimate_density(254, 200, -100) == 255,
	      "density: capped at 255");
	CHECK(lichen_rf_health_estimate_density(0, 200, -100) == 3,
	      "density: zero neighbors with bonuses");

	/* CCP-15 corpora (b7z9.29.6/.7). JSON sections are exercised when
	 * the vector paths are supplied (ctest add_test); Zephyr/twister
	 * runs without argv keep the hardcoded checks. */
	if (argc > 2) {
		char *json = read_file(argv[2]);
		CHECK(json != NULL, "ema: corpus readable");
		if (json != NULL) {
			static const char *const SEQ[] = {
				"convergence_sequence_positive",
				"convergence_sequence_negative",
				"alternating_sequence",
			};
			for (size_t i = 0;
			     i < sizeof(SEQ) / sizeof(SEQ[0]); i++) {
				const char *end = NULL;
				const char *obj = find_case(json, SEQ[i],
							    &end);
				CHECK(obj != NULL, "ema: sequence present");
				if (obj != NULL) {
					case_ema_sequence(obj, end);
				}
			}
			static const char *const SINGLE[] = {
				"basic_positive_diff_divisible_by_4",
				"positive_diff_divisible_by_4",
				"negative_diff_divisible_by_4",
				"positive_to_negative_transition",
				"negative_avg_positive_shift",
				"small_diff_not_divisible_by_4",
				"negative_diff_not_divisible_by_4",
				"diff_minus_7_shows_rounding_divergence",
				"boundary_sf12_snr_critical",
				"boundary_sf11_snr_poor",
				"boundary_sf9_snr_good",
				"large_positive_diff",
				"large_negative_diff",
				"i8_boundary_max",
				"i8_boundary_min",
			};
			for (size_t i = 0;
			     i < sizeof(SINGLE) / sizeof(SINGLE[0]); i++) {
				const char *end = NULL;
				const char *obj = find_case(json, SINGLE[i],
							    &end);
				CHECK(obj != NULL, "ema: case present");
				if (obj != NULL) {
					case_ema_single(obj, end);
				}
			}
		}
		free(json);
	}
	if (argc > 1) {
		char *json = read_file(argv[1]);

		CHECK(json != NULL, "interference: corpus readable");
		if (json != NULL) {
			static const char *const NAMES[] = {
				"idle_channel",
				"moderate_busy_low_per",
				"high_busy_high_per",
				"saturated_channel",
				"low_busy_moderate_per",
				"clean_channel_high_per",
			};
			const char *end = NULL;

			for (size_t i = 0; i < sizeof(NAMES) / sizeof(NAMES[0]);
			     i++) {
				const char *obj = find_case(json, NAMES[i],
							    &end);
				CHECK(obj != NULL,
				      "interference: case present");
				if (obj != NULL) {
					case_interference(obj, end);
				}
			}
		}
		free(json);
	}

	if (failures == 0) {
		printf("PASS: rf_health loss threshold\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
