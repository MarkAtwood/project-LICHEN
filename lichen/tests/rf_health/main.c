/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rf_health.h>
#include <stdio.h>
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

static void test_busy_percent_sampler(void)
{
	struct lichen_busy_percent_sampler s;

	/* Zero: no airtime recorded -> 0% */
	lichen_busy_percent_init(&s);
	CHECK(lichen_busy_percent(&s, 250) == 0, "zero busy");

	/* Partial: 800ms out of 32*250=8000ms window -> ~10% */
	lichen_busy_percent_init(&s);
	lichen_busy_percent_record(&s, 1, 800);
	uint8_t pct = lichen_busy_percent(&s, 250);
	CHECK(pct >= 9 && pct <= 11, "partial busy ~10%");

	/* Saturation clamp: 500ms x 32 superframes -> 200% -> clamped 100% */
	lichen_busy_percent_init(&s);
	for (uint64_t sf = 1; sf <= 32; sf++) {
		lichen_busy_percent_record(&s, sf, 500);
	}
	pct = lichen_busy_percent(&s, 250);
	CHECK(pct == 100, "saturation clamp");

	/* Window slide: old superframes fall out */
	lichen_busy_percent_init(&s);
	for (uint64_t sf = 1; sf <= 32; sf++) {
		lichen_busy_percent_record(&s, sf, 250);
	}
	pct = lichen_busy_percent(&s, 250);
	CHECK(pct == 100, "full window saturates");

	lichen_busy_percent_record(&s, 33, 0);
	pct = lichen_busy_percent(&s, 250);
	CHECK(pct > 95 && pct < 100, "window slides");
}

int main(void)
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
	test_busy_percent_sampler();

	/* Interference score (CCP-15 R-02a-137): ccp-interference.json
	 * vectors. busy_percent*10 + per_mille, tenths domain. */
	struct {
		const char *name;
		uint8_t busy;
		uint16_t per;
		uint16_t score;
	} interference[] = {
		{ "idle_channel", 0, 0, 0 },
		{ "moderate_busy_low_per", 30, 50, 350 },
		{ "high_busy_high_per", 80, 200, 1000 },
		{ "saturated_channel", 95, 500, 1450 },
		{ "low_busy_moderate_per", 10, 150, 250 },
		{ "clean_channel_high_per", 5, 600, 650 },
	};
	for (size_t i = 0; i < sizeof(interference) / sizeof(interference[0]);
	     i++) {
		CHECK(lichen_rf_health_interference_score_tenths(
			      interference[i].busy,
			      interference[i].per) ==
			      interference[i].score,
		      interference[i].name);
	}
	CHECK(lichen_rf_health_interference_score_tenths(100, 1000) == 2000,
	      "interference: in-range boundary (100, 1000) -> 2000");
	CHECK(lichen_rf_health_interference_score_tenths(101, 0) == 0xFFFF,
	      "interference: busy > 100 fails closed");
	CHECK(lichen_rf_health_interference_score_tenths(0, 1001) == 0xFFFF,
	      "interference: per > 1000 fails closed");

	/* TX-time BusyPercent sampler (CCP-15 R-02a-131): occupancy purely
	 * from TX airtime — no RSSI input anywhere. */
	{
		struct lichen_rf_health_busy busy;
		lichen_rf_health_busy_init(&busy, 10000);

		/* Zero transmissions -> 0%. */
		CHECK(lichen_rf_health_busy_percent(&busy, 0) == 0,
		      "busy: empty window 0%");

		/* 1000us TX in a 10000ms window -> 0% (tiny). */
		lichen_rf_health_busy_record_tx(&busy, 0, 1000);
		CHECK(lichen_rf_health_busy_percent(&busy, 1000) == 0,
		      "busy: 1ms of 10s ~ 0%");

		/* Saturate: 100 * 100000us = full window (samples ring at
		 * 16, so use fewer larger samples: 10 x 1_000_000us = 10s
		 * of TX in a 10s window = 100%). */
		for (unsigned int j = 0; j < 10; j++) {
			lichen_rf_health_busy_record_tx(&busy, j * 1000U,
							1000000U);
		}
		CHECK(lichen_rf_health_busy_percent(&busy, 10000) == 100,
		      "busy: saturation clamps to 100%");

		/* Window slide: old samples roll off. */
		struct lichen_rf_health_busy slide;
		lichen_rf_health_busy_init(&slide, 10000);
		lichen_rf_health_busy_record_tx(&slide, 0, 500000);   /* 5% of the 10 s window */
		lichen_rf_health_busy_record_tx(&slide, 20000, 100000); /* 1% */
		/* At now=20000 the window is [10000,20000]: only the 100000us
		 * sample (10%) is inside; the 500000 sample at t=0 is out. */
		CHECK(lichen_rf_health_busy_percent(&slide, 20000) == 1,
		      "busy: window slide rolls old samples off");

		/* Sample-overflow ring: > 16 samples keep the newest. Window
		 * 1000ms; 16 newest samples of 100000us = 1000000us = 100%. */
		struct lichen_rf_health_busy ring;
		lichen_rf_health_busy_init(&ring, 1000);
		for (unsigned int j = 0; j < 20; j++) {
			lichen_rf_health_busy_record_tx(&ring, j * 100U,
							100000U);
		}
		CHECK(lichen_rf_health_busy_percent(&ring, 1900) == 100,
		      "busy: ring keeps newest samples, clamped");

		/* NULL guards. */
		lichen_rf_health_busy_init(NULL, 1000);
		CHECK(lichen_rf_health_busy_percent(NULL, 0) == 0,
		      "busy: NULL sampler 0%");
		lichen_rf_health_busy_record_tx(NULL, 0, 0);
	}

	if (failures == 0) {
		printf("ALL TESTS PASSED\n");
	}
	return failures != 0;
}
