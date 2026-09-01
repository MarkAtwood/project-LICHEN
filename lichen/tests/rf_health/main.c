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
	      "density > 8 rebalances regardless of loss");

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

	if (failures == 0) {
		printf("PASS: rf_health loss threshold\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
