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

	if (failures == 0) {
		printf("PASS: rf_health loss threshold\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
