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

	test_busy_percent_sampler();

	if (failures == 0) {
		printf("ALL TESTS PASSED\n");
	}
	return failures != 0;
}
