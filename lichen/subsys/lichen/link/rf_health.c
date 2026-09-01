/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rf_health.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

#define FP_SCALE (1 << 16)
#define FP_ROUND (1 << 15)

void lichen_rf_health_init(struct lichen_rf_health *h)
{
	h->packets_tx = 0;
	h->packets_rx = 0;
	h->tx_failures = 0;
	h->snr.min = INT8_MAX;
	h->snr.max = INT8_MIN;
	h->snr.avg_fp = 0;
	h->snr.count = 0;
	h->density = 0;
	h->load_factor_fp = 0;
}

void lichen_rf_health_record_tx(struct lichen_rf_health *h)
{
	if (h->packets_tx < UINT32_MAX) {
		h->packets_tx++;
	}
}

void lichen_rf_health_record_rx(struct lichen_rf_health *h, int8_t snr)
{
	if (h->packets_rx < UINT32_MAX) {
		h->packets_rx++;
	}
	if (snr < h->snr.min) h->snr.min = snr;
	if (snr > h->snr.max) h->snr.max = snr;

	/* Multiply, not left-shift: snr is int8_t and LoRa SNR is routinely
	 * negative — left-shifting a negative signed value is C11 UB. */
	int32_t snr_fp = (int32_t)snr * FP_SCALE;
	if (h->snr.count == 0) {
		h->snr.avg_fp = snr_fp;
	} else {
		int32_t diff;
		if (__builtin_ssub_overflow(snr_fp, h->snr.avg_fp, &diff)) {
			diff = (snr_fp >= 0) ? INT32_MAX : INT32_MIN;
		}
		/* Arithmetic right shift of the signed EMA accumulator is
		 * intentional (floor semantics); dividing would change rounding
		 * for negative deltas. gcc/clang document the shift as
		 * arithmetic for signed types. */
		// cppcheck-suppress shiftNegativeLHS
		int32_t delta = diff >> LICHEN_RF_EMA_ALPHA_SHIFT;
		if (__builtin_sadd_overflow(h->snr.avg_fp, delta, &h->snr.avg_fp)) {
			h->snr.avg_fp = (delta > 0) ? INT32_MAX : INT32_MIN;
		}
	}
	if (h->snr.count < UINT32_MAX) {
		h->snr.count++;
	}
}

void lichen_rf_health_record_tx_fail(struct lichen_rf_health *h)
{
	if (h->tx_failures < UINT32_MAX) {
		h->tx_failures++;
	}
}

void lichen_rf_health_record_density(struct lichen_rf_health *h, uint8_t density)
{
	h->density = density;
}

void lichen_rf_health_record_load_factor(struct lichen_rf_health *h, uint32_t load_fp)
{
	h->load_factor_fp = load_fp < FP_SCALE ? load_fp : FP_SCALE;
}

uint32_t lichen_rf_health_packet_loss_rate_fp(const struct lichen_rf_health *h)
{
	if (h->packets_tx == 0) return 0;
	uint64_t numerator = (uint64_t)h->tx_failures * 100 * FP_SCALE;
	return (uint32_t)(numerator / h->packets_tx);
}

uint8_t lichen_rf_health_packet_loss_rate_pct(const struct lichen_rf_health *h)
{
	uint32_t fp = lichen_rf_health_packet_loss_rate_fp(h);
	uint32_t pct = fp >> 16;
	return (uint8_t)(pct > 100 ? 100 : pct);
}

uint16_t lichen_rf_health_packet_loss_permille(const struct lichen_rf_health *h)
{
	uint32_t fp = lichen_rf_health_packet_loss_rate_fp(h);
	uint64_t permille = ((uint64_t)fp * 10) >> 16;
	return (uint16_t)(permille > 1000 ? 1000 : permille);
}

int8_t lichen_rf_health_snr_avg(const struct lichen_rf_health *h)
{
	if (h->snr.count == 0) return 0;
	/* Clamp before rounding: the saturation paths can store INT32_MAX,
	 * and adding FP_ROUND to that would overflow. */
	int32_t avg = h->snr.avg_fp;
	if (avg > INT32_MAX - FP_ROUND) {
		avg = INT32_MAX - FP_ROUND;
	}
	return (int8_t)((avg + FP_ROUND) >> 16);
}

uint8_t lichen_rf_health_adaptive_sf(const struct lichen_rf_health *h)
{
	int8_t snr_ema = lichen_rf_health_snr_avg(h);
	bool load_high = h->load_factor_fp > LICHEN_RF_LOAD_HIGH_FP;

	if (h->density > LICHEN_RF_DENSITY_CRITICAL || snr_ema < LICHEN_RF_SNR_CRITICAL) {
		return 12;
	}
	if (h->density > LICHEN_RF_DENSITY_HIGH || snr_ema < LICHEN_RF_SNR_POOR || load_high) {
		return 11;
	}
	if (h->density < LICHEN_RF_DENSITY_LOW && snr_ema > LICHEN_RF_SNR_GOOD) {
		return 9;
	}
	return 10;
}

bool lichen_rf_health_should_rebalance(const struct lichen_rf_health *h)
{
	/* Spec 02a-coordinated-capacity.md 2a.8 R-02a-112: EMA_Loss > 0.25
	 * (LOSS_HIGH, pinned by ccp16_ema_loss_threshold.json). Compared in
	 * the Q16.16 fixed-point domain (25% = 25 << 16 = 1638400, strictly
	 * greater) so fractional losses in (0.25, 0.26] trigger per the
	 * vector's ema_loss_0.251_minimal_above case; the whole-percent
	 * helper truncates and would miss them.
	 */
	return h->density > LICHEN_RF_DENSITY_HIGH
		|| h->load_factor_fp > LICHEN_RF_LOAD_REBALANCE_FP
		|| lichen_rf_health_packet_loss_rate_fp(h) > (25u << 16);
}

void lichen_rf_health_reset(struct lichen_rf_health *h)
{
	lichen_rf_health_init(h);
}

uint8_t lichen_rf_health_estimate_density(uint8_t neighbor_count,
					  uint16_t loss_permille,
					  int8_t rssi_ema_dbm)
{
	/* CCP-16 2a.10.3 (R-02a-117), rust rf_health.rs parity:
	 * distinct peers heard in the window, adjusted for hidden
	 * congestion and weak links, clamped to [0, 255]. */
	uint16_t density = neighbor_count;

	if (loss_permille > LICHEN_RF_DENSITY_PER_BONUS_PERMILLE) {
		density = (density > UINT16_MAX - 2) ? UINT16_MAX
						     : density + 2;
	}
	if (rssi_ema_dbm < LICHEN_RF_DENSITY_RSSI_BONUS_DBM) {
		density = (density > UINT16_MAX - 1) ? UINT16_MAX
						     : density + 1;
	}
	return density > 255u ? 255u : (uint8_t)density;
}

uint16_t lichen_rf_health_interference_score_tenths(uint8_t busy_percent,
						    uint16_t packet_error_permille)
{
	/* CCP-15 (R-02a-137), rust rf_health.rs parity: busy percent in
	 * tenths + packet error permille; out-of-range fails closed. */
	if (busy_percent > 100u || packet_error_permille > 1000u) {
		return 0xFFFFu;
	}
	return (uint16_t)((uint32_t)busy_percent * 10u + packet_error_permille);
}

/* Merge note: two complementary TX-airtime BusyPercent samplers coexist
 * here (both under spec 2a.10.3 / CCP-15 R-02a-131; RSSI is never an
 * input to either). lichen_busy_percent_* buckets airtime per
 * superframe; lichen_rf_health_busy_* uses a rolling millisecond
 * window. rf_health.h declares and the rf_health test exercises both. */
void lichen_busy_percent_init(struct lichen_busy_percent_sampler *s)
{
	memset(s, 0, sizeof(*s));
}

void lichen_busy_percent_record(struct lichen_busy_percent_sampler *s,
				uint64_t superframe, uint32_t airtime_ms)
{
	if (superframe > s->current_sf) {
		s->current_sf = superframe;
	}
	for (uint8_t i = 0; i < s->count; i++) {
		if (s->sf[i] == superframe) {
			uint64_t sum =
				(uint64_t)s->airtime_ms[i] + airtime_ms;
			s->airtime_ms[i] = sum > UINT32_MAX
						   ? UINT32_MAX
						   : (uint32_t)sum;
			return;
		}
	}
	if (s->count >= LICHEN_BUSY_PERCENT_MAX_ENTRIES) {
		uint8_t oldest = 0;
		for (uint8_t i = 1; i < s->count; i++) {
			if (s->sf[i] < s->sf[oldest]) {
				oldest = i;
			}
		}
		memmove(&s->sf[oldest], &s->sf[oldest + 1],
			(s->count - oldest - 1) * sizeof(s->sf[0]));
		memmove(&s->airtime_ms[oldest], &s->airtime_ms[oldest + 1],
			(s->count - oldest - 1) * sizeof(s->airtime_ms[0]));
		s->count--;
	}
	s->sf[s->count] = superframe;
	s->airtime_ms[s->count] = airtime_ms;
	s->count++;
}

uint8_t lichen_busy_percent(struct lichen_busy_percent_sampler *s,
			    uint32_t slot_duration_ms)
{
	/* Drop entries outside the exclusive window before summing. */
	uint8_t kept = 0;
	uint64_t total_ms = 0;
	for (uint8_t i = 0; i < s->count; i++) {
		if (s->sf[i] + LICHEN_BUSY_PERCENT_WINDOW_SF >
		    s->current_sf) {
			s->sf[kept] = s->sf[i];
			s->airtime_ms[kept] = s->airtime_ms[i];
			total_ms += s->airtime_ms[kept];
			kept++;
		}
	}
	s->count = kept;
	if (slot_duration_ms == 0) {
		return 0;
	}
	uint64_t window_ms =
		(uint64_t)slot_duration_ms * LICHEN_BUSY_PERCENT_WINDOW_SF;
	uint64_t percent = total_ms * 100 / window_ms;
	return percent > 100 ? 100 : (uint8_t)percent;
}

/* ------------------------------------------------------------------ */
/* TX-time BusyPercent sampler (CCP-15 R-02a-131, MUST). Occupancy is  */
/* computed purely from accumulated TX airtime within the rolling      */
/* window — RSSI is never an input.                                    */
/* ------------------------------------------------------------------ */

void lichen_rf_health_busy_init(struct lichen_rf_health_busy *b,
				uint32_t window_ms)
{
	if (b == NULL) {
		return;
	}
	memset(b, 0, sizeof(*b));
	b->window_ms = window_ms;
}

void lichen_rf_health_busy_record_tx(struct lichen_rf_health_busy *b,
				     uint32_t now_ms, uint32_t airtime_us)
{
	if (b == NULL) {
		return;
	}
	if (b->sample_count >= LICHEN_RF_BUSY_MAX_SAMPLES) {
		/* Drop the oldest sample (ring shift; 16 entries max). */
		memmove(&b->sample_time[0], &b->sample_time[1],
			(LICHEN_RF_BUSY_MAX_SAMPLES - 1) *
				sizeof(b->sample_time[0]));
		memmove(&b->sample_us[0], &b->sample_us[1],
			(LICHEN_RF_BUSY_MAX_SAMPLES - 1) *
				sizeof(b->sample_us[0]));
		b->sample_count--;
	}
	b->sample_time[b->sample_count] = now_ms;
	b->sample_us[b->sample_count] = airtime_us;
	b->sample_count++;
}

uint8_t lichen_rf_health_busy_percent(const struct lichen_rf_health_busy *b,
				      uint32_t now_ms)
{
	if (b == NULL || b->window_ms == 0) {
		return 0;
	}
	uint64_t cutoff = (uint64_t)now_ms >= b->window_ms
				  ? (uint64_t)now_ms - b->window_ms
				  : 0;
	uint64_t tx_us = 0;
	for (size_t i = 0; i < b->sample_count; i++) {
		if (b->sample_time[i] >= cutoff) {
			tx_us += b->sample_us[i];
		}
	}
	/* percent = tx_us / (window_ms * 1000) * 100 = tx_us / (window_ms*10) */
	uint64_t denom = (uint64_t)b->window_ms * 10u;
	uint64_t pct = tx_us / denom;
	return pct > 100u ? 100u : (uint8_t)pct;
}
