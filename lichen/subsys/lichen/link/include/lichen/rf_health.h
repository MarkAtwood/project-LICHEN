/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_RF_HEALTH_H_
#define LICHEN_RF_HEALTH_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define LICHEN_RF_EMA_ALPHA_SHIFT 2
#define LICHEN_RF_DENSITY_CRITICAL 20
#define LICHEN_RF_DENSITY_HIGH 10
#define LICHEN_RF_DENSITY_LOW 5
/* CCP-16 2a.10.3 density-estimate thresholds (rust rf_health.rs parity). */
#define LICHEN_RF_DENSITY_PER_BONUS_PERMILLE 100u
#define LICHEN_RF_DENSITY_RSSI_BONUS_DBM (-90)
#define LICHEN_RF_SNR_CRITICAL (-5)
#define LICHEN_RF_SNR_POOR 0
#define LICHEN_RF_SNR_GOOD 8
#define LICHEN_RF_LOAD_HIGH_FP 0xCCCC
#define LICHEN_RF_LOAD_REBALANCE_FP 0x6666

struct lichen_snr_stats {
	int8_t min;
	int8_t max;
	int32_t avg_fp;
	uint32_t count;
};

struct lichen_rf_health {
	uint32_t packets_tx;
	uint32_t packets_rx;
	uint32_t tx_failures;
	struct lichen_snr_stats snr;
	uint8_t density;
	uint32_t load_factor_fp;
};

void lichen_rf_health_init(struct lichen_rf_health *h);
void lichen_rf_health_record_tx(struct lichen_rf_health *h);
void lichen_rf_health_record_rx(struct lichen_rf_health *h, int8_t snr);
void lichen_rf_health_record_tx_fail(struct lichen_rf_health *h);
void lichen_rf_health_record_density(struct lichen_rf_health *h, uint8_t density);
void lichen_rf_health_record_load_factor(struct lichen_rf_health *h, uint32_t load_fp);
uint32_t lichen_rf_health_packet_loss_rate_fp(const struct lichen_rf_health *h);
uint8_t lichen_rf_health_packet_loss_rate_pct(const struct lichen_rf_health *h);
uint16_t lichen_rf_health_packet_loss_permille(const struct lichen_rf_health *h);
int8_t lichen_rf_health_snr_avg(const struct lichen_rf_health *h);
uint8_t lichen_rf_health_adaptive_sf(const struct lichen_rf_health *h);
bool lichen_rf_health_should_rebalance(const struct lichen_rf_health *h);
uint8_t lichen_rf_health_estimate_density(uint8_t neighbor_count,
					  uint16_t loss_permille,
					  int8_t rssi_ema_dbm);

/**
 * TX-time BusyPercent sampler (CCP-15 R-02a-131, MUST): rolling
 * occupancy computed purely from accumulated TX airtime — RSSI is
 * never an input (R-02a-131 explicitly forbids RSSI-derived busy).
 *
 * Usage: lichen_rf_health_busy_init(&b, window_ms); then
 * lichen_rf_health_busy_record_tx(&b, now_ms, airtime_us) per
 * transmission and lichen_rf_health_busy_percent(&b, now_ms) to read
 * the occupancy. Samples older than the window roll off. now_ms MUST
 * be monotonic non-decreasing across record_tx calls (monotonic
 * uptime per spec 18.4.3); the eviction assumes sample_time[0] is the
 * oldest entry.
 */
#define LICHEN_RF_BUSY_MAX_SAMPLES 16u

struct lichen_rf_health_busy {
	uint32_t window_ms;
	/** Ring of (timestamp, airtime) samples inside the window. */
	uint32_t sample_time[LICHEN_RF_BUSY_MAX_SAMPLES];
	uint32_t sample_us[LICHEN_RF_BUSY_MAX_SAMPLES];
	size_t sample_count;
};

void lichen_rf_health_busy_init(struct lichen_rf_health_busy *b,
				uint32_t window_ms);
void lichen_rf_health_busy_record_tx(struct lichen_rf_health_busy *b,
				     uint32_t now_ms, uint32_t airtime_us);
uint8_t lichen_rf_health_busy_percent(const struct lichen_rf_health_busy *b,
				      uint32_t now_ms);

/**
 * CCP-15 interference score (R-02a-137; rust rf_health.rs
 * interference_score_tenths parity): busy_percent*10 + per_mille, in
 * tenths of a percentage point. Returns -1 (via LICHEN_RF_INVALID
 * sentinel 0xFFFF) when inputs are out of range.
 */
uint16_t lichen_rf_health_interference_score_tenths(uint8_t busy_percent,
						    uint16_t packet_error_permille);
void lichen_rf_health_reset(struct lichen_rf_health *h);
#endif /* LICHEN_RF_HEALTH_H_ */

/** Rolling-window TX-time BusyPercent sampler (spec 2a.10.3, R-02a-131).
 *  TX-time based occupancy; MUST NOT use RSSI-derived values.
 *  Window: RF_METRICS_WINDOW_SF superframes of slot_duration_ms each. */
#define LICHEN_BUSY_PERCENT_WINDOW_SF 32
#define LICHEN_BUSY_PERCENT_MAX_ENTRIES 32

struct lichen_busy_percent_sampler {
	/** Per-superframe TX airtime (ms) inside the current window. */
	uint64_t sf[LICHEN_BUSY_PERCENT_MAX_ENTRIES];
	uint32_t airtime_ms[LICHEN_BUSY_PERCENT_MAX_ENTRIES];
	uint64_t current_sf;
	uint8_t count;
};

void lichen_busy_percent_init(struct lichen_busy_percent_sampler *s);
void lichen_busy_percent_record(struct lichen_busy_percent_sampler *s,
				uint64_t superframe, uint32_t airtime_ms);
uint8_t lichen_busy_percent(struct lichen_busy_percent_sampler *s,
			    uint32_t slot_duration_ms);
