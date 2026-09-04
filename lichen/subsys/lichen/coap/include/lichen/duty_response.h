// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

/**
 * @file duty_response.h
 * @brief Duty-cycle congestion 5.03 load-shedding response builder
 *        (spec 07 10.2.3, R-07-031; bead b7z9.45.b).
 *
 * Mirrors python/src/lichen/coap/params.py congestion_service_unavailable():
 * a 5.03 Service Unavailable carrying Max-Age + CBOR
 * {reason: "duty_cycle", retry_after: N, level: "<level>"}.
 */

#ifndef LICHEN_COAP_DUTY_RESPONSE_H_
#define LICHEN_COAP_DUTY_RESPONSE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Duty-cycle congestion levels (spec §10.2.3; mirrors python
 * CongestionLevel). */
enum lichen_congestion_level {
	LICHEN_CONGESTION_NORMAL = 0,
	LICHEN_CONGESTION_ELEVATED = 1,
	LICHEN_CONGESTION_CRITICAL = 2,
	LICHEN_CONGESTION_EXHAUSTED = 3,
};

/** Assembled 5.03 response. The caller delivers it through the OSCORE
 * response path (coap_oscore_respond_resource) with the CBOR content
 * format and the Max-Age option set to retry_after_s. */
struct lichen_duty_response {
	uint8_t code;              /**< 0xA3 (5.03 Service Unavailable). */
	uint8_t payload[64];       /**< CBOR {reason, retry_after, level}. */
	size_t payload_len;        /**< Encoded payload length. */
	uint32_t max_age;          /**< Max-Age option value == retry_after. */
};

/** Map a duty-cycle usage permille (0..1000+) to a congestion level
 * (thresholds per spec 07 10.2.3: <700 normal, <850 elevated,
 * <950 critical, else exhausted). */
enum lichen_congestion_level
lichen_congestion_level_from_usage(uint16_t usage_permille);

/** Build the congestion 5.03 response (mirrors python
 * congestion_service_unavailable): payload CBOR {reason: "duty_cycle",
 * retry_after: N, level: "..."} with retry_after defaulting to 120 s and
 * negative values clamped to 0. Returns 0 on success, -EINVAL on invalid
 * arguments. */
int lichen_duty_congestion_response(enum lichen_congestion_level level,
				    int64_t retry_after_s,
				    struct lichen_duty_response *out);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_DUTY_RESPONSE_H_ */
