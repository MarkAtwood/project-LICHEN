/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file backoff.h
 * @brief Sender backoff state after a 5.03 Service Unavailable
 *        (spec 07-transport-app.md 10.2.4, R-07-032: "Senders receiving 5.03
 *        MUST back off for the indicated duration")
 *
 * Freestanding (no kernel dependencies): time is injected by the caller so
 * the state machine is host-testable. The CoAP client owns one instance per
 * peer socket and drives it with k_uptime_get().
 */

#ifndef LICHEN_COAP_BACKOFF_H_
#define LICHEN_COAP_BACKOFF_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief One peer's 5.03 backoff state (monotonic-clock driven).
 */
struct lichen_coap_backoff {
	bool active;    /**< True while a backoff window is armed */
	int64_t until_ms; /**< Monotonic ms timestamp when the window ends */
};

/**
 * @brief Select the backoff duration for one 5.03 response.
 *
 * Precedence mirrors the Rust and Python clients: the duty-cycle CBOR
 * payload's @p retry_after (when present) wins; otherwise the 60 s default
 * (the caller's Max-Age option is not observable in the blockwise callback —
 * documented in coap_client.c). Result is capped at 3600 s (DoS bound on
 * attacker-influenced durations).
 *
 * @param payload      Response payload bytes (may be NULL)
 * @param payload_len  Payload length
 * @param found        Set true when the CBOR payload carried retry_after
 * @return Backoff duration in seconds
 */
uint32_t lichen_coap_backoff_duration_s(const uint8_t *payload,
					size_t payload_len, bool *found);

/** Arm the backoff (active for @p retry_after_s seconds from @p now_ms). */
void lichen_coap_backoff_arm(struct lichen_coap_backoff *backoff,
			     uint32_t retry_after_s, int64_t now_ms);

/** True while the peer is under an unexpired backoff. */
bool lichen_coap_backoff_active(const struct lichen_coap_backoff *backoff,
				int64_t now_ms);

/** Milliseconds remaining under backoff (0 when none). */
int64_t
lichen_coap_backoff_remaining_ms(const struct lichen_coap_backoff *backoff,
				 int64_t now_ms);

/** Clear the backoff (successful exchange with the peer). */
void lichen_coap_backoff_clear(struct lichen_coap_backoff *backoff);

#endif /* LICHEN_COAP_BACKOFF_H_ */
