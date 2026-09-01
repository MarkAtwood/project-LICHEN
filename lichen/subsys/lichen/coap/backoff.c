/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file backoff.c
 * @brief Sender backoff state after a 5.03 Service Unavailable
 *        (spec 07-transport-app.md 10.2.4, R-07-032)
 */

#include <lichen/coap_backoff.h>

#include <string.h>

/* Spec 07 10.2.4 defaults, mirroring the Rust and Python clients:
 * DEFAULT_503_BACKOFF_S = 60, MAX_BACKOFF_S = 3600 (DoS cap). */
#define LICHEN_COAP_BACKOFF_DEFAULT_S 60U
#define LICHEN_COAP_BACKOFF_MAX_S 3600U

uint32_t lichen_coap_backoff_duration_s(const uint8_t *payload,
					size_t payload_len, bool *found)
{
	/* The duty-cycle payload is CBOR {reason: "duty_cycle", retry_after:
	 * uint, level: uint}. Hand-scan the CBOR for the retry_after uint:
	 * the map is tiny and fixed-shape, so a full zcbor dependency in this
	 * freestanding module is not warranted. Any parse failure falls back
	 * to the default. */
	*found = false;
	if (payload == NULL || payload_len == 0U || (payload[0] & 0xE0U) != 0xA0U) {
		return LICHEN_COAP_BACKOFF_DEFAULT_S;
	}

	size_t offset = 1U;
	size_t count = (size_t)(payload[0] & 0x1FU);
	if ((payload[0] & 0x1FU) == 0x18U && payload_len > 1U) {
		count = payload[1];
		offset = 2U;
	}

	for (size_t i = 0U; i < count && offset < payload_len; i++) {
		/* Key: expect text string "retry_after" (major 3). */
		if ((payload[offset] & 0xE0U) != 0x60U) {
			return LICHEN_COAP_BACKOFF_DEFAULT_S;
		}
		size_t key_len = (size_t)(payload[offset] & 0x1FU);
		if ((payload[offset] & 0x1FU) >= 0x18U ||
		    offset + 1U + key_len > payload_len) {
			return LICHEN_COAP_BACKOFF_DEFAULT_S;
		}
		bool is_retry_after =
		    key_len == 11U && memcmp(&payload[offset + 1U], "retry_after", 11U) == 0;
		offset += 1U + key_len;
		if (offset >= payload_len) {
			return LICHEN_COAP_BACKOFF_DEFAULT_S;
		}

		/* Value: accept unsigned ints (short and 2-byte extended
		 * forms cover the whole 3600 s cap); skip text/bstr values so
		 * the fixed-shape map's string fields do not abort the scan. */
		uint8_t head = payload[offset];
		uint8_t major = (uint8_t)(head & 0xE0U);
		uint8_t info = (uint8_t)(head & 0x1FU);
		offset += 1U;
		if (major == 0x00U) {
			uint32_t value = (uint32_t)info;
			if (info == 0x18U) {
				if (offset >= payload_len) {
					return LICHEN_COAP_BACKOFF_DEFAULT_S;
				}
				value = payload[offset];
				offset += 1U;
			} else if (info == 0x19U) {
				if (offset + 2U > payload_len) {
					return LICHEN_COAP_BACKOFF_DEFAULT_S;
				}
				value = ((uint32_t)payload[offset] << 8) |
					payload[offset + 1U];
				offset += 2U;
			} else if (info >= 0x1AU) {
				return LICHEN_COAP_BACKOFF_DEFAULT_S;
			}
			if (is_retry_after) {
				*found = true;
				return value > LICHEN_COAP_BACKOFF_MAX_S
				       ? LICHEN_COAP_BACKOFF_MAX_S
				       : value;
			}
		} else if (major == 0x40U || major == 0x60U) {
			if (info >= 0x18U || offset + info > payload_len) {
				return LICHEN_COAP_BACKOFF_DEFAULT_S;
			}
			offset += info;
		} else {
			return LICHEN_COAP_BACKOFF_DEFAULT_S;
		}
	}
	return LICHEN_COAP_BACKOFF_DEFAULT_S;
}

void lichen_coap_backoff_arm(struct lichen_coap_backoff *backoff,
			     uint32_t retry_after_s, int64_t now_ms)
{
	if (backoff == NULL) {
		return;
	}
	if (retry_after_s > LICHEN_COAP_BACKOFF_MAX_S) {
		retry_after_s = LICHEN_COAP_BACKOFF_MAX_S;
	}
	backoff->active = retry_after_s != 0U;
	backoff->until_ms = now_ms + (int64_t)retry_after_s * 1000;
}

bool lichen_coap_backoff_active(const struct lichen_coap_backoff *backoff,
				int64_t now_ms)
{
	if (backoff == NULL || !backoff->active) {
		return false;
	}
	if (now_ms >= backoff->until_ms) {
		return false;
	}
	return true;
}

int64_t lichen_coap_backoff_remaining_ms(
	const struct lichen_coap_backoff *backoff, int64_t now_ms)
{
	if (!lichen_coap_backoff_active(backoff, now_ms)) {
		return 0;
	}
	return backoff->until_ms - now_ms;
}

void lichen_coap_backoff_clear(struct lichen_coap_backoff *backoff)
{
	if (backoff != NULL) {
		backoff->active = false;
	}
}
