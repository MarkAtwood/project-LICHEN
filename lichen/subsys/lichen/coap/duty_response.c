// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

/**
 * @file duty_response.c
 * @brief Duty-cycle congestion 5.03 response builder (spec 07 10.2.3,
 *        R-07-031; bead b7z9.45.b). Mirrors python params.py
 *        congestion_service_unavailable().
 */

#include <lichen/duty_response.h>

#include <string.h>

static const char *congestion_level_str(enum lichen_congestion_level level)
{
	switch (level) {
	case LICHEN_CONGESTION_NORMAL:
		return "normal";
	case LICHEN_CONGESTION_ELEVATED:
		return "elevated";
	case LICHEN_CONGESTION_CRITICAL:
		return "critical";
	case LICHEN_CONGESTION_EXHAUSTED:
	default:
		return "exhausted";
	}
}

enum lichen_congestion_level
lichen_congestion_level_from_usage(uint16_t usage_permille)
{
	if (usage_permille >= 950) {
		return LICHEN_CONGESTION_EXHAUSTED;
	}
	if (usage_permille >= 850) {
		return LICHEN_CONGESTION_CRITICAL;
	}
	if (usage_permille >= 700) {
		return LICHEN_CONGESTION_ELEVATED;
	}
	return LICHEN_CONGESTION_NORMAL;
}

struct cbor_cursor {
	uint8_t *buf;
	size_t cap;
	size_t len;
};

static int cbor_put(struct cbor_cursor *c, uint8_t byte)
{
	if (c->len >= c->cap) {
		return -1;
	}
	c->buf[c->len++] = byte;
	return 0;
}

static int cbor_uint(struct cbor_cursor *c, uint64_t value)
{
	if (value <= 23U) {
		return cbor_put(c, (uint8_t)value);
	}
	if (value <= UINT8_MAX) {
		if (cbor_put(c, 0x18) != 0) {
			return -1;
		}
		return cbor_put(c, (uint8_t)value);
	}
	if (value <= UINT16_MAX) {
		if (cbor_put(c, 0x19) != 0) {
			return -1;
		}
		if (c->cap - c->len < 2U) {
			return -1;
		}
		c->buf[c->len++] = (uint8_t)(value >> 8);
		c->buf[c->len++] = (uint8_t)value;
		return 0;
	}
	if (value <= UINT32_MAX) {
		if (cbor_put(c, 0x1A) != 0) {
			return -1;
		}
		if (c->cap - c->len < 4U) {
			return -1;
		}
		for (int shift = 24; shift >= 0; shift -= 8) {
			if (cbor_put(c, (uint8_t)(value >> shift)) != 0) {
				return -1;
			}
		}
		return 0;
	}
	return -1; /* Out of range for the 64-byte response buffer. */
}

static int cbor_tstr(struct cbor_cursor *c, const char *text)
{
	size_t text_len = strlen(text);

	if (text_len > 23U) {
		return -1;
	}
	if (cbor_put(c, (uint8_t)(0x60U | text_len)) != 0) {
		return -1;
	}
	if (c->cap - c->len < text_len) {
		return -1;
	}
	memcpy(c->buf + c->len, text, text_len);
	c->len += text_len;
	return 0;
}

int lichen_duty_congestion_response(enum lichen_congestion_level level,
				    int64_t retry_after_s,
				    struct lichen_duty_response *out)
{
	if (out == NULL) {
		return -22; /* -EINVAL */
	}

	/* Mirror python congestion_service_unavailable: explicit 0 is a real
	 * value (Max-Age 0 = "immediately stale"); negatives mean "not
	 * provided" and select the 120 s default (the sentinel cannot
	 * collide with a real value — documented in duty_response.h). */
	uint32_t retry_after;
	if (retry_after_s < 0) {
		retry_after = 120U;
	} else if (retry_after_s > (int64_t)UINT32_MAX) {
		retry_after = UINT32_MAX;
	} else {
		retry_after = (uint32_t)retry_after_s;
	}

	memset(out, 0, sizeof(*out));
	out->code = 0xA3; /* 5.03 Service Unavailable */
	out->max_age = retry_after;

	struct cbor_cursor c = { out->payload, sizeof(out->payload), 0 };
	/* {reason: "duty_cycle", retry_after: N, level: "..."} */
	if (cbor_put(&c, 0xA3) != 0 || /* map(3) */
	    cbor_tstr(&c, "reason") != 0 ||
	    cbor_tstr(&c, "duty_cycle") != 0 ||
	    cbor_tstr(&c, "retry_after") != 0 ||
	    cbor_uint(&c, retry_after) != 0 ||
	    cbor_tstr(&c, "level") != 0 ||
	    cbor_tstr(&c, congestion_level_str(level)) != 0) {
		return -1;
	}
	out->payload_len = c.len;
	return 0;
}
