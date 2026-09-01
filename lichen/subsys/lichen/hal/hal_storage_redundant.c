/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Two-slot redundant-record storage primitive. C port of
 * rust/lichen-hal/src/storage.rs provision_redundant/open_redundant/
 * update_redundant. Keys and record magic are caller-owned. */

#include <lichen/hal_storage_redundant.h>

#include <string.h>

#define REDUNDANT_SLOT_VERSION 1u
#define REDUNDANT_HEADER_LEN 20u
#define REDUNDANT_TRAILER_LEN 4u

/* IEEE CRC32 (poly 0xEDB88320 reflected, init/final 0xFFFFFFFF) — matches
 * the Rust crc32 in lichen-hal storage.rs. */
static uint32_t redundant_crc32(const uint8_t *data, size_t len)
{
	uint32_t crc = UINT32_MAX;

	for (size_t i = 0; i < len; i++) {
		crc ^= (uint32_t)data[i];
		for (int bit = 0; bit < 8; bit++) {
			uint32_t mask = 0U - (crc & 1U);
			crc = (crc >> 1) ^ (0xEDB88320U & mask);
		}
	}
	return ~crc;
}

static void encode_slot(uint8_t *record, const uint8_t magic[4],
			uint64_t generation, const uint8_t *payload,
			size_t payload_len, size_t *encoded_len)
{
	record[0] = magic[0];
	record[1] = magic[1];
	record[2] = magic[2];
	record[3] = magic[3];
	record[4] = REDUNDANT_SLOT_VERSION;
	memset(&record[5], 0, 3);
	for (int i = 0; i < 8; i++) {
		record[8 + i] = (uint8_t)(generation >> (56 - 8 * i));
	}
	uint32_t len_be = (uint32_t)payload_len;
	record[16] = (uint8_t)(len_be >> 24);
	record[17] = (uint8_t)(len_be >> 16);
	record[18] = (uint8_t)(len_be >> 8);
	record[19] = (uint8_t)len_be;
	memcpy(&record[REDUNDANT_HEADER_LEN], payload, payload_len);
	uint32_t checksum = redundant_crc32(record,
					    REDUNDANT_HEADER_LEN + payload_len);
	uint8_t *trailer = &record[REDUNDANT_HEADER_LEN + payload_len];
	trailer[0] = (uint8_t)(checksum >> 24);
	trailer[1] = (uint8_t)(checksum >> 16);
	trailer[2] = (uint8_t)(checksum >> 8);
	trailer[3] = (uint8_t)checksum;
	*encoded_len = REDUNDANT_HEADER_LEN + payload_len + REDUNDANT_TRAILER_LEN;
}

/* Returns true and fills generation/payload_len for a valid slot record;
 * false for short, wrong-magic, wrong-version, zero-generation,
 * length-inconsistent, or checksum-mismatch records. */
static bool parse_slot(const uint8_t *raw, size_t raw_len,
		       const uint8_t magic[4], uint64_t *generation,
		       const uint8_t **payload, size_t *payload_len)
{
	if (raw_len < REDUNDANT_HEADER_LEN + REDUNDANT_TRAILER_LEN) {
		return false;
	}
	if (memcmp(raw, magic, 4) != 0 || raw[4] != REDUNDANT_SLOT_VERSION) {
		return false;
	}
	if (raw[5] != 0 || raw[6] != 0 || raw[7] != 0) {
		return false;
	}
	uint64_t stored_generation = 0;
	for (int i = 0; i < 8; i++) {
		stored_generation = (stored_generation << 8) | raw[8 + i];
	}
	if (stored_generation == 0) {
		return false;
	}
	uint32_t len_be = ((uint32_t)raw[16] << 24) |
			  ((uint32_t)raw[17] << 16) |
			  ((uint32_t)raw[18] << 8) | (uint32_t)raw[19];
	size_t checksum_at = REDUNDANT_HEADER_LEN + len_be;
	if (checksum_at + REDUNDANT_TRAILER_LEN != raw_len) {
		return false;
	}
	uint32_t expected = ((uint32_t)raw[checksum_at] << 24) |
			    ((uint32_t)raw[checksum_at + 1] << 16) |
			    ((uint32_t)raw[checksum_at + 2] << 8) |
			    (uint32_t)raw[checksum_at + 3];
	if (redundant_crc32(raw, checksum_at) != expected) {
		return false;
	}
	*generation = stored_generation;
	*payload = &raw[REDUNDANT_HEADER_LEN];
	*payload_len = len_be;
	return true;
}

enum lichen_hal_redundant_provision_result lichen_hal_redundant_provision(
	void *user, const struct lichen_hal_redundant_ops *ops,
	const char *keys[2], const uint8_t magic[4], const uint8_t *payload,
	size_t payload_len, uint8_t *record, size_t record_cap)
{
	uint8_t probe[1];
	size_t probe_len = 0;

	for (int i = 0; i < 2; i++) {
		int rc = ops->read(user, keys[i], probe, sizeof(probe),
				   &probe_len);
		if (rc == 0) {
			return LICHEN_HAL_REDUNDANT_PROVISION_EXISTS;
		}
		if (rc < 0) {
			return LICHEN_HAL_REDUNDANT_PROVISION_STORAGE;
		}
	}

	if (record_cap < LICHEN_REDUNDANT_SLOT_OVERHEAD + payload_len) {
		return LICHEN_HAL_REDUNDANT_PROVISION_ENCODE;
	}
	size_t encoded_len;
	encode_slot(record, magic, 1, payload, payload_len, &encoded_len);
	if (ops->write(user, keys[0], record, encoded_len) != 0) {
		return LICHEN_HAL_REDUNDANT_PROVISION_STORAGE;
	}
	return LICHEN_HAL_REDUNDANT_PROVISION_OK;
}

enum lichen_hal_redundant_open_result lichen_hal_redundant_open(
	void *user, const struct lichen_hal_redundant_ops *ops,
	const char *keys[2], const uint8_t magic[4], uint8_t *slot_a,
	uint8_t *slot_b, size_t slot_cap, uint8_t *out, size_t out_cap,
	struct lichen_hal_redundant_value *value)
{
	size_t raw_a_len = 0;
	size_t raw_b_len = 0;
	int rc_a = ops->read(user, keys[0], slot_a, slot_cap, &raw_a_len);
	int rc_b = ops->read(user, keys[1], slot_b, slot_cap, &raw_b_len);

	if (rc_a < 0 || rc_b < 0) {
		return LICHEN_HAL_REDUNDANT_OPEN_STORAGE;
	}
	if (rc_a == 0 && raw_a_len > slot_cap) {
		return LICHEN_HAL_REDUNDANT_OPEN_BUFFER_TOO_SMALL;
	}
	if (rc_b == 0 && raw_b_len > slot_cap) {
		return LICHEN_HAL_REDUNDANT_OPEN_BUFFER_TOO_SMALL;
	}

	bool a_present = (rc_a == 0);
	bool b_present = (rc_b == 0);
	if (!a_present && !b_present) {
		return LICHEN_HAL_REDUNDANT_OPEN_MISSING;
	}

	uint64_t gen_a = 0;
	uint64_t gen_b = 0;
	const uint8_t *payload_a = NULL;
	const uint8_t *payload_b = NULL;
	size_t payload_a_len = 0;
	size_t payload_b_len = 0;
	bool a_valid = a_present &&
		       parse_slot(slot_a, raw_a_len, magic, &gen_a, &payload_a,
				  &payload_a_len);
	bool b_valid = b_present &&
		       parse_slot(slot_b, raw_b_len, magic, &gen_b, &payload_b,
				  &payload_b_len);

	const uint8_t *payload = NULL;
	size_t payload_len = 0;
	if (a_valid && b_valid) {
		if (gen_b > gen_a) {
			payload = payload_b;
			payload_len = payload_b_len;
			value->slot = 1;
		} else {
			payload = payload_a;
			payload_len = payload_a_len;
			value->slot = 0;
		}
		value->generation = (payload == payload_b) ? gen_b : gen_a;
	} else if (a_valid) {
		payload = payload_a;
		payload_len = payload_a_len;
		value->generation = gen_a;
		value->slot = 0;
	} else if (b_valid) {
		payload = payload_b;
		payload_len = payload_b_len;
		value->generation = gen_b;
		value->slot = 1;
	} else {
		return LICHEN_HAL_REDUNDANT_OPEN_CORRUPT;
	}

	if (payload_len > out_cap) {
		return LICHEN_HAL_REDUNDANT_OPEN_BUFFER_TOO_SMALL;
	}
	memcpy(out, payload, payload_len);
	value->len = payload_len;
	return LICHEN_HAL_REDUNDANT_OPEN_OK;
}

enum lichen_hal_redundant_update_result lichen_hal_redundant_update(
	void *user, const struct lichen_hal_redundant_ops *ops,
	const char *keys[2], const uint8_t magic[4],
	const struct lichen_hal_redundant_value *current, const uint8_t *payload,
	size_t payload_len, uint8_t *record, size_t record_cap,
	struct lichen_hal_redundant_value *value)
{
	uint8_t slot_buf[2][LICHEN_REDUNDANT_SLOT_OVERHEAD + 255];
	size_t raw_a_len = 0;
	size_t raw_b_len = 0;
	int rc_a = ops->read(user, keys[0], slot_buf[0], sizeof(slot_buf[0]),
			     &raw_a_len);
	int rc_b = ops->read(user, keys[1], slot_buf[1], sizeof(slot_buf[1]),
			     &raw_b_len);

	if (rc_a < 0 || rc_b < 0) {
		return LICHEN_HAL_REDUNDANT_UPDATE_STORAGE;
	}

	bool a_present = (rc_a == 0);
	bool b_present = (rc_b == 0);
	uint64_t gen_a = 0;
	uint64_t gen_b = 0;
	bool a_valid = false;
	bool b_valid = false;
	if (a_present) {
		const uint8_t *unused;
		size_t len;
		a_valid = parse_slot(slot_buf[0], raw_a_len, magic, &gen_a,
				     &unused, &len);
	}
	if (b_present) {
		const uint8_t *unused;
		size_t len;
		b_valid = parse_slot(slot_buf[1], raw_b_len, magic, &gen_b,
				     &unused, &len);
	}

	uint64_t latest_generation;
	unsigned latest_slot;
	if (a_valid && b_valid) {
		if (gen_b > gen_a) {
			latest_generation = gen_b;
			latest_slot = 1;
		} else {
			latest_generation = gen_a;
			latest_slot = 0;
		}
	} else if (a_valid) {
		latest_generation = gen_a;
		latest_slot = 0;
	} else if (b_valid) {
		latest_generation = gen_b;
		latest_slot = 1;
	} else if (!a_present && !b_present) {
		return LICHEN_HAL_REDUNDANT_UPDATE_STALE;
	} else {
		return LICHEN_HAL_REDUNDANT_UPDATE_CORRUPT;
	}

	if (latest_generation != current->generation ||
	    latest_slot != current->slot) {
		return LICHEN_HAL_REDUNDANT_UPDATE_STALE;
	}
	if (current->generation == UINT64_MAX) {
		return LICHEN_HAL_REDUNDANT_UPDATE_EXHAUSTED;
	}

	if (record_cap < LICHEN_REDUNDANT_SLOT_OVERHEAD + payload_len) {
		return LICHEN_HAL_REDUNDANT_UPDATE_ENCODE;
	}
	uint64_t generation = current->generation + 1;
	unsigned slot = 1 - current->slot;
	size_t encoded_len;
	encode_slot(record, magic, generation, payload, payload_len,
		    &encoded_len);
	if (ops->write(user, keys[slot], record, encoded_len) != 0) {
		return LICHEN_HAL_REDUNDANT_UPDATE_STORAGE;
	}
	value->generation = generation;
	value->slot = slot;
	value->len = payload_len;
	return LICHEN_HAL_REDUNDANT_UPDATE_OK;
}
