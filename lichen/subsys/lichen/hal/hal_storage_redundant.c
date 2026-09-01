/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Two-slot redundant-record storage primitive. C port of
 * rust/lichen-hal/src/storage.rs provision_redundant/open_redundant/
 * update_redundant. Keys and record magic are caller-owned.
 *
 * Merge note (main x beads-worker-2): two API surfaces over the same
 * wire format live in this file. lichen_hal_storage_* (public codec +
 * storage layer, consumed by rpl_dao_tx_persist) came from main;
 * lichen_hal_redundant_* (compact wrapper with private codec) came from
 * beads-worker-2. The merged test suite exercises both, so both are
 * kept; each retains its original implementation verbatim. */

#include <lichen/hal_storage_redundant.h>

#include <errno.h>
#include <string.h>

/* Reflected CRC-32 (poly 0xEDB88320), bit-exact with the Rust crc32 in
 * lichen-hal storage.rs: init 0xFFFFFFFF, 8 unrolled reflect-in steps,
 * final complement. Matches zlib/PNG CRC-32.
 */
uint32_t lichen_hal_storage_crc32(const uint8_t *data, size_t len)
{
	uint32_t crc = UINT32_MAX;

	for (size_t i = 0; i < len; i++) {
		crc ^= (uint32_t)data[i];
		for (unsigned int bit = 0; bit < 8; bit++) {
			uint32_t mask = 0u - (crc & 1u);

			crc = (crc >> 1) ^ (0xEDB88320u & mask);
		}
	}
	return ~crc;
}

size_t lichen_hal_storage_encode_slot(const uint8_t magic[4], uint64_t generation,
				      const uint8_t *payload, size_t payload_len,
				      uint8_t *out, size_t out_len)
{
	if (out == NULL || magic == NULL || payload == NULL ||
	    out_len < LICHEN_STORAGE_SLOT_HEADER_LEN +
			      LICHEN_STORAGE_SLOT_TRAILER_LEN ||
	    payload_len > UINT32_MAX - LICHEN_STORAGE_SLOT_HEADER_LEN -
				      LICHEN_STORAGE_SLOT_TRAILER_LEN) {
		return 0;
	}
	size_t len = LICHEN_STORAGE_SLOT_HEADER_LEN + payload_len +
		     LICHEN_STORAGE_SLOT_TRAILER_LEN;

	if (generation == 0 || out_len < len) {
		return 0;
	}
	memcpy(&out[0], magic, 4);
	out[4] = LICHEN_STORAGE_SLOT_VERSION;
	memset(&out[5], 0, 3);
	for (unsigned int i = 0; i < 8; i++) {
		out[8 + i] = (uint8_t)(generation >> (8 * (7 - i)));
	}
	uint32_t payload_len32 = (uint32_t)payload_len;

	for (unsigned int i = 0; i < 4; i++) {
		out[16 + i] = (uint8_t)(payload_len32 >> (8 * (3 - i)));
	}
	memcpy(&out[LICHEN_STORAGE_SLOT_HEADER_LEN], payload, payload_len);
	size_t checksum_at = LICHEN_STORAGE_SLOT_HEADER_LEN + payload_len;
	uint32_t checksum = lichen_hal_storage_crc32(out, checksum_at);

	for (unsigned int i = 0; i < 4; i++) {
		out[checksum_at + i] = (uint8_t)(checksum >> (8 * (3 - i)));
	}
	return len;
}

bool lichen_hal_storage_parse_slot(const uint8_t *raw, size_t raw_len,
				   const uint8_t magic[4], uint64_t *generation,
				   const uint8_t **payload, size_t *payload_len)
{
	size_t min_len = LICHEN_STORAGE_SLOT_HEADER_LEN +
			 LICHEN_STORAGE_SLOT_TRAILER_LEN;

	if (raw == NULL || magic == NULL || generation == NULL ||
	    payload == NULL || payload_len == NULL || raw_len < min_len ||
	    memcmp(&raw[0], magic, 4) != 0 ||
	    raw[4] != LICHEN_STORAGE_SLOT_VERSION ||
	    memcmp(&raw[5], "\0\0\0", 3) != 0) {
		return false;
	}
	uint64_t gen = 0;

	for (unsigned int i = 8; i < 16; i++) {
		gen = (gen << 8) | raw[i];
	}
	if (gen == 0) {
		return false;
	}
	uint32_t plen32 = 0;

	for (unsigned int i = 16; i < 20; i++) {
		plen32 = (plen32 << 8) | raw[i];
	}
	if (plen32 > raw_len - min_len) {
		return false;
	}
	size_t plen = plen32;
	size_t checksum_at = LICHEN_STORAGE_SLOT_HEADER_LEN + plen;

	if (checksum_at + LICHEN_STORAGE_SLOT_TRAILER_LEN != raw_len) {
		return false;
	}
	uint32_t expected = 0;

	for (unsigned int i = 0; i < 4; i++) {
		expected = (expected << 8) | raw[checksum_at + i];
	}
	if (lichen_hal_storage_crc32(raw, checksum_at) != expected) {
		return false;
	}
	*generation = gen;
	*payload = &raw[LICHEN_STORAGE_SLOT_HEADER_LEN];
	*payload_len = plen;
	return true;
}

/* ------------------------------------------------------------------ */
/* Two-slot redundant storage layer (port of rust storage.rs           */
/* provision_redundant / open_redundant / update_redundant).           */
/* ------------------------------------------------------------------ */

/* ops->read wrapper: 0 = found, 1 = missing, other <0 = storage error. */
static int read_one(const struct lichen_hal_storage_ops *ops, void *user,
		    const char *key, uint8_t *buf, size_t buf_len,
		    size_t *length)
{
	int ret = ops->read(user, key, buf, buf_len, length);

	if (ret == 1) {
		return 1;
	}
	if (ret == 0 && *length > buf_len) {
		return -EOVERFLOW;
	}
	return ret;
}

enum lichen_hal_storage_provision_status lichen_hal_storage_provision_redundant(
	const struct lichen_hal_storage_ops *ops, void *user,
	const char *const keys[2], const uint8_t magic[4],
	const uint8_t *payload, size_t payload_len, uint8_t *record,
	size_t record_len)
{
	uint8_t present_probe[1];
	size_t present_len = 0;
	int ret;

	if (ops == NULL || ops->read == NULL || ops->write == NULL ||
	    keys == NULL || keys[0] == NULL || keys[1] == NULL ||
	    magic == NULL || payload == NULL || record == NULL) {
		return LICHEN_STORAGE_PROVISION_STORAGE_ERROR;
	}
	ret = ops->read(user, keys[0], present_probe, sizeof(present_probe),
			&present_len);
	if (ret < 0) {
		return LICHEN_STORAGE_PROVISION_STORAGE_ERROR;
	}
	if (ret == 0) {
		return LICHEN_STORAGE_PROVISION_EXISTS;
	}
	ret = ops->read(user, keys[1], present_probe, sizeof(present_probe),
			&present_len);
	if (ret < 0) {
		return LICHEN_STORAGE_PROVISION_STORAGE_ERROR;
	}
	if (ret == 0) {
		return LICHEN_STORAGE_PROVISION_EXISTS;
	}
	size_t len = lichen_hal_storage_encode_slot(magic, 1, payload,
						    payload_len, record,
						    record_len);
	if (len == 0) {
		return LICHEN_STORAGE_PROVISION_STORAGE_ERROR;
	}
	if (ops->write(user, keys[0], record, len) != 0) {
		return LICHEN_STORAGE_PROVISION_STORAGE_ERROR;
	}
	return LICHEN_STORAGE_PROVISION_OK;
}

enum lichen_hal_storage_open_status lichen_hal_storage_open_redundant(
	const struct lichen_hal_storage_ops *ops, void *user,
	const char *const keys[2], const uint8_t magic[4], uint8_t *slot_a,
	size_t slot_a_len, uint8_t *slot_b, size_t slot_b_len, uint8_t *out,
	size_t *out_len, struct lichen_hal_storage_value *value)
{
	size_t len_a = 0;
	size_t len_b = 0;
	int ret_a;
	int ret_b;
	bool present_a;
	bool present_b;
	uint64_t gen_a = 0;
	uint64_t gen_b = 0;
	const uint8_t *payload_a = NULL;
	const uint8_t *payload_b = NULL;
	size_t payload_a_len = 0;
	size_t payload_b_len = 0;
	bool valid_a;
	bool valid_b;
	uint64_t generation;
	const uint8_t *payload;
	size_t payload_len;
	enum lichen_hal_storage_slot slot;

	if (ops == NULL || ops->read == NULL || keys == NULL ||
	    keys[0] == NULL || keys[1] == NULL || magic == NULL ||
	    slot_a == NULL || slot_b == NULL || out == NULL ||
	    out_len == NULL || value == NULL) {
		return LICHEN_STORAGE_OPEN_STORAGE_ERROR;
	}
	ret_a = read_one(ops, user, keys[0], slot_a, slot_a_len, &len_a);
	ret_b = read_one(ops, user, keys[1], slot_b, slot_b_len, &len_b);
	if (ret_a == -EOVERFLOW || ret_b == -EOVERFLOW) {
		return LICHEN_STORAGE_OPEN_BUFFER_TOO_SMALL;
	}
	if (ret_a < 0 || ret_b < 0) {
		return LICHEN_STORAGE_OPEN_STORAGE_ERROR;
	}
	present_a = ret_a == 0;
	present_b = ret_b == 0;
	if (!present_a && !present_b) {
		return LICHEN_STORAGE_OPEN_MISSING;
	}
	valid_a = present_a && lichen_hal_storage_parse_slot(
					 slot_a, len_a, magic, &gen_a,
					 &payload_a, &payload_a_len);
	valid_b = present_b && lichen_hal_storage_parse_slot(
					 slot_b, len_b, magic, &gen_b,
					 &payload_b, &payload_b_len);
	if (valid_a && valid_b && gen_b > gen_a) {
		generation = gen_b;
		slot = LICHEN_STORAGE_SLOT_B;
		payload = payload_b;
		payload_len = payload_b_len;
	} else if (valid_a) {
		generation = gen_a;
		slot = LICHEN_STORAGE_SLOT_A;
		payload = payload_a;
		payload_len = payload_a_len;
	} else if (valid_b) {
		generation = gen_b;
		slot = LICHEN_STORAGE_SLOT_B;
		payload = payload_b;
		payload_len = payload_b_len;
	} else {
		return LICHEN_STORAGE_OPEN_CORRUPT;
	}
	if (payload_len > *out_len) {
		return LICHEN_STORAGE_OPEN_BUFFER_TOO_SMALL;
	}
	memcpy(out, payload, payload_len);
	value->generation = generation;
	value->slot = slot;
	value->len = payload_len;
	*out_len = payload_len;
	return LICHEN_STORAGE_OPEN_OK;
}
enum lichen_hal_storage_update_status lichen_hal_storage_update_redundant(
	const struct lichen_hal_storage_ops *ops, void *user,
	const char *const keys[2], const uint8_t magic[4],
	const struct lichen_hal_storage_value *current, const uint8_t *payload,
	size_t payload_len, uint8_t *record, size_t record_len,
	struct lichen_hal_storage_value *updated)
{
	uint64_t gen[2] = { 0, 0 };
	size_t stored_len[2] = { 0, 0 };
	bool present[2] = { false, false };
	bool valid[2] = { false, false };
	int rets[2];
	uint64_t generation;
	enum lichen_hal_storage_slot slot;
	size_t len;
	uint64_t latest_gen = 0;
	enum lichen_hal_storage_slot latest_slot = LICHEN_STORAGE_SLOT_A;

	if (ops == NULL || ops->read == NULL || ops->write == NULL ||
	    keys == NULL || keys[0] == NULL || keys[1] == NULL ||
	    magic == NULL || current == NULL || payload == NULL ||
	    record == NULL || updated == NULL) {
		return LICHEN_STORAGE_UPDATE_STORAGE_ERROR;
	}
	/* Like the Rust reference, each slot is read into the shared scratch
	 * buffer and reduced to (generation, length) before the next read;
	 * payload bytes are not retained across the two reads.
	 */
	for (unsigned int i = 0; i < 2; i++) {
		size_t raw_len = 0;

		rets[i] = read_one(ops, user, keys[i], record, record_len,
				   &raw_len);
		if (rets[i] == -EOVERFLOW) {
			/* Stored length exceeds the scratch buffer: the Rust
			 * reference classifies this as Corrupt too.
			 */
			return LICHEN_STORAGE_UPDATE_CORRUPT;
		}
		if (rets[i] < 0) {
			return LICHEN_STORAGE_UPDATE_STORAGE_ERROR;
		}
		present[i] = rets[i] == 0;
		if (present[i]) {
			const uint8_t *slot_payload = NULL;

			valid[i] = lichen_hal_storage_parse_slot(
				record, raw_len, magic, &gen[i],
				&slot_payload, &stored_len[i]);
		}
	}
	if (valid[0] && valid[1] && gen[1] > gen[0]) {
		latest_gen = gen[1];
		latest_slot = LICHEN_STORAGE_SLOT_B;
	} else if (valid[0]) {
		latest_gen = gen[0];
		latest_slot = LICHEN_STORAGE_SLOT_A;
	} else if (valid[1]) {
		latest_gen = gen[1];
		latest_slot = LICHEN_STORAGE_SLOT_B;
	} else if (!present[0] && !present[1]) {
		return LICHEN_STORAGE_UPDATE_STALE;
	} else {
		return LICHEN_STORAGE_UPDATE_CORRUPT;
	}
	if (latest_gen != current->generation || latest_slot != current->slot) {
		return LICHEN_STORAGE_UPDATE_STALE;
	}
	if (current->generation == UINT64_MAX) {
		return LICHEN_STORAGE_UPDATE_EXHAUSTED;
	}
	generation = current->generation + 1;
	len = lichen_hal_storage_encode_slot(magic, generation, payload,
					     payload_len, record, record_len);
	if (len == 0) {
		return LICHEN_STORAGE_UPDATE_BUFFER_TOO_SMALL;
	}
	slot = (current->slot == LICHEN_STORAGE_SLOT_A) ? LICHEN_STORAGE_SLOT_B
						       : LICHEN_STORAGE_SLOT_A;
	if (ops->write(user, keys[(unsigned int)slot], record, len) != 0) {
		return LICHEN_STORAGE_UPDATE_STORAGE_ERROR;
	}
	updated->generation = generation;
	updated->slot = slot;
	updated->len = payload_len;
	return LICHEN_STORAGE_UPDATE_OK;
}

/* ------------------------------------------------------------------ */
/* Compact wrapper surface (lichen_hal_redundant_*), private codec.    */
/* ------------------------------------------------------------------ */
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
