/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

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
