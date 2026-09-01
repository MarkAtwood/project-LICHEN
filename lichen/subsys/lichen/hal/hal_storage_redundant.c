/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/hal_storage_redundant.h>

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
