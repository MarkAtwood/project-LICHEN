/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file redundant_slot.c
 * @brief Two-slot redundant-record persistence (spec 09 14.2).
 *
 * Mirrors rust/lichen-hal/src/storage.rs:120-248 bit-exactly, including the
 * CRC-32 (reflected, poly 0xEDB88320, init/final u32::MAX/XOR) so records
 * written by either implementation validate in the other.
 */

#include <lichen/redundant_slot.h>

#include <errno.h>
#include <string.h>

#define REDUNDANT_SLOT_VERSION 1U
#define REDUNDANT_HEADER_LEN 20U
#define REDUNDANT_TRAILER_LEN 4U

/* CRC-32 (reflected, ISO-HDLC): identical to the Rust crc32 in
 * lichen-hal storage.rs and to zlib's crc32. */
static uint32_t redundant_crc32(const uint8_t *data, size_t len)
{
	uint32_t crc = UINT32_MAX;

	for (size_t i = 0U; i < len; i++) {
		crc ^= (uint32_t)data[i];
		for (int bit = 0; bit < 8; bit++) {
			crc = (crc >> 1) ^
			      (0xEDB88320U & (0U - (crc & 1U)));
		}
	}
	return ~crc;
}

static int encode_slot(const uint8_t magic[4], uint64_t generation,
		       const uint8_t *payload, size_t len, uint8_t *record,
		       size_t record_cap)
{
	if (len > UINT32_MAX || generation == 0U ||
	    len > record_cap - LICHEN_REDUNDANT_OVERHEAD) {
		return -1;
	}

	record[0] = magic[0];
	record[1] = magic[1];
	record[2] = magic[2];
	record[3] = magic[3];
	record[4] = REDUNDANT_SLOT_VERSION;
	record[5] = 0U;
	record[6] = 0U;
	record[7] = 0U;
	for (int i = 0; i < 8; i++) {
		record[8U + (size_t)i] =
		    (uint8_t)(generation >> (8 * (7 - i)));
	}
	record[16] = (uint8_t)(len >> 24);
	record[17] = (uint8_t)(len >> 16);
	record[18] = (uint8_t)(len >> 8);
	record[19] = (uint8_t)len;
	memcpy(&record[REDUNDANT_HEADER_LEN], payload, len);

	uint32_t crc = redundant_crc32(record, REDUNDANT_HEADER_LEN + len);
	record[REDUNDANT_HEADER_LEN + len] = (uint8_t)(crc >> 24);
	record[REDUNDANT_HEADER_LEN + len + 1U] = (uint8_t)(crc >> 16);
	record[REDUNDANT_HEADER_LEN + len + 2U] = (uint8_t)(crc >> 8);
	record[REDUNDANT_HEADER_LEN + len + 3U] = (uint8_t)crc;
	return (int)(REDUNDANT_HEADER_LEN + len + REDUNDANT_TRAILER_LEN);
}

/* Parse one slot: returns payload length (> 0) or -1 when invalid. */
static int parse_slot(const uint8_t *raw, size_t raw_len,
		      const uint8_t magic[4], uint64_t *generation)
{
	if (raw_len < REDUNDANT_HEADER_LEN + REDUNDANT_TRAILER_LEN ||
	    raw[0] != magic[0] || raw[1] != magic[1] || raw[2] != magic[2] ||
	    raw[3] != magic[3] || raw[4] != REDUNDANT_SLOT_VERSION ||
	    raw[5] != 0U || raw[6] != 0U || raw[7] != 0U) {
		return -1;
	}

	*generation = 0U;
	for (int i = 0; i < 8; i++) {
		*generation = (*generation << 8) | raw[8U + (size_t)i];
	}
	size_t len = ((size_t)raw[16] << 24) | ((size_t)raw[17] << 16) |
		     ((size_t)raw[18] << 8) | (size_t)raw[19];
	if (len > raw_len - LICHEN_REDUNDANT_OVERHEAD) {
		return -1;
	}

	uint32_t crc = ((uint32_t)raw[REDUNDANT_HEADER_LEN + len] << 24) |
		       ((uint32_t)raw[REDUNDANT_HEADER_LEN + len + 1U] << 16) |
		       ((uint32_t)raw[REDUNDANT_HEADER_LEN + len + 2U] << 8) |
		       (uint32_t)raw[REDUNDANT_HEADER_LEN + len + 3U];
	if (redundant_crc32(raw, REDUNDANT_HEADER_LEN + len) != crc) {
		return -1;
	}
	return (int)len;
}

int lichen_redundant_provision(const struct lichen_redundant_io *io,
			       const char *const keys[2],
			       const uint8_t magic[4], const uint8_t *payload,
			       size_t len, uint8_t *record, size_t record_cap)
{
	if (io == NULL || io->read == NULL || io->write == NULL ||
	    keys == NULL || magic == NULL || payload == NULL || record == NULL) {
		return -EINVAL;
	}

	uint8_t probe[1];
	if (io->read(io->user, keys[0], probe, sizeof(probe)) > 0 ||
	    io->read(io->user, keys[1], probe, sizeof(probe)) > 0) {
		return -EEXIST;
	}

	int encoded = encode_slot(magic, 1U, payload, len, record, record_cap);
	if (encoded < 0) {
		return -EINVAL;
	}
	return io->write(io->user, keys[0], record, (size_t)encoded);
}

int lichen_redundant_open(const struct lichen_redundant_io *io,
			  const char *const keys[2], const uint8_t magic[4],
			  uint8_t *slot_a, size_t slot_a_cap, uint8_t *slot_b,
			  size_t slot_b_cap, uint8_t *out, size_t out_cap,
			  struct lichen_redundant_value *value)
{
	if (io == NULL || io->read == NULL || keys == NULL || magic == NULL ||
	    slot_a == NULL || slot_b == NULL || out == NULL || value == NULL) {
		return -EINVAL;
	}

	int len_a = io->read(io->user, keys[0], slot_a, slot_a_cap);
	int len_b = io->read(io->user, keys[1], slot_b, slot_b_cap);
	if (len_a < -1 || len_b < -1) {
		return -EIO; /* storage failure */
	}

	uint64_t gen_a = 0U;
	uint64_t gen_b = 0U;
	int pay_a = -1;
	int pay_b = -1;
	if (len_a > 0) {
		pay_a = parse_slot(slot_a, (size_t)len_a, magic, &gen_a);
	}
	if (len_b > 0) {
		pay_b = parse_slot(slot_b, (size_t)len_b, magic, &gen_b);
	}

	const uint8_t *payload = NULL;
	size_t payload_len = 0U;
	if (pay_a > 0 && pay_b > 0) {
		if (gen_b > gen_a) {
			payload = slot_b + REDUNDANT_HEADER_LEN;
			payload_len = (size_t)pay_b;
			value->generation = gen_b;
			value->slot = 1;
		} else {
			payload = slot_a + REDUNDANT_HEADER_LEN;
			payload_len = (size_t)pay_a;
			value->generation = gen_a;
			value->slot = 0;
		}
	} else if (pay_a > 0) {
		payload = slot_a + REDUNDANT_HEADER_LEN;
		payload_len = (size_t)pay_a;
		value->generation = gen_a;
		value->slot = 0;
	} else if (pay_b > 0) {
		payload = slot_b + REDUNDANT_HEADER_LEN;
		payload_len = (size_t)pay_b;
		value->generation = gen_b;
		value->slot = 1;
	} else if (len_a == 0 && len_b == 0) {
		return -ENOENT; /* Missing */
	} else {
		return -EIO; /* Corrupt */
	}

	if (payload_len > out_cap) {
		return -ENOSPC; /* BufferTooSmall */
	}
	memcpy(out, payload, payload_len);
	value->len = payload_len;
	return 0;
}

int lichen_redundant_update(const struct lichen_redundant_io *io,
			    const char *const keys[2], const uint8_t magic[4],
			    const struct lichen_redundant_value *current,
			    const uint8_t *payload, size_t len,
			    uint8_t *record, size_t record_cap,
			    struct lichen_redundant_value *value)
{
	if (io == NULL || io->read == NULL || io->write == NULL ||
	    keys == NULL || magic == NULL || current == NULL || payload == NULL ||
	    record == NULL || value == NULL || record_cap == 0U) {
		return -EINVAL;
	}

	/* Re-read both slots into the caller's record buffer, reused exactly
	 * as the Rust read_parsed_update does: parse generation/len from each
	 * read before the buffer is overwritten by the next read. */
	int len_a = io->read(io->user, keys[0], record, record_cap);
	uint64_t gen_a = 0U;
	int pay_a = len_a > 0 ? parse_slot(record, (size_t)len_a, magic, &gen_a)
			      : -1;
	int len_b = io->read(io->user, keys[1], record, record_cap);
	uint64_t gen_b = 0U;
	int pay_b = len_b > 0 ? parse_slot(record, (size_t)len_b, magic, &gen_b)
			      : -1;
	if (len_a < -1 || len_b < -1) {
		return -EIO;
	}

	uint64_t latest_gen = 0U;
	int latest_slot = -1;
	if (pay_a > 0 && pay_b > 0) {
		if (gen_b > gen_a) {
			latest_gen = gen_b;
			latest_slot = 1;
		} else {
			latest_gen = gen_a;
			latest_slot = 0;
		}
	} else if (pay_a > 0) {
		latest_gen = gen_a;
		latest_slot = 0;
	} else if (pay_b > 0) {
		latest_gen = gen_b;
		latest_slot = 1;
	} else if (len_a == 0 && len_b == 0) {
		return -ESTALE;
	} else {
		return -EIO; /* Corrupt */
	}

	if (latest_gen != current->generation || latest_slot != current->slot) {
		return -ESTALE;
	}

	if (current->generation == UINT64_MAX) {
		return -EOVERFLOW; /* generation wrap: terminal (spec 14.2) */
	}
	uint64_t generation = current->generation + 1U;

	int encoded = encode_slot(magic, generation, payload, len, record,
				  record_cap);
	if (encoded < 0) {
		return -ENOSPC;
	}

	int slot = 1 - current->slot;
	int ret = io->write(io->user, keys[slot], record, (size_t)encoded);
	if (ret == 0) {
		value->generation = generation;
		value->slot = slot;
		value->len = len;
	}
	return ret;
}
