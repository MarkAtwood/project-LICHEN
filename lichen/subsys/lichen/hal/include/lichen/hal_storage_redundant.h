/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file hal_storage_redundant.h
 * @brief Two-slot redundant-record slot encoding (C port of rust
 *	  lichen-hal storage.rs encode_slot/parse_slot, bead b7z9.11.1).
 *
 * Slot layout (LICHEN_STORAGE_SLOT_HEADER_LEN + payload + trailer):
 *   [0..4)   magic (caller-chosen, e.g. "DTX2")
 *   [4]      version (1)
 *   [5..8)   reserved (zero)
 *   [8..16)  generation u64 big-endian, MUST be nonzero
 *   [16..20) payload length u32 big-endian
 *   [20..)   payload
 *   [..+4)   CRC-32 (reflected, poly 0xEDB88320) of everything before it
 */

#ifndef LICHEN_HAL_STORAGE_REDUNDANT_H_
#define LICHEN_HAL_STORAGE_REDUNDANT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LICHEN_STORAGE_SLOT_VERSION 1U
#define LICHEN_STORAGE_SLOT_HEADER_LEN 20U
#define LICHEN_STORAGE_SLOT_TRAILER_LEN 4U

/** CRC-32 (reflected, poly 0xEDB88320), bit-exact with Rust lichen-hal. */
uint32_t lichen_hal_storage_crc32(const uint8_t *data, size_t len);

/**
 * Encode one slot record into out.
 *
 * All pointer arguments must be non-NULL (even when payload_len is 0).
 * Returns the total encoded length, or 0 when: generation is 0, the
 * total record length would exceed UINT32_MAX, or out is too small.
 *
 * Deviation from the Rust reference (lichen-hal storage.rs encode_slot):
 * the payload bound here is UINT32_MAX minus the 24-byte record overhead,
 * so a record can never exceed a u32 length field. The Rust version only
 * checks payload <= u32::MAX and is platform-dependent in that last
 * 24-size window. The C bound is the stricter, overflow-safe one.
 */
size_t lichen_hal_storage_encode_slot(const uint8_t magic[4], uint64_t generation,
				      const uint8_t *payload, size_t payload_len,
				      uint8_t *out, size_t out_len);

/**
 * Parse and validate one slot record.
 *
 * All pointer arguments must be non-NULL. On success returns true, writes
 * the generation, and sets *payload / *payload_len into the payload region
 * of raw.
 */
bool lichen_hal_storage_parse_slot(const uint8_t *raw, size_t raw_len,
				   const uint8_t magic[4], uint64_t *generation,
				   const uint8_t **payload, size_t *payload_len);

/**
 * Backing-store operations. Mirrors the Rust NonVolatile trait surface used
 * by the two-slot primitive: read returns 1 when the key is absent, an
 * errno (< 0) on failure, 0 when found (with *length set to the stored
 * length, truncated to capacity).
 */
struct lichen_hal_storage_ops {
	int (*read)(void *user, const char *key, uint8_t *out, size_t capacity,
		    size_t *length);
	int (*write)(void *user, const char *key, const uint8_t *value,
		     size_t length);
};

/** Which of the two slots a value lives in. */
enum lichen_hal_storage_slot {
	LICHEN_STORAGE_SLOT_A = 0,
	LICHEN_STORAGE_SLOT_B = 1,
};

/** A successfully opened or updated two-slot value. */
struct lichen_hal_storage_value {
	uint64_t generation;
	enum lichen_hal_storage_slot slot;
	size_t len;
};

/** open_redundant outcomes. */
enum lichen_hal_storage_open_status {
	LICHEN_STORAGE_OPEN_OK = 0,
	LICHEN_STORAGE_OPEN_MISSING = -1,
	LICHEN_STORAGE_OPEN_CORRUPT = -2,
	LICHEN_STORAGE_OPEN_BUFFER_TOO_SMALL = -3,
	LICHEN_STORAGE_OPEN_STORAGE_ERROR = -4,
};

/** provision_redundant outcomes. */
enum lichen_hal_storage_provision_status {
	LICHEN_STORAGE_PROVISION_OK = 0,
	LICHEN_STORAGE_PROVISION_EXISTS = -1,
	LICHEN_STORAGE_PROVISION_STORAGE_ERROR = -2,
};

/** update_redundant outcomes. */
enum lichen_hal_storage_update_status {
	LICHEN_STORAGE_UPDATE_OK = 0,
	LICHEN_STORAGE_UPDATE_STALE = -1,
	LICHEN_STORAGE_UPDATE_EXHAUSTED = -2,
	LICHEN_STORAGE_UPDATE_CORRUPT = -3,
	LICHEN_STORAGE_UPDATE_STORAGE_ERROR = -4,
	LICHEN_STORAGE_UPDATE_BUFFER_TOO_SMALL = -5,
};

/**
 * Provision an absent two-slot value at generation 1 into keys[0].
 * Fails with EXISTS when either key already holds anything (even corrupt
 * bytes); existing state is never overwritten.
 */
enum lichen_hal_storage_provision_status lichen_hal_storage_provision_redundant(
	const struct lichen_hal_storage_ops *ops, void *user,
	const char *const keys[2], const uint8_t magic[4],
	const uint8_t *payload, size_t payload_len, uint8_t *record,
	size_t record_len);

/**
 * Load the newest valid value from the two slots.
 *
 * out receives the payload; out_len is the buffer capacity on entry and the
 * payload length on success. MISSING when both keys are absent, CORRUPT
 * when at least one exists but neither parses.
 */
enum lichen_hal_storage_open_status lichen_hal_storage_open_redundant(
	const struct lichen_hal_storage_ops *ops, void *user,
	const char *const keys[2], const uint8_t magic[4], uint8_t *slot_a,
	size_t slot_a_len, uint8_t *slot_b, size_t slot_b_len, uint8_t *out,
	size_t *out_len, struct lichen_hal_storage_value *value);

/**
 * Persist the next generation to the slot opposite value->slot.
 *
 * Re-reads both slots and refuses (STALE) unless the caller's (generation,
 * slot) still matches the newest valid state; refuses (EXHAUSTED) at
 * generation UINT64_MAX (no wrap). On storage-write failure the previous
 * slot remains intact and the error is surfaced (the Rust reference has no
 * rollback either: the caller retries with the same current value).
 *
 * C-specific deviation: BUFFER_TOO_SMALL is returned when the record
 * buffer cannot hold the encoded next generation; the Rust reference
 * panics there ("record buffer sized by caller").
 */
enum lichen_hal_storage_update_status lichen_hal_storage_update_redundant(
	const struct lichen_hal_storage_ops *ops, void *user,
	const char *const keys[2], const uint8_t magic[4],
	const struct lichen_hal_storage_value *current, const uint8_t *payload,
	size_t payload_len, uint8_t *record, size_t record_len,
	struct lichen_hal_storage_value *updated);

#endif /* LICHEN_HAL_STORAGE_REDUNDANT_H_ */
