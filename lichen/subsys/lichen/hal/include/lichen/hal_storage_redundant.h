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
 *
 * Merge note (main x beads-worker-2): this header carries two API
 * surfaces over the same wire format. lichen_hal_storage_* exposes the
 * codec (crc32/encode/parse) plus the storage layer and is consumed by
 * rpl_dao_tx_persist; lichen_hal_redundant_* is the compact wrapper
 * surface with a private codec. Both are exercised by
 * tests/hal_storage_redundant, so both are kept.
 */

#ifndef LICHEN_HAL_STORAGE_REDUNDANT_H_
#define LICHEN_HAL_STORAGE_REDUNDANT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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

/** Slot record layout: magic(4) version(1) rsvd(3) gen(8) len(4) payload crc(4). */
#define LICHEN_REDUNDANT_SLOT_OVERHEAD 24u

/** Result codes for lichen_hal_redundant_provision. */
enum lichen_hal_redundant_provision_result {
	LICHEN_HAL_REDUNDANT_PROVISION_OK = 0,
	LICHEN_HAL_REDUNDANT_PROVISION_EXISTS,
	LICHEN_HAL_REDUNDANT_PROVISION_STORAGE,
	LICHEN_HAL_REDUNDANT_PROVISION_ENCODE, /**< record buffer too small */
};

/** Result codes for lichen_hal_redundant_open. */
enum lichen_hal_redundant_open_result {
	LICHEN_HAL_REDUNDANT_OPEN_OK = 0,
	LICHEN_HAL_REDUNDANT_OPEN_MISSING,
	LICHEN_HAL_REDUNDANT_OPEN_CORRUPT,
	LICHEN_HAL_REDUNDANT_OPEN_BUFFER_TOO_SMALL,
	LICHEN_HAL_REDUNDANT_OPEN_STORAGE,
};

/** Result codes for lichen_hal_redundant_update. */
enum lichen_hal_redundant_update_result {
	LICHEN_HAL_REDUNDANT_UPDATE_OK = 0,
	LICHEN_HAL_REDUNDANT_UPDATE_STALE,
	LICHEN_HAL_REDUNDANT_UPDATE_EXHAUSTED,
	LICHEN_HAL_REDUNDANT_UPDATE_CORRUPT,
	LICHEN_HAL_REDUNDANT_UPDATE_STORAGE,
	LICHEN_HAL_REDUNDANT_UPDATE_ENCODE, /**< record buffer too small */
};

/** Newest valid value resolved by open/update. */
struct lichen_hal_redundant_value {
	uint64_t generation;
	unsigned slot; /**< 0 = keys[0], 1 = keys[1] */
	size_t len;    /**< Payload length */
};

/**
 * @brief Storage-agnostic key/value operations (project ops-vtable style).
 *
 * read: copy the stored value for @p key into @p out (up to @p cap bytes),
 * set @p *len to the FULL stored length, return 0 if found, 1 if missing,
 * negative errno on storage failure. A caller that only receives partial
 * bytes (stored length > cap) must treat the value as overflow.
 *
 * write: store @p value under @p key, return 0 on success, negative errno
 * on failure.
 */
struct lichen_hal_redundant_ops {
	int (*read)(void *user, const char *key, uint8_t *out, size_t cap,
		    size_t *len);
	int (*write)(void *user, const char *key, const uint8_t *value,
		     size_t len);
};

/**
 * @brief Provision an absent two-slot value (writes slot A, generation 1).
 *
 * Fails with EXISTS if either key is already present. Existing or corrupt
 * state is never overwritten.
 *
 * @param[in]  user   Opaque storage handle passed to @p ops
 * @param[in]  ops    Storage ops vtable
 * @param[in]  keys   Two storage keys (slot A, slot B)
 * @param[in]  magic  4-byte record magic (caller-owned, e.g. "DTX2")
 * @param[in]  payload Initial payload bytes
 * @param[in]  payload_len Payload length
 * @param[out] record Scratch buffer for the encoded slot record
 * @param[in]  record_cap Scratch buffer capacity
 * @return PROVISION_OK, PROVISION_EXISTS, PROVISION_STORAGE, or
 *         PROVISION_ENCODE
 */
enum lichen_hal_redundant_provision_result lichen_hal_redundant_provision(
	void *user, const struct lichen_hal_redundant_ops *ops,
	const char *keys[2], const uint8_t magic[4], const uint8_t *payload,
	size_t payload_len, uint8_t *record, size_t record_cap);

/**
 * @brief Open the newest valid value from two alternating slots.
 *
 * @param[in]  user   Opaque storage handle passed to @p ops
 * @param[in]  ops    Storage ops vtable
 * @param[in]  keys   Two storage keys (slot A, slot B)
 * @param[in]  magic  4-byte record magic
 * @param      slot_a Scratch buffer (>= record_cap) for slot A raw bytes
 * @param      slot_b Scratch buffer (>= record_cap) for slot B raw bytes
 * @param[in]  slot_cap Scratch buffer capacity
 * @param[out] out    Decoded payload
 * @param[in]  out_cap Output capacity
 * @param[out] value  Generation/slot/len of the opened record
 * @return OPEN_OK, OPEN_MISSING, OPEN_CORRUPT, OPEN_BUFFER_TOO_SMALL, or
 *         OPEN_STORAGE
 */
enum lichen_hal_redundant_open_result lichen_hal_redundant_open(
	void *user, const struct lichen_hal_redundant_ops *ops,
	const char *keys[2], const uint8_t magic[4], uint8_t *slot_a,
	uint8_t *slot_b, size_t slot_cap, uint8_t *out, size_t out_cap,
	struct lichen_hal_redundant_value *value);

/**
 * @brief Persist the next generation to the slot opposite value->slot.
 *
 * Re-parses both slots fresh; rejects STALE when the caller's
 * (generation, slot) doesn't match the stored latest; EXHAUSTED at u64
 * generation max. On storage-write failure the old slot remains intact
 * (no explicit rollback).
 *
 * @param[in]  user   Opaque storage handle passed to @p ops
 * @param[in]  ops    Storage ops vtable
 * @param[in]  keys   Two storage keys (slot A, slot B)
 * @param[in]  magic  4-byte record magic
 * @param[in]  current Caller's view of the current record
 * @param[in]  payload Next payload bytes
 * @param[in]  payload_len Next payload length
 * @param[out] record Scratch buffer for the encoded slot record
 * @param[in]  record_cap Scratch buffer capacity
 * @param[out] value  Generation/slot/len of the newly written record
 * @return UPDATE_OK, UPDATE_STALE, UPDATE_EXHAUSTED, UPDATE_CORRUPT,
 *         UPDATE_STORAGE, or UPDATE_ENCODE
 */
enum lichen_hal_redundant_update_result lichen_hal_redundant_update(
	void *user, const struct lichen_hal_redundant_ops *ops,
	const char *keys[2], const uint8_t magic[4],
	const struct lichen_hal_redundant_value *current, const uint8_t *payload,
	size_t payload_len, uint8_t *record, size_t record_cap,
	struct lichen_hal_redundant_value *value);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_HAL_STORAGE_REDUNDANT_H_ */
