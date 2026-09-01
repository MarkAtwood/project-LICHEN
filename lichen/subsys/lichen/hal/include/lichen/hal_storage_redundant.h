/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_HAL_STORAGE_REDUNDANT_H_
#define LICHEN_HAL_STORAGE_REDUNDANT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
