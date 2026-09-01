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

#endif /* LICHEN_HAL_STORAGE_REDUNDANT_H_ */
