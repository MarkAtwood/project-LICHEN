/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file redundant_slot.h
 * @brief Two-slot redundant-record persistence primitive (spec 09 14.2).
 *
 * C port of rust/lichen-hal/src/storage.rs redundant-slot storage:
 * each record is magic[4] | version u8 | 3x zero | generation u64 BE |
 * len u32 BE | payload | crc32 BE (20-byte header + 4-byte trailer, CRC-32
 * reflected/ISO-HDLC bit-exact with the Rust implementation).
 *
 * Freestanding: storage is abstracted behind @ref lichen_redundant_io so the
 * module is host-testable; the Zephyr settings/NonVolatile backend binds the
 * read/write callbacks.
 */

#ifndef LICHEN_REDUNDANT_SLOT_H_
#define LICHEN_REDUNDANT_SLOT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Slot record overhead: 20-byte header + 4-byte CRC32 trailer. */
#define LICHEN_REDUNDANT_OVERHEAD 24U

/** Storage operations bound by the backend (settings/NVS/host fake). */
struct lichen_redundant_io {
	/**
	 * @brief Read a record.
	 *
	 * @param user   Backend context
	 * @param key    Storage key
	 * @param out    Buffer for the stored bytes
	 * @param cap    Buffer capacity
	 * @return Stored length (> 0), 0 if the key is absent,
	 *         negative errno on storage failure.
	 */
	int (*read)(void *user, const char *key, uint8_t *out, size_t cap);
	/** Write a record; returns 0 or negative errno. */
	int (*write)(void *user, const char *key, const uint8_t *data,
		     size_t len);
	void *user;
};

/** Newest valid value opened from the two slots. */
struct lichen_redundant_value {
	uint64_t generation; /**< Monotonic generation (never 0). */
	int slot;            /**< Slot index the value was read from (0/1). */
	size_t len;          /**< Payload length in bytes. */
};

/**
 * @brief Provision an absent two-slot value (generation 1, slot 0).
 *
 * Existing or corrupt state is NOT overwritten.
 *
 * @return 0, -EEXIST if either key is present, -EINVAL if the record buffer
 *         cannot hold the payload, -EIO on storage failure.
 */
int lichen_redundant_provision(const struct lichen_redundant_io *io,
			       const char *const keys[2],
			       const uint8_t magic[4], const uint8_t *payload,
			       size_t len, uint8_t *record, size_t record_cap);

/**
 * @brief Open the newest valid value from the two slots.
 *
 * @param value      Receives generation/slot/len of the newest value
 * @return 0, -ENOENT if both keys are absent (Missing), -EIO if a present
 *         record is corrupt (Corrupt) or storage fails, -ENOSPC if @p out
 *         cannot hold the payload (BufferTooSmall).
 */
int lichen_redundant_open(const struct lichen_redundant_io *io,
			  const char *const keys[2], const uint8_t magic[4],
			  uint8_t *slot_a, size_t slot_a_cap, uint8_t *slot_b,
			  size_t slot_b_cap, uint8_t *out, size_t out_cap,
			  struct lichen_redundant_value *value);

/**
 * @brief Persist the next generation to the slot opposite @p current.
 *
 * @param value Receives the new generation/slot/len on success
 * @return 0, -ESTALE if storage no longer matches @p current, -EOVERFLOW at
 *         u64 generation wrap, -ENOSPC if @p record_cap is insufficient,
 *         -EIO on corrupt storage state or write failure.
 */
int lichen_redundant_update(const struct lichen_redundant_io *io,
			    const char *const keys[2], const uint8_t magic[4],
			    const struct lichen_redundant_value *current,
			    const uint8_t *payload, size_t len,
			    uint8_t *record, size_t record_cap,
			    struct lichen_redundant_value *value);

#endif /* LICHEN_REDUNDANT_SLOT_H_ */
