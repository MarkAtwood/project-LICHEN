/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file beacon.h
 * @brief TDMA beacon wire codec (spec 02a-coordinated-capacity.md §2a.2).
 *
 * Port of rust lichen-core tdma_beacon.rs and python rpl/tdma_beacon.py.
 * Fixed-format uncompressed beacon header (24 bytes) plus trailing
 * Schnorr48 signature (48 bytes); minimum beacon size: 24 + 48 = 72.
 *
 * Header layout (all unsigned big-endian):
 *   [0..4)   epoch         u32 BE
 *   [4]      num_slots     u8
 *   [5..9)   sfn           u32 BE
 *   [9..13)  timestamp     u32 BE
 *   [13]     flags         u8 (bit0 scheduled, bit1 csma, bit2 ch0_rx,
 *                              bit3 gnss_pps; bits 4-7 reserved, MUST be
 *                              zero on send; reserved mask 0xF0)
 *   [14]     rx_chains     u8
 *   [15..17) setup_window  u16 BE
 *   [17..19) occupied_time u16 BE
 *   [19]     guard         u8 (normative 50 ms)
 *   [20..24) channel_mask  u32 BE (bit0 = CH0)
 *
 * CBOR options (per CDDL, e.g. slot_map / pow_challenge) sit between the
 * header and the trailing 48-byte Schnorr48 beacon signature.
 *
 * Merge note (main + beads-worker-7, bead l9sb): HEAD's API (enum
 * lichen_beacon_status, bounds-checked header_parse/header_serialize,
 * flag predicates, signed_data with signed_len, cbor_options) is kept
 * because bead l9sb requires the cbor_options extraction and it is the
 * complete port of the Python/Rust reference codecs; the beads-worker-7
 * parse_header/serialize_header names and LICHEN_BEACON_ERR_* defines are
 * superseded by the enum API. Retained from beads-worker-7: the
 * LICHEN_BEACON_H_ include guard (matches the project's flat guard
 * convention) and the typed layout table / per-symbol doc comments.
 */

#ifndef LICHEN_BEACON_H_
#define LICHEN_BEACON_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Beacon header size (bytes). */
#define LICHEN_BEACON_HEADER_SIZE 24U
/** Trailing Schnorr48 signature size (bytes). */
#define LICHEN_BEACON_SIG_SIZE 48U
/** Minimum total beacon size (header + signature). */
#define LICHEN_BEACON_MIN_SIZE (LICHEN_BEACON_HEADER_SIZE + LICHEN_BEACON_SIG_SIZE)

/** Reserved flag mask (bits 4-7 fail closed on parse and serialize). */
#define LICHEN_BEACON_FLAG_RESERVED_MASK 0xF0U

/** Beacon flags. */
#define LICHEN_BEACON_FLAG_SCHEDULED 0x01U
#define LICHEN_BEACON_FLAG_CSMA 0x02U
#define LICHEN_BEACON_FLAG_CH0_RX 0x04U
#define LICHEN_BEACON_FLAG_GNSS_PPS 0x08U

/** Maximum slot_map entries (rust parity; see lichen_beacon_write_slot_map). */
#define LICHEN_SLOT_MAP_MAX_ENTRIES 64U

/** Parse/serialize status. */
enum lichen_beacon_status {
	LICHEN_BEACON_OK = 0,		  /**< success */
	LICHEN_BEACON_TOO_SHORT = -1,	  /**< buffer too short */
	LICHEN_BEACON_RESERVED_FLAG_SET = -2, /**< reserved flag bits set */
	LICHEN_BEACON_INVALID_FIELD = -3, /**< field out of wire range */
};

/** Parsed TDMA beacon header fields. */
struct lichen_beacon_header {
	uint32_t epoch;
	uint8_t num_slots;
	uint32_t sfn;
	uint32_t timestamp;
	uint8_t flags;
	uint8_t rx_chains;
	uint16_t setup_window;
	uint16_t occupied_time;
	uint8_t guard;
	uint32_t channel_mask;
};

/**
 * @brief Parse the 24-byte beacon header.
 * @return LICHEN_BEACON_OK on success; LICHEN_BEACON_TOO_SHORT if the
 *         buffer is short (or data/out is NULL);
 *         LICHEN_BEACON_RESERVED_FLAG_SET if any reserved flag bit
 *         (4-7) is set
 */
enum lichen_beacon_status
lichen_beacon_header_parse(const uint8_t *data, size_t len,
			   struct lichen_beacon_header *out);

/**
 * @brief Serialize the 24-byte beacon header.
 * @return LICHEN_BEACON_OK on success; LICHEN_BEACON_TOO_SHORT if the
 *         output buffer is short (or header/out is NULL);
 *         LICHEN_BEACON_RESERVED_FLAG_SET if reserved flag bits are set.
 *         Member widths match the wire widths exactly, so no field can
 *         be out of range; LICHEN_BEACON_INVALID_FIELD is kept for API
 *         stability with the Python/Rust codecs.
 */
enum lichen_beacon_status
lichen_beacon_header_serialize(const struct lichen_beacon_header *header,
			       uint8_t *out, size_t out_len);

/** Flag predicates (flags byte must already be reserved-mask validated). */
bool lichen_beacon_is_scheduled(uint8_t flags);
bool lichen_beacon_is_csma(uint8_t flags);
bool lichen_beacon_is_ch0_rx(uint8_t flags);
bool lichen_beacon_has_gnss_pps(uint8_t flags);

/**
 * @brief Extract the trailing 48-byte Schnorr48 beacon signature.
 * @return pointer into @p beacon, or NULL when too short
 */
const uint8_t *lichen_beacon_signature_bytes(const uint8_t *beacon, size_t len);

/**
 * @brief Bytes covered by the beacon signature (everything except the
 *        trailing signature).
 * @return pointer to @p beacon with @p signed_len set, or NULL when too
 *         short or when signed_len is NULL
 */
const uint8_t *lichen_beacon_signed_data(const uint8_t *beacon, size_t len,
					 size_t *signed_len);

/**
 * @brief CBOR options between the header and the signature.
 * @return pointer into @p beacon with @p options_len set, or NULL when
 *         the beacon is minimal (header + signature only), too short, or
 *         when options_len is NULL
 */
const uint8_t *lichen_beacon_cbor_options(const uint8_t *beacon, size_t len,
					  size_t *options_len);
/** slot_map parse outcomes (rust SlotMapError parity). */
enum lichen_slot_map_status {
	LICHEN_SLOT_MAP_OK = 0,
	LICHEN_SLOT_MAP_EMPTY = 1, /**< valid: empty map (no intent) */
	LICHEN_SLOT_MAP_NOT_AN_ARRAY = -1,
	LICHEN_SLOT_MAP_TRUNCATED = -2,
	LICHEN_SLOT_MAP_TOO_MANY_SLOTS = -3,
	LICHEN_SLOT_MAP_INVALID_ENCODING = -4,
	LICHEN_SLOT_MAP_OUT_OF_BOUNDS = -5,
	LICHEN_SLOT_MAP_NOT_SORTED = -6,
	LICHEN_SLOT_MAP_TRAILING_BYTES = -7,
};

/**
 * Parse a CBOR-encoded slot_map from beacon options and validate it
 * (rust tdma_beacon.rs parse_slot_map): CBOR array of ascending unique
 * immediate/1-byte slot indices, each < num_slots, no trailing bytes.
 * Empty input is a valid empty map (LICHEN_SLOT_MAP_EMPTY). On
 * LICHEN_SLOT_MAP_OK the slots are written to out (capacity out_cap) and
 * *out_len receives the count.
 *
 * Merge note (main + beads-worker-1): beads-worker-1's
 * lichen_beacon_parse_slot_map declaration is kept (beacon.c implements
 * it and tdma_beacon tests exercise it); the closing endif comment uses
 * LICHEN_BEACON_H_ to match the actual include guard above (see the
 * top-of-file merge note: flat guard convention, not
 * LICHEN_LINK_BEACON_H_).
 */
enum lichen_slot_map_status
lichen_beacon_parse_slot_map(const uint8_t *cbor, size_t cbor_len,
			     uint8_t num_slots, uint8_t *out, size_t out_cap,
			     size_t *out_len);
/** Encode a slot_map as a CBOR array (beacon CBOR options section).
 *  Accepts up to LICHEN_SLOT_MAP_MAX_ENTRIES (64, rust parity). Returns the
 *  encoded length, or 0 when out is too small, slot_count exceeds 64,
 *  or slots is NULL with a nonzero count. */
size_t lichen_beacon_write_slot_map(const uint8_t *slots, size_t slot_count,
				    uint8_t *out, size_t out_len);

#endif /* LICHEN_BEACON_H_ */
