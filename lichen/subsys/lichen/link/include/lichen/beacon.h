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

/**
 * @brief Local intersection of a beacon's advertised channel_mask with the
 *        locally permitted mask (spec 02a 2a.2 R-02a-006, bit 0=CH0).
 * @return intersection mask; 0 means no common channel, in which case the
 *         caller MUST reject/ignore the beacon. The wire field is u32, so
 *         both inputs are wire-width exact; plan widths above 32 channels
 *         cannot be expressed in the beacon and must be pre-masked by the
 *         caller into @p permitted.
 */
uint32_t lichen_beacon_intersect_channel_mask(uint32_t permitted,
					      uint32_t advertised);

#endif /* LICHEN_BEACON_H_ */
