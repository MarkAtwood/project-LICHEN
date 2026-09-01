/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file beacon.h
 * @brief TDMA beacon wire codec (spec 02a-coordinated-capacity.md §2a.2).
 *
 * Fixed-format uncompressed beacon layout:
 *   [0..4)  epoch         u32 BE
 *   [4]     num_slots     u8
 *   [5..9)  sfn           u32 BE
 *   [9..13) timestamp     u32 BE
 *   [13]    flags         u8 (bit0 scheduled, bit1 csma, bit2 ch0_rx,
 *                             bit3 gnss_pps; reserved mask 0xF0)
 *   [14]    rx_chains     u8
 *   [15..17) setup_window  u16 BE
 *   [17..19) occupied_time u16 BE
 *   [19]    guard          u8 (normative 50 ms)
 *   [20..24) channel_mask  u32 (bit0 = CH0)
 *
 * CBOR options (per CDDL, e.g. slot_map / pow_challenge) sit between the
 * header and the trailing 48-byte Schnorr48 beacon signature.
 * Minimum beacon size: 24 + 48 = 72.
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

/** Parsed beacon header fields. */
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

/** Parse/serialize error codes. */
#define LICHEN_BEACON_ERR_SHORT (-1)    /**< buffer too short */
#define LICHEN_BEACON_ERR_RESERVED (-2) /**< reserved flag bits set */

/**
 * @brief Parse the 24-byte beacon header.
 * @return 0 on success; LICHEN_BEACON_ERR_SHORT if too short;
 *         LICHEN_BEACON_ERR_RESERVED if reserved flag bits (0xF0) are set
 */
int lichen_beacon_parse_header(const uint8_t *data, size_t len,
			       struct lichen_beacon_header *out);

/**
 * @brief Serialize the 24-byte beacon header.
 * @return bytes written (24), or LICHEN_BEACON_ERR_RESERVED if reserved
 *         flag bits are set
 */
int lichen_beacon_serialize_header(const struct lichen_beacon_header *header,
				   uint8_t *out);

/**
 * @brief Extract the trailing 48-byte beacon signature.
 * @return pointer into @p beacon, or NULL when too short
 */
const uint8_t *lichen_beacon_signature_bytes(const uint8_t *beacon,
					     size_t len);

/**
 * @brief Bytes covered by the beacon signature (0..E-48).
 */
const uint8_t *lichen_beacon_signed_data(const uint8_t *beacon, size_t len);

#endif /* LICHEN_BEACON_H_ */
