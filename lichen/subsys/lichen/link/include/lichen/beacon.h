/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file beacon.h
 * @brief TDMA beacon wire format (spec/02a-coordinated-capacity.md 2a.2).
 *
 * Port of rust lichen-core tdma_beacon.rs and python rpl/tdma_beacon.py:
 * fixed-format uncompressed beacon header (24 bytes) plus trailing
 * Schnorr48 signature (48 bytes, minimum beacon 72).
 *
 * Header layout (all unsigned big-endian):
 *   [0..4)   epoch
 *   [4]      num_slots
 *   [5..9)   sfn
 *   [9..13)  timestamp
 *   [13]     flags (bit0 scheduled, bit1 csma, bit2 ch0_rx, bit3 gnss_pps,
 *            bits 4-7 reserved MUST be zero on send)
 *   [14]     rx_chains
 *   [15..17) setup_window
 *   [17..19) occupied_time
 *   [19]     guard (normative 50 ms)
 *   [20..24) channel_mask (bit0 = CH0)
 *
 * CBOR options (per CDDL, e.g. slot_map / pow_challenge) sit between the
 * header and the trailing beacon signature.
 */

#ifndef LICHEN_LINK_BEACON_H_
#define LICHEN_LINK_BEACON_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LICHEN_BEACON_HEADER_SIZE 24U
#define LICHEN_BEACON_SIG_SIZE 48U
#define LICHEN_BEACON_MIN_SIZE (LICHEN_BEACON_HEADER_SIZE + LICHEN_BEACON_SIG_SIZE)

#define LICHEN_BEACON_FLAG_SCHEDULED 0x01u
#define LICHEN_BEACON_FLAG_CSMA 0x02u
#define LICHEN_BEACON_FLAG_CH0_RX 0x04u
#define LICHEN_BEACON_FLAG_GNSS_PPS 0x08u
#define LICHEN_BEACON_FLAG_RESERVED_MASK 0xF0u

/** Parse/serialize status. */
enum lichen_beacon_status {
	LICHEN_BEACON_OK = 0,
	LICHEN_BEACON_TOO_SHORT = -1,
	LICHEN_BEACON_RESERVED_FLAG_SET = -2,
	LICHEN_BEACON_INVALID_FIELD = -3,
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

/** Parse the 24-byte beacon header. Fails on short buffers and on any
 *  reserved flag bit (4-7) being set. */
enum lichen_beacon_status
lichen_beacon_header_parse(const uint8_t *data, size_t len,
			   struct lichen_beacon_header *out);

/** Serialize the 24-byte beacon header. Fails on short buffers and
 *  reserved flag bits (member widths match the wire widths exactly, so
 *  no field can be out of range; LICHEN_BEACON_INVALID_FIELD is kept
 *  for API stability with the Python/Rust codecs). */
enum lichen_beacon_status
lichen_beacon_header_serialize(const struct lichen_beacon_header *header,
			       uint8_t *out, size_t out_len);

/** Flag predicates (flags byte must already be reserved-mask validated). */
bool lichen_beacon_is_scheduled(uint8_t flags);
bool lichen_beacon_is_csma(uint8_t flags);
bool lichen_beacon_is_ch0_rx(uint8_t flags);
bool lichen_beacon_has_gnss_pps(uint8_t flags);

/** Trailing 48-byte Schnorr48 signature, or NULL when too short. */
const uint8_t *lichen_beacon_signature_bytes(const uint8_t *beacon, size_t len);

/** Everything except the trailing signature, or NULL when too short or
 *  when signed_len is NULL. */
const uint8_t *lichen_beacon_signed_data(const uint8_t *beacon, size_t len,
					 size_t *signed_len);

/** CBOR options between the header and the signature; NULL when the
 *  beacon is minimal (header + signature only), too short, or when
 *  options_len is NULL. */
const uint8_t *lichen_beacon_cbor_options(const uint8_t *beacon, size_t len,
					  size_t *options_len);

#endif /* LICHEN_LINK_BEACON_H_ */
