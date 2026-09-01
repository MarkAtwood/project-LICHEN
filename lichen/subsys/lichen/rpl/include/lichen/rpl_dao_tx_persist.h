/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rpl_dao_tx_persist.h
 * @brief 64-bit DAO origin sequence TX-state payload codec
 *	  (C port of rust lichen-rpl persistence.rs DaoTxState layout,
 *	  spec 09 14.2 R-09-014/016; bead b7z9.11.2).
 *
 * TX-state payload layout (DAO_TX_HEADER_LEN + signed_dao bytes):
 *   [0..32)   public key of this node
 *   [32..48)  local origin address (16 bytes)
 *   [48]      RPL instance ID
 *   [49..65)  DODAG ID (16 bytes)
 *   [65..73)  sequence u64 big-endian
 *   [73..75)  signed-DAO length u16 big-endian (<= MAX_SIGNED_DAO_LEN)
 *   [75..)    exact signed DAO bytes for retransmission
 */

#ifndef LICHEN_RPL_DAO_TX_PERSIST_H_
#define LICHEN_RPL_DAO_TX_PERSIST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LICHEN_DAO_TX_HEADER_LEN 75U
#define LICHEN_DAO_TX_MAX_SIGNED_LEN 255U
#define LICHEN_DAO_TX_KEYS_0 "rpl.tx.a"
#define LICHEN_DAO_TX_KEYS_1 "rpl.tx.b"

/** Encode one TX-state payload into out. Returns the payload length
 *  (LICHEN_DAO_TX_HEADER_LEN + signed_dao_len), or 0 when signed_dao
 *  exceeds LICHEN_DAO_TX_MAX_SIGNED_LEN or out is too small. All pointer
 *  arguments must be non-NULL except signed_dao, which may be NULL when
 *  signed_dao_len is 0 (matching the Rust reference's empty slice).
 */
size_t lichen_rpl_dao_tx_encode(const uint8_t public_key[32],
				const uint8_t local_origin[16],
				uint8_t rpl_instance_id,
				const uint8_t dodag_id[16], uint64_t sequence,
				const uint8_t *signed_dao, size_t signed_dao_len,
				uint8_t *out, size_t out_len);

/** Parsed TX-state header fields. */
struct lichen_rpl_dao_tx_header {
	const uint8_t *public_key;
	const uint8_t *local_origin;
	uint8_t rpl_instance_id;
	const uint8_t *dodag_id;
	uint64_t sequence;
	uint16_t signed_dao_len;
	const uint8_t *signed_dao;
};

/**
 * Parse a persisted TX-state payload (as loaded from a two-slot record).
 * Requires payload_len == LICHEN_DAO_TX_HEADER_LEN + declared signed_dao
 * length (exact, matching the Rust open() length gate) and
 * signed_dao_len <= LICHEN_DAO_TX_MAX_SIGNED_LEN; returns false on any
 * violation. The returned pointers borrow into payload.
 */
bool lichen_rpl_dao_tx_parse(const uint8_t *payload, size_t payload_len,
			     struct lichen_rpl_dao_tx_header *header);

#endif /* LICHEN_RPL_DAO_TX_PERSIST_H_ */
