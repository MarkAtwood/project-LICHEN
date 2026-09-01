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

/* ------------------------------------------------------------------ */
/* DAO TX state: boot-time open/provision over the two-slot primitive  */
/* (C port of rust lichen-rpl persistence.rs DaoTxState, bead          */
/* b7z9.11.2; spec 09 14.2 R-09-014/016).                              */
/* ------------------------------------------------------------------ */

#include <lichen/hal_storage_redundant.h>

#define LICHEN_DAO_TX_SLOT_KEY_A LICHEN_DAO_TX_KEYS_0
#define LICHEN_DAO_TX_SLOT_KEY_B LICHEN_DAO_TX_KEYS_1

/** Persisted DAO TX state after a successful open. */
struct lichen_rpl_dao_tx_state {
	struct lichen_hal_storage_value current;
	uint8_t public_key[32];
	uint8_t local_origin[16];
	uint8_t rpl_instance_id;
	uint8_t dodag_id[16];
	uint64_t last_reserved;
	uint8_t last_signed_dao[LICHEN_DAO_TX_MAX_SIGNED_LEN];
	size_t last_signed_dao_len;
};

/** open outcomes (negative = error, matching Rust taxonomy). */
enum lichen_rpl_dao_tx_open_status {
	LICHEN_DAO_TX_OPEN_OK = 0,
	LICHEN_DAO_TX_OPEN_MISSING = -1,
	LICHEN_DAO_TX_OPEN_CORRUPT = -2,
	LICHEN_DAO_TX_OPEN_KEY_MISMATCH = -3,
	LICHEN_DAO_TX_OPEN_SCOPE_MISMATCH = -4,
	LICHEN_DAO_TX_OPEN_STORAGE_ERROR = -5,
};

/** provision outcomes. */
enum lichen_rpl_dao_tx_provision_status {
	LICHEN_DAO_TX_PROVISION_OK = 0,
	LICHEN_DAO_TX_PROVISION_ALREADY = -1,
	LICHEN_DAO_TX_PROVISION_CORRUPT = -2,
	LICHEN_DAO_TX_PROVISION_STORAGE_ERROR = -3,
};

/**
 * Load the newest valid TX state. Keys rpl.tx.a/rpl.tx.b, magic "DTX2".
 * Validates the persisted key and scope (local_origin, instance, dodag)
 * against the expected values. Requires last_signed_dao_len capacity of
 * nothing: the signed bytes are copied into state (max 255).
 */
enum lichen_rpl_dao_tx_open_status lichen_rpl_dao_tx_open(
	const struct lichen_hal_storage_ops *ops, void *user,
	const uint8_t expected_key[32], const uint8_t local_origin[16],
	uint8_t rpl_instance_id, const uint8_t dodag_id[16],
	struct lichen_rpl_dao_tx_state *state);

/**
 * Provision an absent TX state at sequence 0 with empty signed bytes.
 * ALREADY when a valid state exists for any key; CORRUPT when a record
 * exists but is unparseable (mirrors the Rust Exists->Corrupt mapping).
 */
enum lichen_rpl_dao_tx_provision_status lichen_rpl_dao_tx_provision(
	const struct lichen_hal_storage_ops *ops, void *user,
	const uint8_t expected_key[32], const uint8_t local_origin[16],
	uint8_t rpl_instance_id, const uint8_t dodag_id[16],
	struct lichen_rpl_dao_tx_state *state);

#endif /* LICHEN_RPL_DAO_TX_PERSIST_H_ */
