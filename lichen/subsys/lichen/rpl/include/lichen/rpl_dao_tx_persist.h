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

/** reserve_next / clear_transmitted outcomes. */
enum lichen_rpl_dao_tx_tx_status {
	LICHEN_DAO_TX_TX_OK = 0,
	LICHEN_DAO_TX_TX_INVALID_STATE = -1,
	LICHEN_DAO_TX_TX_EXHAUSTED = -2,
	LICHEN_DAO_TX_TX_STORAGE_ERROR = -3,
	/* Storage state changed under the caller (re-open and retry);
	 * distinct from INVALID_STATE per the Rust taxonomy. */
	LICHEN_DAO_TX_TX_STALE = -4,
	LICHEN_DAO_TX_TX_CORRUPT = -5,
};

/**
 * Reserve the next origin sequence: persist generation+1 carrying
 * sequence = last_reserved + 1 BEFORE the DAO is built (crash-safe
 * ordering; rust reserve_next). Returns the reserved sequence via *next.
 * EXHAUSTED at u64 max (no wrap).
 */
enum lichen_rpl_dao_tx_tx_status lichen_rpl_dao_tx_reserve_next(
	const struct lichen_hal_storage_ops *ops, void *user,
	struct lichen_rpl_dao_tx_state *state, uint8_t *record,
	size_t record_len, uint64_t *next);

/**
 * Clear the exact retry bytes after successful transmission: persist
 * the same sequence with empty signed bytes. INVALID_STATE when no
 * signed bytes are pending.
 */
enum lichen_rpl_dao_tx_tx_status lichen_rpl_dao_tx_clear_transmitted(
	const struct lichen_hal_storage_ops *ops, void *user,
	struct lichen_rpl_dao_tx_state *state, uint8_t *record,
	size_t record_len);

/** finalize_signed outcomes (rust DaoTxError parity). */
enum lichen_rpl_dao_tx_finalize_status {
	LICHEN_DAO_TX_FINALIZE_OK = 0,
	LICHEN_DAO_TX_FINALIZE_INVALID_STATE = -1,
	LICHEN_DAO_TX_FINALIZE_OVERSIZED = -2,
	LICHEN_DAO_TX_FINALIZE_ENCODING = -3,
	LICHEN_DAO_TX_FINALIZE_EXHAUSTED = -4,
	LICHEN_DAO_TX_FINALIZE_STALE = -5,
	LICHEN_DAO_TX_FINALIZE_CORRUPT = -6,
	LICHEN_DAO_TX_FINALIZE_STORAGE_ERROR = -7,
};

/**
 * Validate a signed DAO envelope (rust message.rs
 * SignedDaoEnvelope::from_bytes) and extract the origin sequence.
 *
 * Requirements: DAO base (D=1, 20 bytes), flags zero, exactly one
 * terminal 0x12 origin-signature option (56 bytes: sequence u64 BE
 * nonzero + Schnorr48), only PAD1/generalized-Target/Transit(20)/
 * TargetDescriptor(4) options before it. Returns 0 and writes *sequence
 * on success; negative on any violation.
 */
int lichen_rpl_dao_envelope_sequence(const uint8_t *data, size_t len,
				     uint64_t *sequence);

/**
 * Persist the exact signed DAO bytes for `sequence` before they may be
 * transmitted (rust finalize_signed). Rejects: sequence mismatch with
 * the reserved value, oversized signed DAO, envelope validation failure,
 * already-finalized equal-sequence rebuild, u64 generation exhaustion.
 */
enum lichen_rpl_dao_tx_finalize_status lichen_rpl_dao_tx_finalize_signed(
	const struct lichen_hal_storage_ops *ops, void *user,
	struct lichen_rpl_dao_tx_state *state, uint64_t sequence,
	const uint8_t *signed_dao, size_t signed_dao_len, uint8_t *record,
	size_t record_len);

#endif /* LICHEN_RPL_DAO_TX_PERSIST_H_ */
