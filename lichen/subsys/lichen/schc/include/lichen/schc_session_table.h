/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/schc_session_table.h
 * @brief Bounded, no-hot-path-allocation state tables for the authenticated
 *        SCHC fragmentation session authority.
 *
 * Spec/03-adaptation.md section 5.6 state containers. This module owns ONLY
 * storage: alloc / lookup / invalidate for reassembly contexts, tombstones,
 * and admission floors. It performs no authentication, replay-counter, or
 * fragmentation logic - higher slices layer that on top. Every entry carries
 * the opaque key-generation token of the authority that admitted it, so a
 * generation change can atomically retire every entry it issued.
 *
 * Bounds (spec 5.6 MUSTs, static fixed storage, no malloc in the hot path):
 * - at most LICHEN_SCHC_MAX_CTX_PER_SIGNER (4) active contexts per remote signer
 * - at most LICHEN_SCHC_MAX_CONTEXTS (64) active contexts globally
 * - at most LICHEN_SCHC_MAX_TOMBSTONES (256) tombstones per direction
 * - at most LICHEN_SCHC_MAX_FLOORS (256) admission floors per direction
 * On authenticated allocation exhaustion the receiver reports failure WITHOUT
 * evicting or mutating an active authenticated context. Tombstone overflow
 * instead evicts the oldest tombstone by terminal-time (spec requirement).
 */

#ifndef LICHEN_SCHC_SESSION_TABLE_H_
#define LICHEN_SCHC_SESSION_TABLE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/errno.h>
#include <lichen/schc_session.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum active reassembly contexts per remote signer (spec 5.6). */
#define LICHEN_SCHC_MAX_CTX_PER_SIGNER 4U
/** Maximum active reassembly contexts globally (spec 5.6). */
#define LICHEN_SCHC_MAX_CONTEXTS 64U
/** Maximum tombstones per direction (spec 5.6). */
#define LICHEN_SCHC_MAX_TOMBSTONES 256U
/** Maximum admission floors per direction (spec 5.6). */
#define LICHEN_SCHC_MAX_FLOORS 256U

/**
 * @brief Ordered reassembly-context key (spec 5.6).
 *
 * The tuple (local_identity, remote_signer_identity, remote_key_generation,
 * fragmentation_rule_id). Two contexts are the same session iff all four
 * fields are equal.
 */
struct lichen_schc_ctx_key {
	struct lichen_schc_identity local;   /**< Receiver's full local key. */
	struct lichen_schc_identity remote;  /**< Authenticated peer signer key. */
	lichen_schc_generation_t generation; /**< Remote trust-record generation. */
	uint8_t rule_id;                     /**< Directional Rule ID (0x78/0x79). */
};

/**
 * @brief Terminal outcome recorded in a tombstone.
 */
enum lichen_schc_terminal {
	LICHEN_SCHC_TERMINAL_COMPLETED = 0, /**< Whole packet verified (C=1). */
	LICHEN_SCHC_TERMINAL_SENDER_ABORT,  /**< Authenticated Sender-Abort. */
	LICHEN_SCHC_TERMINAL_RECEIVER_ABORT, /**< Receiver-Abort issued. */
	LICHEN_SCHC_TERMINAL_EXPIRED,       /**< Inactivity, no terminal exchange. */
};

/**
 * @brief One bounded reassembly-context slot.
 *
 * The opaque `state` payload is owned by the caller (a higher slice); this
 * module only manages slot lifetime and keying.
 */
struct lichen_schc_context {
	struct lichen_schc_ctx_key key;
	bool occupied;
	uint32_t state; /**< Opaque per-context caller payload. */
};

/**
 * @brief One bounded tombstone (terminal hold-down record).
 */
struct lichen_schc_tombstone {
	struct lichen_schc_ctx_key key;
	bool occupied;
	enum lichen_schc_terminal outcome;
	uint32_t high_water;    /**< Session-wide greatest replay counter. */
	uint32_t terminal_time; /**< Terminal timestamp (eviction + hold-down). */
};

/**
 * @brief One bounded durable admission floor.
 */
struct lichen_schc_floor {
	struct lichen_schc_ctx_key key;
	bool occupied;
	uint32_t high_water; /**< Generation-scoped durable admission floor. */
};

/**
 * @brief Bounded session-state tables (single owner, not thread-safe).
 *
 * Caller (the fragmentation authority) serializes access. All storage is
 * fixed; no allocation occurs after the table is zero-initialized.
 */
struct lichen_schc_session_table {
	struct lichen_schc_context contexts[LICHEN_SCHC_MAX_CONTEXTS];
	struct lichen_schc_tombstone tombstones[LICHEN_SCHC_MAX_TOMBSTONES];
	struct lichen_schc_floor floors[LICHEN_SCHC_MAX_FLOORS];
	size_t context_count;
	size_t tombstone_count;
	size_t floor_count;
};

/**
 * @brief Initialize (zero) the session tables.
 *
 * @param table Table to initialize (must not be NULL).
 */
void lichen_schc_table_init(struct lichen_schc_session_table *table);

/**
 * @brief Compare two context keys for equality (all four fields).
 *
 * @return true iff local, remote, generation, and rule_id all match.
 */
bool lichen_schc_ctx_key_equal(const struct lichen_schc_ctx_key *a,
			       const struct lichen_schc_ctx_key *b);

/**
 * @brief Allocate a context for @p key.
 *
 * Fails WITHOUT evicting or mutating an active context when the global table
 * is full (64) or the remote signer already has 4 active contexts. An exact
 * duplicate key returns the existing context (idempotent), not a new slot.
 *
 * @param table Session tables (must not be NULL).
 * @param key   Reassembly-context key (must not be NULL).
 * @param[out] out The allocated (or existing) context slot (must not be NULL;
 *                 on success points into the table, valid until invalidated).
 * @return 0 on success, -EINVAL on NULL args, -ENOBUFS on global-table
 *         exhaustion, -EAGAIN on per-signer cap reached.
 */
int lichen_schc_ctx_alloc(struct lichen_schc_session_table *table,
			  const struct lichen_schc_ctx_key *key,
			  struct lichen_schc_context **out);

/**
 * @brief Find an active context by key.
 *
 * @return Pointer to the context, or NULL if not present.
 */
struct lichen_schc_context *
lichen_schc_ctx_find(struct lichen_schc_session_table *table,
		     const struct lichen_schc_ctx_key *key);

/**
 * @brief Record a terminal tombstone for @p key.
 *
 * Tombstones persist the terminal outcome, session high-water, and terminal
 * time for the hold-down / idempotent-replay window. On overflow the OLDEST
 * tombstone by terminal_time is evicted (spec 5.6 requirement) - unlike
 * context allocation, tombstone recording never fails for capacity.
 *
 * @param table         Session tables (must not be NULL).
 * @param key           Context key being retired (must not be NULL).
 * @param outcome       Terminal outcome.
 * @param high_water    Session-wide greatest replay counter.
 * @param terminal_time Terminal timestamp (for eviction ordering + hold-down).
 * @return 0 on success, -EINVAL on NULL args.
 */
int lichen_schc_tombstone_put(struct lichen_schc_session_table *table,
			      const struct lichen_schc_ctx_key *key,
			      enum lichen_schc_terminal outcome,
			      uint32_t high_water, uint32_t terminal_time);

/**
 * @brief Find a tombstone by key.
 *
 * @return Pointer to the tombstone, or NULL if not present.
 */
struct lichen_schc_tombstone *
lichen_schc_tombstone_find(struct lichen_schc_session_table *table,
			   const struct lichen_schc_ctx_key *key);

/**
 * @brief Record (or raise) the durable admission floor for @p key.
 *
 * The floor persists the generation-scoped high-water after the hold-down.
 * A floor is monotonic: recording a lower-or-equal high_water keeps the
 * existing (higher) floor. On overflow the floor with the SMALLEST high_water
 * is evicted (fail-closed: it discards the least-restrictive admission floor;
 * spec 5.6 mandates eviction order only for tombstones, not floors).
 *
 * @param table      Session tables (must not be NULL).
 * @param key        Context key (must not be NULL).
 * @param high_water Generation-scoped durable admission floor.
 * @return 0 on success, -EINVAL on NULL args.
 */
int lichen_schc_floor_put(struct lichen_schc_session_table *table,
			  const struct lichen_schc_ctx_key *key,
			  uint32_t high_water);

/**
 * @brief Find an admission floor by key.
 *
 * @return Pointer to the floor, or NULL if not present.
 */
struct lichen_schc_floor *
lichen_schc_floor_find(struct lichen_schc_session_table *table,
		       const struct lichen_schc_ctx_key *key);

/**
 * @brief Atomically invalidate every entry in a retired generation.
 *
 * Revocation, replacement, or rotation retires every active context,
 * tombstone, and admission floor issued under @p generation for
 * @p remote - EVEN when the same public key is later reinstalled (the new
 * generation is a distinct token).
 *
 * @param table      Session tables (must not be NULL).
 * @param remote     Remote signer identity (must not be NULL).
 * @param generation Retired generation token.
 * @return Number of entries invalidated (>=0), or -EINVAL on NULL args.
 */
int lichen_schc_table_invalidate_generation(
	struct lichen_schc_session_table *table,
	const struct lichen_schc_identity *remote,
	lichen_schc_generation_t generation);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SCHC_SESSION_TABLE_H_ */
