/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/schc_authority.h
 * @brief Authenticated SCHC session authority: trust-record lifecycle and
 *        generation-currentness gate (spec/03-adaptation.md section 5.6).
 *
 * This module owns the authority side of the spec 5.6 key-generation token:
 * it mints generation tokens, tracks which generation is current for each
 * authenticated remote signer, and atomically retires every slice of state a
 * retired generation issued (reassembly contexts, tombstones including their
 * cached terminal responses, and admission floors) via the bounded session
 * tables.
 *
 * Producer contract (spec 5.6, "authenticated DIO evidence"):
 * - lichen_schc_authority_install() / lichen_schc_authority_revoke() MUST be
 *   called only by the authenticated trust-record path (the RPL/DIO +
 *   link-signature verification owner) with an identity whose authenticity
 *   has already been established. This module cannot and does not re-verify
 *   signatures; it enforces the lifecycle rules on top of that evidence.
 * - No caller-selected authority: the install API accepts NO generation
 *   token. The authority mints each token itself from a private monotonic
 *   issuer counter, so a caller can never choose, replay, or predict a
 *   generation. Tokens are opaque; only equality is meaningful. Token 0
 *   (LICHEN_SCHC_GENERATION_INVALID) is never issued.
 *
 * Lifecycle rules (spec 5.6):
 * - Revocation, replacement, or rotation atomically invalidates EVERY active
 *   context, tombstone, cached response, and admission floor in the retired
 *   generation - EVEN when the same public key is later reinstalled. A
 *   reinstall mints a fresh, distinct generation, so state issued under the
 *   retired token stays unreachable (generation isolation).
 * - Before EVERY context mutation or control response the receiver MUST
 *   revalidate that every applicable generation token is current
 *   (lichen_schc_authority_key_current()). A false verdict means the message
 *   is unauthenticated-or-stale: it MUST be silently dropped, MUST NOT
 *   trigger a control response, and MUST NOT mutate any state. The gate is
 *   read-only and itself guarantees the no-mutation half of that rule.
 *
 * Bounds and failure policy:
 * - At most LICHEN_SCHC_MAX_TRUST_RECORDS concurrent trust records. On
 *   exhaustion install fails closed (-ENOBUFS) WITHOUT evicting or mutating
 *   a current trust record: silently invalidating a peer's sessions is worse
 *   than refusing a new one.
 * - Issuer-counter exhaustion (2^64 mints; unreachable in practice) fails
 *   closed (-EOVERFLOW) rather than wrapping a token.
 *
 * Single owner, not thread-safe; the caller serializes access. All storage
 * is caller-provided and fixed; no allocation occurs after init.
 */

#ifndef LICHEN_SCHC_AUTHORITY_H_
#define LICHEN_SCHC_AUTHORITY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/errno.h>
#include <lichen/schc_session.h>
#include <lichen/schc_session_table.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Maximum concurrent trust records (bound on distinct authenticated
 *        remote signers with live lifecycle state).
 *
 * Matches the largest slice-2 per-class bound (tombstones/floors: 256 per
 * direction); the number of distinct remote signers that can hold durable
 * session state cannot exceed the durable tables themselves.
 */
#define LICHEN_SCHC_MAX_TRUST_RECORDS 256U

/**
 * @brief Reserved generation token: never issued, never current.
 *
 * Zeroed state therefore never accidentally validates, and failure paths can
 * publish a value that fails every currentness check.
 */
#define LICHEN_SCHC_GENERATION_INVALID ((lichen_schc_generation_t)0U)

/**
 * @brief One trust record: the current generation for a remote signer.
 */
struct lichen_schc_trust_record {
	struct lichen_schc_identity remote;   /**< Authenticated peer key. */
	lichen_schc_generation_t generation;  /**< Current minted token. */
	bool occupied;
};

/**
 * @brief The SCHC session authority (single owner, not thread-safe).
 *
 * @param table is caller-owned and MUST outlive the authority; it is the
 *        state retired on generation changes.
 */
struct lichen_schc_authority {
	struct lichen_schc_session_table *table;
	struct lichen_schc_trust_record records[LICHEN_SCHC_MAX_TRUST_RECORDS];
	size_t record_count;
	lichen_schc_generation_t next_generation; /**< Private issuer counter. */
};

/**
 * @brief Initialize the authority and bind it to its session tables.
 *
 * @param auth  Authority to initialize (must not be NULL).
 * @param table Session tables the authority retires state from (must not be
 *              NULL; caller-owned, must outlive @p auth). A NULL table is
 *              rejected by every later entry point: an authority without the
 *              state it retires cannot honor the atomic-invalidation rule.
 */
void lichen_schc_authority_init(struct lichen_schc_authority *auth,
				struct lichen_schc_session_table *table);

/**
 * @brief Install (or rotate/replace) the trust record for a remote signer.
 *
 * Mints a FRESH generation token and makes it current for @p remote. If a
 * record already exists (replacement/rotation), the retired generation is
 * fully invalidated in the bound tables - contexts, tombstones, cached
 * responses, floors - BEFORE the new token is published, so the transition
 * is all-or-nothing and old-generation state is unreachable afterwards.
 *
 * @param auth  Authority (must not be NULL, must be initialized).
 * @param remote Authenticated remote signer identity from the DIO/trust
 *               path (must not be NULL).
 * @param[out] out_generation The minted token (must not be NULL). Set to
 *               LICHEN_SCHC_GENERATION_INVALID on every failure after
 *               argument validation (untouched when an argument is NULL).
 * @return 0 on success; -EINVAL on NULL args or unbound authority;
 *         -ENOBUFS when the trust-record table is full (fail closed, no
 *         eviction); -EOVERFLOW on issuer-counter exhaustion (fail closed).
 */
int lichen_schc_authority_install(struct lichen_schc_authority *auth,
				  const struct lichen_schc_identity *remote,
				  lichen_schc_generation_t *out_generation);

/**
 * @brief Revoke a remote signer's trust record without replacement.
 *
 * Atomically invalidates every entry in the retired generation, then drops
 * the record. Revoking an unknown signer retires nothing and succeeds
 * (idempotent).
 *
 * @param auth  Authority (must not be NULL, must be initialized).
 * @param remote Remote signer being revoked (must not be NULL).
 * @return 0 on success (including the no-op case); -EINVAL on NULL args or
 *         unbound authority.
 */
int lichen_schc_authority_revoke(struct lichen_schc_authority *auth,
				 const struct lichen_schc_identity *remote);

/**
 * @brief Currentness gate: is @p generation the current token for @p remote?
 *
 * Read-only; mutates nothing. LICHEN_SCHC_GENERATION_INVALID is never
 * current, and a generation minted for a different remote is never current
 * here.
 *
 * @return true iff a trust record exists for @p remote and its current
 *         token equals @p generation.
 */
bool lichen_schc_authority_generation_current(
	const struct lichen_schc_authority *auth,
	const struct lichen_schc_identity *remote,
	lichen_schc_generation_t generation);

/**
 * @brief Revalidation gate for a context key (spec 5.6 MUST).
 *
 * The receiver MUST call this before EVERY context mutation or control
 * response addressing @p key. A false verdict means the message is stale or
 * unauthenticated: drop it silently - no control response, no state
 * mutation. Read-only; mutates nothing.
 *
 * @return true iff the key's generation token is current for its remote
 *         signer.
 */
bool lichen_schc_authority_key_current(
	const struct lichen_schc_authority *auth,
	const struct lichen_schc_ctx_key *key);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SCHC_AUTHORITY_H_ */
