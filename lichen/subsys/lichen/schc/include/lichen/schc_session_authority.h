/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/schc_session_authority.h
 * @brief Authenticated SCHC session authority: trust-record lifecycle and
 *        generation currentness gate (spec/03-adaptation.md 5.6).
 *
 * This module owns the authority lifecycle slices 1-2 prepared for: it
 * installs SCHC session policy ONLY from authenticated DIO evidence (the
 * caller presents a remote signer identity whose DIO signature it has
 * already verified; no caller-selected generation token is ever accepted),
 * revalidates generation currentness before any context mutation or control
 * response, and atomically retires every context, tombstone, cached
 * response, and admission floor of a retired generation - even when the
 * same public key is later reinstalled (generation isolation).
 *
 * Authority rules (spec 5.6):
 * - Generation tokens are ISSUED BY THIS MODULE from a monotonic counter;
 *   no API accepts a caller-supplied token, so no caller can select a
 *   previous (retired) generation or forge currentness. Token 0 never
 *   identifies an installed trust record.
 * - "Before every context mutation or control response, the receiver MUST
 *   revalidate that every applicable generation token is current": the gate
 *   (lichen_schc_authority_gate) is the single choke point for that
 *   revalidation.
 * - Revocation/replacement/rotation retires the old generation FIRST at the
 *   trust record (so it immediately fails the gate) and then atomically
 *   invalidates every class of bounded state issued under it.
 * - An unauthenticated fragment is silently dropped and MUST NOT cause a
 *   control response; a fragment carrying a retired generation is treated
 *   identically. Neither path mutates any state - the gate takes no table
 *   pointer, so a drop decision CANNOT mutate bounded state.
 *
 * Single owner, not thread-safe: the fragmentation authority serializes
 * access (same contract as the slice-2 state tables). All storage is
 * fixed; no allocation occurs after init.
 */

#ifndef LICHEN_SCHC_SESSION_AUTHORITY_H_
#define LICHEN_SCHC_SESSION_AUTHORITY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/errno.h>
#include <lichen/schc_session.h>
#include <lichen/schc_session_table.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum simultaneous remote trust records (bounded, fail-closed). */
#define LICHEN_SCHC_MAX_AUTHORITIES 32U

/**
 * @brief One remote trust record: the authority-issued current generation
 *        for one authenticated remote signer.
 */
struct lichen_schc_authority_entry {
	struct lichen_schc_identity remote;  /**< Authenticated signer key. */
	lichen_schc_generation_t generation; /**< Current issued token. */
	bool occupied;
};

/**
 * @brief The session authority: bounded trust records plus the monotonic
 *        token issuer.
 */
struct lichen_schc_authority {
	struct lichen_schc_authority_entry entries[LICHEN_SCHC_MAX_AUTHORITIES];
	lichen_schc_generation_t next_generation; /**< Next token to issue. */
	size_t count;
};

/**
 * @brief Verdict of the generation-currentness admission gate.
 */
enum lichen_schc_gate_verdict {
	/** Authenticated fragment with a current generation: proceed. */
	LICHEN_SCHC_GATE_ADMIT = 0,
	/**
	 * Unauthenticated fragment: silently drop. MUST NOT cause a control
	 * response (spec 5.6) and MUST NOT mutate any state.
	 */
	LICHEN_SCHC_GATE_DROP_SILENT,
	/**
	 * Authenticated fragment carrying a retired or never-installed
	 * generation: drop identically to an unauthenticated fragment (no
	 * control response, no mutation) - its generation is not current.
	 */
	LICHEN_SCHC_GATE_DROP_STALE,
};

/**
 * @brief Initialize the authority (no trust records, token issuer at 1).
 *
 * Token 0 never identifies an installed record, so a zeroed context key can
 * never pass the currentness gate against a fresh authority.
 *
 * @param auth Authority to initialize (must not be NULL).
 */
void lichen_schc_authority_init(struct lichen_schc_authority *auth);

/**
 * @brief Install SCHC session policy for an authenticated remote signer.
 *
 * The caller MUST present @p remote only as authenticated DIO evidence (a
 * DIO whose link-layer signature verified under this key). The generation
 * token is issued internally; there is deliberately no parameter through
 * which a caller could select one.
 *
 * First install of @p remote creates the trust record. A later install of
 * the SAME key (replacement/rotation) retires the old generation: the trust
 * record flips to a fresh token FIRST (so the old generation immediately
 * fails the gate) and then @p table is atomically invalidated of every
 * context, tombstone, cached response, and admission floor issued under the
 * retired generation. The same key therefore NEVER resumes its retired
 * generation (generation isolation).
 *
 * @param auth          Session authority (must not be NULL).
 * @param table         Bounded state tables to atomically retire the
 *                      replaced generation from (must not be NULL; pass a
 *                      zero-initialized table if none exists yet).
 * @param remote        Authenticated remote signer identity (must not be
 *                      NULL).
 * @param[out] generation Issued current generation token (must not be
 *                      NULL).
 * @return 0 on success, -EINVAL on NULL args, -ENOBUFS when the bounded
 *         trust-record table is full (fail-closed: no live record is
 *         evicted), -EOVERFLOW when the token issuer is exhausted.
 */
int lichen_schc_authority_install(struct lichen_schc_authority *auth,
				  struct lichen_schc_session_table *table,
				  const struct lichen_schc_identity *remote,
				  lichen_schc_generation_t *generation);

/**
 * @brief Revoke the trust record for @p remote.
 *
 * Retires the current generation (gate fails it immediately) and atomically
 * invalidates every entry issued under it in @p table. Revocation is
 * idempotent: an unknown remote invalidates nothing and returns 0, so a
 * replayed revocation DIO is harmless.
 *
 * @param auth   Session authority (must not be NULL).
 * @param table  Bounded state tables (must not be NULL).
 * @param remote Remote signer identity to revoke (must not be NULL).
 * @return Number of table entries invalidated (>=0), or -EINVAL on NULL
 *         args.
 */
int lichen_schc_authority_revoke(struct lichen_schc_authority *auth,
				 struct lichen_schc_session_table *table,
				 const struct lichen_schc_identity *remote);

/**
 * @brief Revalidate that @p generation is the current token for @p remote.
 *
 * This is the revalidation the spec requires BEFORE every context mutation
 * or control response.
 *
 * @param auth       Session authority (must not be NULL).
 * @param remote     Remote signer identity (must not be NULL).
 * @param generation Generation token presented by the message.
 * @return true iff @p remote is installed and @p generation equals its
 *         current token.
 */
bool lichen_schc_authority_current(
	const struct lichen_schc_authority *auth,
	const struct lichen_schc_identity *remote,
	lichen_schc_generation_t generation);

/**
 * @brief Admission gate for one inbound fragment/control message.
 *
 * Classifies the message WITHOUT any state access beyond read-only
 * currentness: the gate takes no table pointer, so a drop decision cannot
 * mutate bounded state, and a drop never produces a control response.
 *
 * @param auth          Session authority (must not be NULL).
 * @param remote        Authenticated remote signer identity (must not be
 *                      NULL).
 * @param generation    Generation token the message binds.
 * @param authenticated true iff the fragment passed link-layer signature
 *                      authentication (and replay protection).
 * @return LICHEN_SCHC_GATE_ADMIT only for an authenticated message with a
 *         current generation; otherwise the drop verdict.
 */
enum lichen_schc_gate_verdict
lichen_schc_authority_gate(const struct lichen_schc_authority *auth,
			   const struct lichen_schc_identity *remote,
			   lichen_schc_generation_t generation,
			   bool authenticated);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SCHC_SESSION_AUTHORITY_H_ */
