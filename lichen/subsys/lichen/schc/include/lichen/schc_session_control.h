/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/schc_session_control.h
 * @brief Control-plane authorization and terminal hold-down for the
 *        authenticated SCHC session authority (spec/03-adaptation.md 5.6;
 *        bead l1qw.3.7.6.5).
 *
 * Final slice: composes slices 1-4 (identity/direction, bounded tables,
 * authority lifecycle, in-session fragment rules) into the integration seam
 * Link/L2 consumes. This module owns control authorization, the
 * ACK-REQ/ACK ambiguity classification, the 4-ACK-then-abort rule, the
 * 60-second tombstone hold-down, and the durable admission-floor handoff.
 *
 * Rules (spec 5.6):
 * - ACK, ACK REQ, Sender-Abort, and Receiver-Abort are issued ONLY from
 *   authenticated state transitions: the slice-3 gate (authenticated +
 *   current generation) is revalidated before every control response, and
 *   no API here accepts a caller-supplied generation token.
 * - A two-octet ACK REQ can be bit-identical to a compressed C=0 ACK; the
 *   message MUST be classified from the authenticated sender role and the
 *   directional Rule ID BEFORE invoking an ACK decoder or mutating sender
 *   state (lichen_schc_control_classify).
 * - The receiver emits at most LICHEN_SCHC_MAX_ACK_RESPONSES (4) ACK
 *   responses per session; a 5th otherwise-valid All-1/ACK REQ gets a
 *   Receiver-Abort and the session enters terminal hold-down.
 * - On completion or an authenticated abort, a tombstone retains the
 *   terminal outcome and session high-water; for
 *   LICHEN_SCHC_HOLDDOWN_SECONDS (60) a repeated authenticated All-1/ACK
 *   REQ with a strictly newer counter replays the same terminal response
 *   idempotently without starting a session, and every authenticated late
 *   message in the current generation advances the tombstone high-water.
 *   After the hold-down the generation-scoped high-water remains as the
 *   bounded durable admission floor.
 * - On authenticated allocation exhaustion the receiver sends ONE
 *   Receiver-Abort for the rejected key and MUST NOT evict or mutate an
 *   active authenticated context (fail-closed allocation).
 *
 * The final terminal ACK bytes are NOT cached: a terminal C=1 ACK is fully
 * determined by (Rule ID, W) and a terminal abort by its class, so the
 * caller regenerates the deterministic bytes from the replayed outcome.
 *
 * Single owner, not thread-safe (same contract as slices 2-4). All storage
 * fixed; no allocation after init.
 */

#ifndef LICHEN_SCHC_SESSION_CONTROL_H_
#define LICHEN_SCHC_SESSION_CONTROL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/errno.h>
#include <lichen/schc_session_authority.h>
#include <lichen/schc_session_rx.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum ACK responses per session before Receiver-Abort (spec 5.6). */
#define LICHEN_SCHC_MAX_ACK_RESPONSES 4U

/** Terminal hold-down (fragmentation inactivity interval), seconds. */
#define LICHEN_SCHC_HOLDDOWN_SECONDS 60U

/**
 * @brief Classification of the ACK-REQ / C=0-ACK ambiguous short form.
 *
 * Both classes retain the data transfer's Rule ID; the AUTHENTICATED SENDER
 * ROLE resolves the direction. Classification happens before any decoder or
 * sender-state mutation.
 */
enum lichen_schc_control_class {
	/** Authenticated sender IS the data sender: the blob is an ACK REQ. */
	LICHEN_SCHC_CLASS_ACK_REQ = 0,
	/** Authenticated sender is the data RECEIVER: the blob is an ACK. */
	LICHEN_SCHC_CLASS_ACK,
	/** Rule ID / role binding is invalid: reject, decode nothing. */
	LICHEN_SCHC_CLASS_INVALID,
};

/**
 * @brief What the receiver must emit (or not) for one control/data step.
 */
enum lichen_schc_control_response {
	/** Emit nothing (silent drop). */
	LICHEN_SCHC_RESP_NONE = 0,
	/** Emit an ACK for the session (whole-packet C=1 or bitmap C=0 is
	 *  the caller's codec decision from reassembly state). */
	LICHEN_SCHC_RESP_ACK,
	/** Emit a Receiver-Abort; the session has entered terminal hold-down. */
	LICHEN_SCHC_RESP_RECEIVER_ABORT,
	/**
	 * Idempotent replay within the hold-down: re-emit the SAME terminal
	 * response recorded in the tombstone (see `outcome`).
	 */
	LICHEN_SCHC_RESP_REPLAY,
};

/**
 * @brief Per-session control state (ACK budget + counter mirror).
 *
 * The tile store itself stays with the slice-4 reassembly owner; this
 * record carries only what control decisions need.
 */
struct lichen_schc_ctl_session {
	struct lichen_schc_ctx_key key;
	uint32_t high_water;  /**< Session-wide greatest accepted counter. */
	uint8_t ack_count;    /**< ACK responses emitted this session. */
	bool occupied;
};

/**
 * @brief The session control authority: slices 2-3 composed, plus the
 *        bounded per-session control records.
 */
struct lichen_schc_control {
	struct lichen_schc_authority auth;       /**< Trust records (slice 3). */
	struct lichen_schc_session_table table;  /**< Bounded state (slice 2). */
	struct lichen_schc_ctl_session sessions[LICHEN_SCHC_MAX_CONTEXTS];
	size_t session_count;
};

/**
 * @brief Initialize the control authority (all substate zeroed).
 */
void lichen_schc_control_init(struct lichen_schc_control *ctl);

/**
 * @brief Classify the ambiguous two-octet form BEFORE any ACK decode.
 *
 * @param data_sender_role Canonical role of the data sender for the
 *                         session this message belongs to.
 * @param sender_role      Authenticated role of THIS message's sender
 *                         (from link-layer signature identity).
 * @param rule_id          Received Rule ID.
 * @return The classification; LICHEN_SCHC_CLASS_INVALID on any binding
 *         failure (including out-of-range roles).
 */
enum lichen_schc_control_class
lichen_schc_control_classify(enum lichen_schc_endpoint data_sender_role,
			     enum lichen_schc_endpoint sender_role,
			     uint8_t rule_id);

/**
 * @brief Install/revoke a remote trust record (slice-3 seam for L2).
 *
 * Thin wrappers so Link/L2 holds exactly one object; generation tokens are
 * still only ever issued internally. Revocation also frees this module's
 * per-session control records for the retired generation (the slice-2
 * tables are invalidated by the authority itself).
 */
int lichen_schc_control_install(struct lichen_schc_control *ctl,
				const struct lichen_schc_identity *remote,
				lichen_schc_generation_t *generation);
int lichen_schc_control_revoke(struct lichen_schc_control *ctl,
			       const struct lichen_schc_identity *remote);

/**
 * @brief Open a session for an authenticated canonical first fragment.
 *
 * Atomic: on any failure NOTHING is mutated (gate, admission, and both
 * allocations are all checked before any write). The ONLY failure that
 * produces a control response is authenticated allocation exhaustion
 * (spec 5.6: one Receiver-Abort for the rejected key, no eviction).
 *
 * @param ctl          Control authority (must not be NULL).
 * @param key          Full reassembly-context key; `generation` must be the
 *                     CURRENT token for `key.remote` (must not be NULL).
 * @param w            W field of the fragment.
 * @param fcn          FCN field of the fragment.
 * @param counter      Authenticated 24-bit link replay counter.
 * @param[out] resp    Control response (must not be NULL).
 * @return 0 on success (check *resp), -EINVAL on NULL args.
 */
int lichen_schc_control_open(struct lichen_schc_control *ctl,
			     const struct lichen_schc_ctx_key *key,
			     uint8_t w, uint8_t fcn, uint32_t counter,
			     enum lichen_schc_control_response *resp);

/**
 * @brief Advance an active session on an authenticated fragment/control.
 *
 * Enforces the strictly-greater session counter (the immutable opening
 * floor's advance), without any tile semantics (the slice-4 owner decides
 * duplicate/conflict on its own store and reports acceptance here only for
 * accepted fragments).
 *
 * @return 0 on accept (high-water advanced), -EINVAL on NULL, -EAGAIN when
 *         the counter is not strictly greater or is exhausted (NOTHING
 *         mutated).
 */
int lichen_schc_control_accept(struct lichen_schc_control *ctl,
			       const struct lichen_schc_ctx_key *key,
			       uint32_t counter);

/**
 * @brief An authenticated All-1 or ACK REQ for the session.
 *
 * Implements the 4-ACK-then-abort rule. On the 5th otherwise-valid request
 * the session is terminated as LICHEN_SCHC_TERMINAL_RECEIVER_ABORT and the
 * terminal hold-down begins (tombstone + durable floor recorded).
 *
 * @param ctl     Control authority.
 * @param key     Session key.
 * @param counter Authenticated 24-bit link replay counter.
 * @param now_s   Current time in seconds (caller clock).
 * @param[out] resp LICHEN_SCHC_RESP_ACK, LICHEN_SCHC_RESP_RECEIVER_ABORT,
 *                  or LICHEN_SCHC_RESP_NONE (stale/unknown: silent drop).
 * @return 0 on success, -EINVAL on NULL args.
 */
int lichen_schc_control_ack_request(struct lichen_schc_control *ctl,
				    const struct lichen_schc_ctx_key *key,
				    uint32_t counter, uint32_t now_s,
				    enum lichen_schc_control_response *resp);

/**
 * @brief An authenticated late message for a tombstoned session.
 *
 * Within the hold-down, a strictly newer counter replays the recorded
 * terminal response idempotently (no session is started) and advances the
 * tombstone high-water; every authenticated late message in the current
 * generation likewise advances it. After the hold-down, or with a stale
 * counter, the message is dropped silently.
 *
 * @param ctl     Control authority.
 * @param key     Session key.
 * @param counter Authenticated 24-bit link replay counter.
 * @param now_s   Current time in seconds.
 * @param[out] resp   LICHEN_SCHC_RESP_REPLAY or LICHEN_SCHC_RESP_NONE.
 * @param[out] outcome Recorded terminal outcome when *resp is REPLAY
 *                     (may be NULL if the caller does not need it).
 * @return 0 on success, -EINVAL on NULL ctl/key/resp.
 */
int lichen_schc_control_late(struct lichen_schc_control *ctl,
			     const struct lichen_schc_ctx_key *key,
			     uint32_t counter, uint32_t now_s,
			     enum lichen_schc_control_response *resp,
			     enum lichen_schc_terminal *outcome);

/**
 * @brief Terminate an active session (completion or authenticated abort).
 *
 * Records the terminal tombstone (outcome, session high-water, now_s) and
 * persists the generation-scoped high-water as the durable admission floor,
 * then frees the session slot. Tombstone/floor writes cannot fail for
 * capacity (bounded eviction), so the transition is all-or-nothing.
 *
 * @return 0 on success, -EINVAL on NULL, -ENOENT if no active session.
 */
int lichen_schc_control_terminate(struct lichen_schc_control *ctl,
				  const struct lichen_schc_ctx_key *key,
				  enum lichen_schc_terminal outcome,
				  uint32_t now_s);

/* ── Read-only metadata for Link/L2 (no mutation paths) ────────────────────*/

/** True when an active session exists for @p key. */
bool lichen_schc_control_session_active(struct lichen_schc_control *ctl,
					const struct lichen_schc_ctx_key *key);

/** Session high-water for @p key (active session or tombstone). */
bool lichen_schc_control_high_water(struct lichen_schc_control *ctl,
				    const struct lichen_schc_ctx_key *key,
				    uint32_t *high_water);

/** ACK responses emitted so far for the active session, if any. */
bool lichen_schc_control_ack_count(struct lichen_schc_control *ctl,
				   const struct lichen_schc_ctx_key *key,
				   uint8_t *ack_count);

/** Durable admission floor for @p key, if recorded. */
bool lichen_schc_control_floor(struct lichen_schc_control *ctl,
			       const struct lichen_schc_ctx_key *key,
			       uint32_t *floor);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SCHC_SESSION_CONTROL_H_ */
