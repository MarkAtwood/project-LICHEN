/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/schc_session_rx.h
 * @brief In-session fragment rules for the authenticated SCHC session
 *        authority (spec/03-adaptation.md 5.6, bead l1qw.3.7.6.4).
 *
 * Layers on slices 1-3 (identity/direction, bounded tables, authority
 * lifecycle): this module owns ONE session's reassembly rules - the
 * session-wide replay high-water counter, session admission, and the
 * duplicate/conflicting tile semantics. It assumes the caller has already
 * passed the fragment through the slice-3 gate (authenticated + current
 * generation).
 *
 * Rules (spec 5.6):
 * - Each accepted fragment carries its authenticated unsigned 24-bit link
 *   replay counter (Epoch followed by SeqNum, packed here into the low 24
 *   bits of a uint32_t). The context tracks the session-wide GREATEST
 *   counter under ordinary unsigned ordering: NO wrap; a counter at
 *   LICHEN_SCHC_COUNTER_MAX (0xffffff) cannot be reused or wrapped under
 *   the same key and no further fragment of the session admits.
 * - Only the canonical first Regular Fragment (W=0, FCN=62) with a counter
 *   strictly greater than the durable admission floor OPENS a session.
 *   All-1, ACK REQ, Sender-Abort, Receiver-Abort, and every other Regular
 *   FCN NEVER open a session. The opening counter becomes the immutable
 *   session-admission floor: every subsequently accepted fragment or
 *   control MUST have a strictly greater counter.
 * - Duplicate vs conflict: an authenticated fragment repeating an
 *   already-stored tile coordinate with IDENTICAL bytes is an idempotent
 *   duplicate - discarded WITHOUT clearing/replacing/resetting any stored
 *   tile, but the session high-water STILL advances to the fresh counter.
 *   A repeated coordinate with DIFFERENT bytes MUST fail closed and MUST
 *   NOT reset the context into an attacker-selected partial packet.
 *
 * Single owner, not thread-safe (same contract as slices 2-3). All tile
 * storage is fixed: LICHEN_SCHC_RX_MAX_TILES (126, the two-window profile
 * ceiling) x LICHEN_SCHC_RX_TILE_LEN (179 bytes).
 */

#ifndef LICHEN_SCHC_SESSION_RX_H_
#define LICHEN_SCHC_SESSION_RX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum value of the authenticated 24-bit link replay counter. */
#define LICHEN_SCHC_COUNTER_MAX 0xffffffU

/** Canonical opener: W field of the first Regular Fragment. */
#define LICHEN_SCHC_RX_OPENER_W 0U
/** Canonical opener: FCN of the first Regular Fragment. */
#define LICHEN_SCHC_RX_OPENER_FCN 62U
/** FCN value of the All-1 fragment (never opens a session). */
#define LICHEN_SCHC_RX_ALL1_FCN 63U

/** Maximum tiles across both windows (WINDOW_SIZE 63, W in {0,1}). */
#define LICHEN_SCHC_RX_MAX_TILES 126U
/** Tile size in bytes (spec 5.6). */
#define LICHEN_SCHC_RX_TILE_LEN 179U

/**
 * @brief Verdict of the session-admission gate.
 */
enum lichen_schc_rx_open {
	/** Canonical opener with a fresh counter: a new session may start. */
	LICHEN_SCHC_RX_OPEN = 0,
	/** Not the canonical W=0/FCN=62 opener: never opens a session. */
	LICHEN_SCHC_RX_OPEN_NOT_OPENER,
	/** Canonical opener but counter not strictly above the floor. */
	LICHEN_SCHC_RX_OPEN_STALE,
	/** Counter beyond the 24-bit space (> 0xffffff): never admits. */
	LICHEN_SCHC_RX_OPEN_EXHAUSTED,
};

/**
 * @brief Verdict of one in-session fragment transition.
 */
enum lichen_schc_rx_verdict {
	/** New tile stored; high-water advanced. */
	LICHEN_SCHC_RX_STORED = 0,
	/**
	 * Idempotent duplicate: same coordinate, identical bytes. Stored
	 * tiles untouched; high-water STILL advanced to the fresh counter.
	 */
	LICHEN_SCHC_RX_DUPLICATE,
	/**
	 * Repeated coordinate with DIFFERENT bytes: fail closed. No tile
	 * is cleared, replaced, or reset; high-water NOT advanced (the
	 * fragment is not accepted).
	 */
	LICHEN_SCHC_RX_CONFLICT,
	/**
	 * Counter not strictly greater than the session high-water: stale
	 * replay, not accepted; no state mutation.
	 */
	LICHEN_SCHC_RX_STALE_COUNTER,
	/** Counter at/beyond the 24-bit space (session high-water already
	 *  0xffffff, or the presented counter exceeds it). */
	LICHEN_SCHC_RX_EXHAUSTED,
	/**
	 * Invalid input: coordinate outside the two-window profile
	 * (W>1 or FCN>62), NULL/closed session, NULL tile, or a tile
	 * length outside 1..LICHEN_SCHC_RX_TILE_LEN.
	 */
	LICHEN_SCHC_RX_INVALID_COORD,
};

/**
 * @brief Reassembly state for ONE bounded session.
 */
struct lichen_schc_rx {
	uint8_t tiles[LICHEN_SCHC_RX_MAX_TILES][LICHEN_SCHC_RX_TILE_LEN];
	uint8_t tile_len[LICHEN_SCHC_RX_MAX_TILES]; /**< 0 = coordinate empty. */
	uint32_t high_water;   /**< Session-wide greatest accepted counter. */
	uint32_t open_floor;   /**< Immutable session-admission floor. */
	bool open;             /**< Session admitted by the opener. */
};

/**
 * @brief Session-admission gate.
 *
 * @param w            W field of the candidate fragment.
 * @param fcn          FCN field of the candidate fragment.
 * @param counter      Authenticated 24-bit link replay counter.
 * @param durable_floor Durable admission floor for the session key
 *                      (generation-scoped; 0 when none recorded).
 * @return The admission verdict.
 */
enum lichen_schc_rx_open lichen_schc_rx_admit(uint8_t w, uint8_t fcn,
					      uint32_t counter,
					      uint32_t durable_floor);

/**
 * @brief Open a session.
 *
 * The caller MUST gate with lichen_schc_rx_admit first and only call this on
 * LICHEN_SCHC_RX_OPEN. The opening counter becomes BOTH the immutable
 * session-admission floor AND the initial high-water.
 *
 * @param rx      Session state to initialize (must not be NULL).
 * @param counter Opening counter (must be <= LICHEN_SCHC_COUNTER_MAX).
 * @return 0 on success, -EINVAL on NULL rx or an out-of-range counter.
 */
int lichen_schc_rx_open(struct lichen_schc_rx *rx, uint32_t counter);

/**
 * @brief One in-session fragment transition (regular data tile).
 *
 * Accepts only counters strictly greater than the session high-water (which
 * is also the immutable opening floor's monotonic advance). Stores the tile
 * for a fresh coordinate; idempotently discards a byte-identical duplicate
 * (high-water still advances); fails closed on a conflicting repeat (no
 * mutation at all). Coordinates map W in {0,1} and FCN in 0..62 onto
 * 0..125 (window 0 occupies indices 0..62, window 1 indices 63..125).
 *
 * @param rx      Session state (must be open; must not be NULL).
 * @param w       W field of the fragment.
 * @param fcn     FCN of the fragment (0..62 for a regular tile).
 * @param tile    Tile bytes (must not be NULL).
 * @param tile_len Tile length in bytes (1..LICHEN_SCHC_RX_TILE_LEN; a
 *                 fragment always carries at least one tile byte).
 * @param counter Authenticated 24-bit link replay counter.
 * @return The transition verdict.
 */
enum lichen_schc_rx_verdict
lichen_schc_rx_fragment(struct lichen_schc_rx *rx, uint8_t w, uint8_t fcn,
			const uint8_t *tile, uint8_t tile_len,
			uint32_t counter);

/**
 * @brief Current session-wide high-water counter.
 */
uint32_t lichen_schc_rx_high_water(const struct lichen_schc_rx *rx);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SCHC_SESSION_RX_H_ */
