/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/replay.h
 * @brief Replay protection window
 *
 * Per-neighbor sliding window to detect and reject replayed frames.
 * Uses a 64-bit bitmap to track recently seen sequence numbers.
 *
 * Ported from rust/lichen-link/src/replay.rs
 */

#ifndef LICHEN_REPLAY_H_
#define LICHEN_REPLAY_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum peers to track replay state for */
#ifndef CONFIG_LICHEN_LINK_MAX_NEIGHBORS
#define CONFIG_LICHEN_LINK_MAX_NEIGHBORS 16
#endif

/** Size of EUI-64 address in bytes */
#define LICHEN_EUI64_SIZE 8

/**
 * @brief Replay window state for one peer
 *
 * Tracks a 64-slot sliding window of sequence numbers. Bit 0 represents
 * last_seq, bit i represents last_seq - i. A set bit means that sequence
 * number was already accepted.
 */
struct lichen_replay_window {
	uint16_t last_seq;   /**< Highest accepted sequence number */
	uint64_t bitmap;     /**< 64-bit seen sequence bitmap */
	bool initialised;    /**< True once first sequence accepted */
};

/**
 * @brief Per-peer replay table entry
 */
struct lichen_replay_entry {
	uint8_t eui64[LICHEN_EUI64_SIZE]; /**< Peer's EUI-64 address */
	struct lichen_replay_window window;
	bool active;                       /**< Entry is in use */
};

/**
 * @brief Table of per-peer replay windows
 */
struct lichen_replay_table {
	struct lichen_replay_entry peers[CONFIG_LICHEN_LINK_MAX_NEIGHBORS];
};

/**
 * @brief Initialize a replay window.
 *
 * @param[out] rw Replay window to initialize
 */
void lichen_replay_init(struct lichen_replay_window *rw);

/**
 * @brief Check and update replay window.
 *
 * Call this for every received frame. Returns true if the frame
 * should be accepted (not a replay), false if it should be rejected.
 *
 * The window tracks 64 sequence numbers relative to the highest seen.
 * Sequence numbers wrap at 65536 (u16 space), with half-space
 * arithmetic to handle wraparound correctly.
 *
 * @param[in,out] rw     Replay window state
 * @param[in]     seq    Received sequence number
 * @return true if frame should be accepted, false if replay
 */
bool lichen_replay_check(struct lichen_replay_window *rw, uint16_t seq);

/**
 * @brief Initialize a replay table.
 *
 * @param[out] table Replay table to initialize
 */
void lichen_replay_table_init(struct lichen_replay_table *table);

/**
 * @brief Get or create replay window for a peer.
 *
 * Looks up the replay window for the given EUI-64 address. If no entry
 * exists and there's room in the table, creates a new entry.
 *
 * @param[in,out] table Replay table
 * @param[in]     eui64 Peer's EUI-64 address (8 bytes)
 * @return Pointer to replay window, or NULL if table is full
 */
struct lichen_replay_window *lichen_replay_get(struct lichen_replay_table *table,
					       const uint8_t eui64[LICHEN_EUI64_SIZE]);

/**
 * @brief Remove a peer from the replay table.
 *
 * @param[in,out] table Replay table
 * @param[in]     eui64 Peer's EUI-64 address (8 bytes)
 */
void lichen_replay_remove(struct lichen_replay_table *table,
			  const uint8_t eui64[LICHEN_EUI64_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_REPLAY_H_ */
