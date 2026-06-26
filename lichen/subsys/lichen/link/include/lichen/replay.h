/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/replay.h
 * @brief Replay protection window
 *
 * Per-neighbor sliding window to detect and reject replayed frames.
 * Uses a bitmap to track recently seen sequence numbers.
 */

#ifndef LICHEN_REPLAY_H_
#define LICHEN_REPLAY_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default replay window size in bits */
#ifndef CONFIG_LICHEN_LINK_REPLAY_WINDOW
#define CONFIG_LICHEN_LINK_REPLAY_WINDOW 64
#endif

/** Replay window bitmap size in bytes */
#define LICHEN_REPLAY_BITMAP_SIZE (CONFIG_LICHEN_LINK_REPLAY_WINDOW / 8)

/**
 * @brief Replay window state for one neighbor
 */
struct lichen_replay_window {
	uint16_t highest_seq;   /**< Highest accepted sequence number */
	uint8_t bitmap[LICHEN_REPLAY_BITMAP_SIZE]; /**< Seen sequence bitmap */
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
 * @param[in,out] rw     Replay window state
 * @param[in]     seqnum Received sequence number
 * @return true if frame should be accepted, false if replay
 */
bool lichen_replay_accept(struct lichen_replay_window *rw, uint16_t seqnum);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_REPLAY_H_ */
