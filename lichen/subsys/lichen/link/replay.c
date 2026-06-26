/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file replay.c
 * @brief Sliding window replay protection
 *
 * Implements RFC 4303 style anti-replay with a sliding window bitmap.
 */

#include <lichen/replay.h>
#include <string.h>

#define WINDOW_SIZE CONFIG_LICHEN_LINK_REPLAY_WINDOW

void lichen_replay_init(struct lichen_replay_window *rw)
{
	rw->highest_seq = 0;
	memset(rw->bitmap, 0, sizeof(rw->bitmap));
}

bool lichen_replay_accept(struct lichen_replay_window *rw, uint16_t seqnum)
{
	/* Handle first packet */
	if (rw->highest_seq == 0 && rw->bitmap[0] == 0) {
		rw->highest_seq = seqnum;
		/* Mark this sequence as seen */
		rw->bitmap[0] = 1;
		return true;
	}

	/* Check if seqnum is ahead of window */
	if (seqnum > rw->highest_seq) {
		uint16_t diff = seqnum - rw->highest_seq;

		if (diff >= WINDOW_SIZE) {
			/* Far ahead: reset window */
			memset(rw->bitmap, 0, sizeof(rw->bitmap));
		} else {
			/* Shift window: move bitmap left by diff positions */
			for (int i = WINDOW_SIZE - 1; i >= 0; i--) {
				int src_bit = i - (int)diff;
				int byte_idx = i / 8;
				int bit_idx = i % 8;
				int src_byte = src_bit / 8;
				int src_bit_idx = src_bit % 8;

				if (src_bit >= 0) {
					if (rw->bitmap[src_byte] & (1 << src_bit_idx)) {
						rw->bitmap[byte_idx] |= (1 << bit_idx);
					} else {
						rw->bitmap[byte_idx] &= ~(1 << bit_idx);
					}
				} else {
					rw->bitmap[byte_idx] &= ~(1 << bit_idx);
				}
			}
		}

		rw->highest_seq = seqnum;
		/* Mark position 0 as seen (current packet) */
		rw->bitmap[0] |= 1;
		return true;
	}

	/* Check if seqnum is within window */
	uint16_t age = rw->highest_seq - seqnum;

	if (age >= WINDOW_SIZE) {
		/* Too old: reject */
		return false;
	}

	/* Check if already seen */
	int byte_idx = age / 8;
	int bit_idx = age % 8;

	if (rw->bitmap[byte_idx] & (1 << bit_idx)) {
		/* Already seen: replay */
		return false;
	}

	/* Mark as seen */
	rw->bitmap[byte_idx] |= (1 << bit_idx);
	return true;
}
