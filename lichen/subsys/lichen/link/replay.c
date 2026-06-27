/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file replay.c
 * @brief Sliding window replay protection
 *
 * Implements per-peer replay protection using a 64-slot bitmap window.
 * Ported from rust/lichen-link/src/replay.rs
 *
 * The window tracks sequence numbers relative to the highest seen.
 * Bit 0 = last_seq, bit i = last_seq - i. Sequence arithmetic wraps
 * at 65536 with half-space normalization to handle u16 wraparound.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <lichen/replay.h>

void lichen_replay_init(struct lichen_replay_window *rw)
{
	rw->last_seq = 0;
	rw->bitmap = 0;
	rw->initialised = false;
}

bool lichen_replay_check(struct lichen_replay_window *rw, uint16_t seq)
{
	int32_t diff;

	if (!rw->initialised) {
		rw->last_seq = seq;
		rw->bitmap = 1;
		rw->initialised = true;
		return true;
	}

	/* Signed distance: positive means seq is newer than last_seq.
	 * Use i32 arithmetic to handle wrapping correctly. */
	diff = (int32_t)seq - (int32_t)rw->last_seq;

	/*
	 * Half-space comparison for u16 sequence numbers:
	 *
	 * When sequence numbers wrap (0 follows 65535), naive comparison
	 * breaks: 0 < 65535 suggests 0 is "older", but it's actually newer.
	 *
	 * The fix: interpret any distance > 32767 as a backward wrap.
	 * We split the 65536-value space in half around the current position:
	 *   - Differences in [1, 32767] mean seq is ahead (newer)
	 *   - Differences in [-32768, -1] mean seq is behind (older)
	 *
	 * Example: last_seq=65530, seq=5
	 *   Raw diff: 5 - 65530 = -65525 (in i32)
	 *   After normalisation: -65525 + 65536 = 11 (seq is 11 ahead, newer)
	 *
	 * Example: last_seq=5, seq=65530
	 *   Raw diff: 65530 - 5 = 65525 (in i32)
	 *   After normalisation: 65525 - 65536 = -11 (seq is 11 behind, older)
	 *
	 * This works as long as no two valid sequence numbers are ever more
	 * than 32767 apart - a safe assumption when packets arrive in roughly
	 * sequential order with a 64-slot window.
	 */
	if (diff > 32767) {
		diff -= 65536;
	} else if (diff < -32768) {
		diff += 65536;
	}

	if (diff > 0) {
		/* Newer than anything we've seen: advance the window */
		uint32_t shift = (uint32_t)diff;

		if (shift >= 64) {
			/* Entire window is beyond what we've seen; reset it */
			rw->bitmap = 1;
		} else {
			rw->bitmap = (rw->bitmap << shift) | 1;
		}
		rw->last_seq = seq;
		return true;
	}

	if (diff == 0) {
		/* Exact duplicate of last_seq */
		return false;
	}

	/* Older than last_seq: check the bitmask */
	uint32_t offset = (uint32_t)(-diff);

	if (offset >= 64) {
		/* Outside the window - too old to verify, reject */
		return false;
	}

	uint64_t bit = (uint64_t)1 << offset;

	if (rw->bitmap & bit) {
		/* Already seen */
		return false;
	}

	rw->bitmap |= bit;
	return true;
}

void lichen_replay_table_init(struct lichen_replay_table *table)
{
	memset(table, 0, sizeof(*table));
}

struct lichen_replay_window *lichen_replay_get(struct lichen_replay_table *table,
					       const uint8_t eui64[LICHEN_EUI64_SIZE])
{
	int free_slot = -1;

	/* Search for existing entry or first free slot */
	for (int i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (table->peers[i].active) {
			if (memcmp(table->peers[i].eui64, eui64, LICHEN_EUI64_SIZE) == 0) {
				return &table->peers[i].window;
			}
		} else if (free_slot < 0) {
			free_slot = i;
		}
	}

	/* Not found - create new entry if there's room */
	if (free_slot < 0) {
		return NULL;
	}

	memcpy(table->peers[free_slot].eui64, eui64, LICHEN_EUI64_SIZE);
	lichen_replay_init(&table->peers[free_slot].window);
	table->peers[free_slot].active = true;

	return &table->peers[free_slot].window;
}

void lichen_replay_remove(struct lichen_replay_table *table,
			  const uint8_t eui64[LICHEN_EUI64_SIZE])
{
	for (int i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (table->peers[i].active &&
		    memcmp(table->peers[i].eui64, eui64, LICHEN_EUI64_SIZE) == 0) {
			table->peers[i].active = false;
			return;
		}
	}
}
