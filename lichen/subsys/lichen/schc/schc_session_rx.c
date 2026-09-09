/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_session_rx.c
 * @brief In-session fragment rules: replay high-water, session admission,
 *        duplicate/conflict tile semantics (spec 5.6; bead l1qw.3.7.6.4).
 */

#include <lichen/schc_session_rx.h>

#include <string.h>

/** Map (W, FCN) to a flat tile index; false when out of profile. */
static bool rx_index(uint8_t w, uint8_t fcn, size_t *index)
{
	if (w > 1U || fcn > LICHEN_SCHC_RX_OPENER_FCN) {
		return false;
	}
	*index = (size_t)w * (LICHEN_SCHC_RX_OPENER_FCN + 1U) + (size_t)fcn;
	return true;
}

enum lichen_schc_rx_open lichen_schc_rx_admit(uint8_t w, uint8_t fcn,
					      uint32_t counter,
					      uint32_t durable_floor)
{
	if (counter > LICHEN_SCHC_COUNTER_MAX) {
		/* Out of the 24-bit space entirely: never admits. */
		return LICHEN_SCHC_RX_OPEN_EXHAUSTED;
	}
	if (w != LICHEN_SCHC_RX_OPENER_W || fcn != LICHEN_SCHC_RX_OPENER_FCN) {
		/* All-1, ACK REQ, aborts, and every other Regular FCN never
		 * open a session. */
		return LICHEN_SCHC_RX_OPEN_NOT_OPENER;
	}
	if (counter <= durable_floor) {
		return LICHEN_SCHC_RX_OPEN_STALE;
	}
	return LICHEN_SCHC_RX_OPEN;
}

int lichen_schc_rx_open(struct lichen_schc_rx *rx, uint32_t counter)
{
	if (rx == NULL || counter > LICHEN_SCHC_COUNTER_MAX) {
		return -EINVAL;
	}
	memset(rx, 0, sizeof(*rx));
	/* The opening counter is the immutable session-admission floor AND
	 * the initial session-wide high-water. */
	rx->open_floor = counter;
	rx->high_water = counter;
	rx->open = true;
	return 0;
}

enum lichen_schc_rx_verdict
lichen_schc_rx_fragment(struct lichen_schc_rx *rx, uint8_t w, uint8_t fcn,
			const uint8_t *tile, uint8_t tile_len,
			uint32_t counter)
{
	if (rx == NULL || !rx->open) {
		return LICHEN_SCHC_RX_INVALID_COORD;
	}

	size_t index;

	if (!rx_index(w, fcn, &index)) {
		return LICHEN_SCHC_RX_INVALID_COORD;
	}
	if (tile == NULL || tile_len == 0U ||
	    tile_len > LICHEN_SCHC_RX_TILE_LEN) {
		/* A fragment always carries at least one tile byte and at most
		 * one fixed tile; tile_len 0 doubles as the coordinate-empty
		 * marker, so an empty tile cannot be represented, and a length
		 * beyond the fixed tile is a caller contract violation. Both
		 * are rejected. */
		return LICHEN_SCHC_RX_INVALID_COORD;
	}

	/* Counter rules first: an out-of-space, stale, or exhausted counter
	 * is not accepted, so it can neither mutate tiles nor advance the
	 * high-water. */
	if (counter > LICHEN_SCHC_COUNTER_MAX ||
	    rx->high_water == LICHEN_SCHC_COUNTER_MAX) {
		return LICHEN_SCHC_RX_EXHAUSTED;
	}
	if (counter <= rx->high_water) {
		return LICHEN_SCHC_RX_STALE_COUNTER;
	}

	if (rx->tile_len[index] != 0U) {
		/* Already-stored coordinate. */
		if (rx->tile_len[index] == tile_len &&
		    memcmp(rx->tiles[index], tile, tile_len) == 0) {
			/* Idempotent duplicate: discard the tile but STILL
			 * advance the session high-water. */
			rx->high_water = counter;
			return LICHEN_SCHC_RX_DUPLICATE;
		}
		/* Conflicting repeat: fail closed. No tile is cleared,
		 * replaced, or reset; the fragment is not accepted, so the
		 * high-water does not advance. */
		return LICHEN_SCHC_RX_CONFLICT;
	}

	/* Fresh coordinate: store the tile, then advance the high-water. */
	memcpy(rx->tiles[index], tile, tile_len);
	rx->tile_len[index] = tile_len;
	rx->high_water = counter;
	return LICHEN_SCHC_RX_STORED;
}

uint32_t lichen_schc_rx_high_water(const struct lichen_schc_rx *rx)
{
	if (rx == NULL) {
		return 0U;
	}
	return rx->high_water;
}
