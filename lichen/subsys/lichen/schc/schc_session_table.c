/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_session_table.c
 * @brief Bounded state tables for the SCHC session authority (spec 5.6).
 */

#include <lichen/schc_session_table.h>

#include <string.h>

void lichen_schc_table_init(struct lichen_schc_session_table *table)
{
	if (table == NULL) {
		return;
	}
	memset(table, 0, sizeof(*table));
}

bool lichen_schc_ctx_key_equal(const struct lichen_schc_ctx_key *a,
			       const struct lichen_schc_ctx_key *b)
{
	if (a == NULL || b == NULL) {
		return false;
	}
	return a->rule_id == b->rule_id && a->generation == b->generation &&
	       memcmp(a->local.pubkey, b->local.pubkey,
		      LICHEN_SCHC_IDENTITY_LEN) == 0 &&
	       memcmp(a->remote.pubkey, b->remote.pubkey,
		      LICHEN_SCHC_IDENTITY_LEN) == 0;
}

struct lichen_schc_context *
lichen_schc_ctx_find(struct lichen_schc_session_table *table,
		     const struct lichen_schc_ctx_key *key)
{
	if (table == NULL || key == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < LICHEN_SCHC_MAX_CONTEXTS; i++) {
		if (table->contexts[i].occupied &&
		    lichen_schc_ctx_key_equal(&table->contexts[i].key, key)) {
			return &table->contexts[i];
		}
	}
	return NULL;
}

int lichen_schc_ctx_alloc(struct lichen_schc_session_table *table,
			  const struct lichen_schc_ctx_key *key,
			  struct lichen_schc_context **out)
{
	if (table == NULL || key == NULL || out == NULL) {
		return -EINVAL;
	}

	/* Idempotent: an exact duplicate key returns the existing slot. */
	struct lichen_schc_context *existing = lichen_schc_ctx_find(table, key);

	if (existing != NULL) {
		*out = existing;
		return 0;
	}

	/* Per-signer cap: at most LICHEN_SCHC_MAX_CTX_PER_SIGNER active
	 * contexts for this remote signer. */
	size_t per_signer = 0;

	for (size_t i = 0; i < LICHEN_SCHC_MAX_CONTEXTS; i++) {
		if (table->contexts[i].occupied &&
		    memcmp(table->contexts[i].key.remote.pubkey, key->remote.pubkey,
			   LICHEN_SCHC_IDENTITY_LEN) == 0) {
			per_signer++;
		}
	}
	if (per_signer >= LICHEN_SCHC_MAX_CTX_PER_SIGNER) {
		/* Fail WITHOUT evicting/mutating an active context. */
		return -EAGAIN;
	}

	/* Global cap. */
	if (table->context_count >= LICHEN_SCHC_MAX_CONTEXTS) {
		return -ENOBUFS;
	}

	for (size_t i = 0; i < LICHEN_SCHC_MAX_CONTEXTS; i++) {
		if (!table->contexts[i].occupied) {
			table->contexts[i].key = *key;
			table->contexts[i].state = 0U;
			table->contexts[i].occupied = true;
			table->context_count++;
			*out = &table->contexts[i];
			return 0;
		}
	}
	/* Unreachable: context_count < MAX implies a free slot, but the count
	 * and slot scan are kept independent for defense in depth. */
	return -ENOBUFS;
}

int lichen_schc_tombstone_put(struct lichen_schc_session_table *table,
			      const struct lichen_schc_ctx_key *key,
			      enum lichen_schc_terminal outcome,
			      uint32_t high_water, uint32_t terminal_time)
{
	if (table == NULL || key == NULL) {
		return -EINVAL;
	}

	/* Exact duplicate key: refresh in place (reterminal of same session). */
	struct lichen_schc_tombstone *existing =
		lichen_schc_tombstone_find(table, key);
	struct lichen_schc_tombstone *slot = existing;

	if (slot == NULL) {
		/* Find a free slot, else evict the OLDEST by terminal_time. */
		if (table->tombstone_count < LICHEN_SCHC_MAX_TOMBSTONES) {
			for (size_t i = 0; i < LICHEN_SCHC_MAX_TOMBSTONES; i++) {
				if (!table->tombstones[i].occupied) {
					slot = &table->tombstones[i];
					table->tombstone_count++;
					break;
				}
			}
		} else {
			/* Overflow: evict oldest tombstone by terminal-time
			 * (spec 5.6 requirement). */
			size_t oldest = 0;
			uint32_t oldest_time = UINT32_MAX;

			for (size_t i = 0; i < LICHEN_SCHC_MAX_TOMBSTONES; i++) {
				if (table->tombstones[i].occupied &&
				    table->tombstones[i].terminal_time < oldest_time) {
					oldest_time = table->tombstones[i].terminal_time;
					oldest = i;
				}
			}
			slot = &table->tombstones[oldest];
		}
	}

	if (existing != NULL) {
		/* Reterminal of the same session (e.g. an idempotent replay of a
		 * terminal frame within the hold-down): the high-water is
		 * monotonic ("session-wide GREATEST replay counter"), so a
		 * replayed captured terminal frame MUST NOT regress it. Advance
		 * the terminal_time to the freshest observation (extends the
		 * eviction/hold-down clock); a replay carrying its original
		 * (older) terminal_time MUST NOT shorten the window either. */
		if (high_water > slot->high_water) {
			slot->high_water = high_water;
		}
		slot->outcome = outcome;
		if (terminal_time > slot->terminal_time) {
			slot->terminal_time = terminal_time;
		}
		return 0;
	}

	/* As in context allocation, a failed scan must not dereference NULL
	 * even if the cached count and occupancy are inconsistent. */
	if (slot == NULL) {
		return -ENOBUFS;
	}
	slot->key = *key;
	slot->outcome = outcome;
	slot->high_water = high_water;
	slot->terminal_time = terminal_time;
	slot->occupied = true;
	return 0;
}

struct lichen_schc_tombstone *
lichen_schc_tombstone_find(struct lichen_schc_session_table *table,
			   const struct lichen_schc_ctx_key *key)
{
	if (table == NULL || key == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < LICHEN_SCHC_MAX_TOMBSTONES; i++) {
		if (table->tombstones[i].occupied &&
		    lichen_schc_ctx_key_equal(&table->tombstones[i].key, key)) {
			return &table->tombstones[i];
		}
	}
	return NULL;
}

int lichen_schc_floor_put(struct lichen_schc_session_table *table,
			  const struct lichen_schc_ctx_key *key,
			  uint32_t high_water)
{
	if (table == NULL || key == NULL) {
		return -EINVAL;
	}

	struct lichen_schc_floor *existing = lichen_schc_floor_find(table, key);

	if (existing != NULL) {
		/* Monotonic: only raise the floor, never lower it. */
		if (high_water > existing->high_water) {
			existing->high_water = high_water;
		}
		return 0;
	}

	struct lichen_schc_floor *slot = NULL;

	if (table->floor_count < LICHEN_SCHC_MAX_FLOORS) {
		for (size_t i = 0; i < LICHEN_SCHC_MAX_FLOORS; i++) {
			if (!table->floors[i].occupied) {
				slot = &table->floors[i];
				table->floor_count++;
				break;
			}
		}
	} else {
		/* Overflow: evict the floor with the SMALLEST high_water (the
		 * most-stale admission floor; a new session needs a strictly
		 * greater counter than the floor, so evicting the lowest floor
		 * discards the least-restrictive record). */
		size_t lowest = 0;
		uint32_t lowest_hw = UINT32_MAX;

		for (size_t i = 0; i < LICHEN_SCHC_MAX_FLOORS; i++) {
			if (table->floors[i].occupied &&
			    table->floors[i].high_water < lowest_hw) {
				lowest_hw = table->floors[i].high_water;
				lowest = i;
			}
		}
		slot = &table->floors[lowest];
	}

	/* A count below capacity must agree with the free-slot scan. */
	if (slot == NULL) {
		return -ENOBUFS;
	}
	slot->key = *key;
	slot->high_water = high_water;
	slot->occupied = true;
	return 0;
}

struct lichen_schc_floor *
lichen_schc_floor_find(struct lichen_schc_session_table *table,
		       const struct lichen_schc_ctx_key *key)
{
	if (table == NULL || key == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < LICHEN_SCHC_MAX_FLOORS; i++) {
		if (table->floors[i].occupied &&
		    lichen_schc_ctx_key_equal(&table->floors[i].key, key)) {
			return &table->floors[i];
		}
	}
	return NULL;
}

int lichen_schc_table_invalidate_generation(
	struct lichen_schc_session_table *table,
	const struct lichen_schc_identity *remote,
	lichen_schc_generation_t generation)
{
	if (table == NULL || remote == NULL) {
		return -EINVAL;
	}

	int invalidated = 0;

	for (size_t i = 0; i < LICHEN_SCHC_MAX_CONTEXTS; i++) {
		if (table->contexts[i].occupied &&
		    table->contexts[i].key.generation == generation &&
		    memcmp(table->contexts[i].key.remote.pubkey, remote->pubkey,
			   LICHEN_SCHC_IDENTITY_LEN) == 0) {
			table->contexts[i].occupied = false;
			table->context_count--;
			invalidated++;
		}
	}
	for (size_t i = 0; i < LICHEN_SCHC_MAX_TOMBSTONES; i++) {
		if (table->tombstones[i].occupied &&
		    table->tombstones[i].key.generation == generation &&
		    memcmp(table->tombstones[i].key.remote.pubkey, remote->pubkey,
			   LICHEN_SCHC_IDENTITY_LEN) == 0) {
			table->tombstones[i].occupied = false;
			table->tombstone_count--;
			invalidated++;
		}
	}
	for (size_t i = 0; i < LICHEN_SCHC_MAX_FLOORS; i++) {
		if (table->floors[i].occupied &&
		    table->floors[i].key.generation == generation &&
		    memcmp(table->floors[i].key.remote.pubkey, remote->pubkey,
			   LICHEN_SCHC_IDENTITY_LEN) == 0) {
			table->floors[i].occupied = false;
			table->floor_count--;
			invalidated++;
		}
	}
	return invalidated;
}
