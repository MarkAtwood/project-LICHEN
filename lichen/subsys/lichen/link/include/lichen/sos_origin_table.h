/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/sos_origin_table.h
 * @brief Per-origin SOS accounting: monotonic Origin Sequence gate +
 *        per-origin rate-limit state (spec 18.4.1)
 *
 * Header-only bounded table so the CoAP server and host unit tests share
 * one implementation. Each origin (keyed by its 8-byte node IID) gets its
 * own highest-accepted Origin Sequence and its own rate-limit state, so:
 *  - a stale-but-valid replay from one origin is rejected (monotonic gate)
 *  - one chatty origin cannot consume another origin's 3/hour budget
 *
 * The table is caller-owned storage (no globals), so it is trivially
 * testable and the server keeps exactly one static instance.
 */

#ifndef LICHEN_SOS_ORIGIN_TABLE_H_
#define LICHEN_SOS_ORIGIN_TABLE_H_

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <lichen/sos_ratelimit.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SOS_ORIGIN_TABLE_MAX
/** Bounded origin slots; LRU eviction beyond this. */
#define SOS_ORIGIN_TABLE_MAX 16
#endif

struct sos_origin_entry {
	bool in_use;
	/** True once any sequence has been accepted (closes the seq-0
	 * replay gap: last_seq==0 alone cannot distinguish "no prior" from
	 * "accepted seq 0"). */
	bool accepted;
	uint8_t iid[8];
	/** Highest Origin Sequence accepted from this origin (gate). */
	uint64_t last_seq;
	struct sos_ratelimit_state rl;
};

struct sos_origin_table {
	struct sos_origin_entry entries[SOS_ORIGIN_TABLE_MAX];
};

static inline void sos_origin_table_init(struct sos_origin_table *table)
{
	if (table == NULL) {
		return;
	}
	memset(table, 0, sizeof(*table));
}

/**
 * Most-recent accepted-alert timestamp for an entry (0 = never active).
 * Used as the true recency metric for LRU eviction; an entry with no
 * recorded alerts is always the preferred eviction victim.
 */
static inline int64_t sos_origin_last_activity(const struct sos_origin_entry *e)
{
	if (e == NULL || !e->in_use || e->rl.alert_count == 0U) {
		return 0;
	}
	return e->rl.alert_times[e->rl.alert_count - 1U];
}

/**
 * Find the entry for iid, allocating one (free slot preferred, else LRU
 * eviction of the least-recently-active origin) when absent.
 *
 * @param[in,out] table  Origin table
 * @param[in]     iid    8-byte origin node IID
 * @return entry pointer, or NULL on NULL input
 */
static inline struct sos_origin_entry *
sos_origin_table_lookup(struct sos_origin_table *table, const uint8_t iid[8])
{
	struct sos_origin_entry *lru;

	if (table == NULL || iid == NULL) {
		return NULL;
	}
	lru = &table->entries[0];
	for (size_t i = 0; i < SOS_ORIGIN_TABLE_MAX; i++) {
		struct sos_origin_entry *e = &table->entries[i];

		if (e->in_use && memcmp(e->iid, iid, 8) == 0) {
			return e;
		}
		if (!e->in_use) {
			lru = e; /* prefer a free slot over evicting */
		} else if (lru->in_use &&
			   sos_origin_last_activity(e) <
				   sos_origin_last_activity(lru)) {
			lru = e;
		}
	}
	/* memset(0) IS sos_ratelimit_state_init (alert_count==0, all times
	 * zero) — done as part of the full-entry clear so this header-only
	 * unit stays free of a link dependency on sos_ratelimit.c (the
	 * sos_post path is compiled into coap_server builds that do not
	 * link the link-layer ratelimit object; bd a2a2 class). */
	memset(lru, 0, sizeof(*lru));
	lru->in_use = true;
	memcpy(lru->iid, iid, 8);
	return lru;
}

/**
 * Monotonic Origin Sequence gate (spec 18.4.1): accept a sequence only if
 * it strictly exceeds the highest already accepted from that origin.
 *
 * @param[in] entry       Origin entry from sos_origin_table_lookup()
 * @param[in] sequence    Candidate Origin Sequence
 * @return true if the sequence advances (accept), false if replay/stale
 */
static inline bool sos_origin_seq_advance(const struct sos_origin_entry *entry,
					  uint64_t sequence)
{
	if (entry == NULL) {
		return false;
	}
	return !entry->accepted || sequence > entry->last_seq;
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SOS_ORIGIN_TABLE_H_ */
