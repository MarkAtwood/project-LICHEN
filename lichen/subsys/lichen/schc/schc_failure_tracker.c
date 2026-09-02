/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/schc_failure_tracker.h>

#include <string.h>

void lichen_schc_failure_tracker_init(struct lichen_schc_failure_tracker *t,
				      uint16_t threshold)
{
	if (t == NULL) {
		return;
	}
	t->threshold = threshold;
	memset(t->entries, 0, sizeof(t->entries));
	t->capacity_events = 0U;
}

bool lichen_schc_failure_record(struct lichen_schc_failure_tracker *t,
				const uint8_t pubkey[LICHEN_SCHC_TRACKER_KEY_LEN])
{
	if (t == NULL || pubkey == NULL || t->threshold == 0U) {
		return false;
	}

	for (size_t i = 0U; i < LICHEN_SCHC_TRACKER_MAX_SOURCES; i++) {
		struct lichen_schc_failure_entry *e = &t->entries[i];

		if (e->active && memcmp(e->pubkey, pubkey,
					LICHEN_SCHC_TRACKER_KEY_LEN) == 0) {
			e->count = e->count < t->threshold ? (uint16_t)(e->count + 1U)
							   : t->threshold;
			bool notify = (e->count == t->threshold) && !e->notified;
			e->notified = e->notified || notify;
			return notify;
		}
	}

	/* Fail closed: never evict an existing run for an untracked signer. */
	for (size_t i = 0U; i < LICHEN_SCHC_TRACKER_MAX_SOURCES; i++) {
		struct lichen_schc_failure_entry *e = &t->entries[i];

		if (!e->active) {
			e->active = true;
			memcpy(e->pubkey, pubkey, LICHEN_SCHC_TRACKER_KEY_LEN);
			e->count = 1U;
			e->notified = (t->threshold == 1U);
			return e->notified;
		}
	}
	t->capacity_events++;
	return false;
}

void lichen_schc_failure_clear(struct lichen_schc_failure_tracker *t,
			       const uint8_t pubkey[LICHEN_SCHC_TRACKER_KEY_LEN])
{
	if (t == NULL || pubkey == NULL) {
		return;
	}
	for (size_t i = 0U; i < LICHEN_SCHC_TRACKER_MAX_SOURCES; i++) {
		struct lichen_schc_failure_entry *e = &t->entries[i];

		if (e->active && memcmp(e->pubkey, pubkey,
					LICHEN_SCHC_TRACKER_KEY_LEN) == 0) {
			memset(e, 0, sizeof(*e));
			return;
		}
	}
}

uint64_t
lichen_schc_failure_capacity_events(const struct lichen_schc_failure_tracker *t)
{
	return (t == NULL) ? 0U : t->capacity_events;
}
