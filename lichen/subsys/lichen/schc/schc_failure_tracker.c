/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/schc_failure_tracker.h>

#include <errno.h>

#include <string.h>

int lichen_schc_failure_tracker_init(struct lichen_schc_failure_tracker *t,
				     uint16_t threshold, uint16_t capacity)
{
	if (t == NULL || threshold == 0 || capacity == 0 ||
	    capacity > LICHEN_SCHC_FT_MAX_SOURCES) {
		return -EINVAL;
	}
	memset(t, 0, sizeof(*t));
	t->threshold = threshold;
	t->capacity = capacity;
	return 0;
}

enum lichen_schc_ft_result
lichen_schc_failure_tracker_record_failure(struct lichen_schc_failure_tracker *t,
					   const uint8_t source[LICHEN_SCHC_FT_SOURCE_LEN])
{
	if (t == NULL || source == NULL) {
		return LICHEN_SCHC_FT_INVALID;
	}
	/* Existing run: saturate at threshold, emit one notification. */
	for (uint16_t i = 0; i < LICHEN_SCHC_FT_MAX_SOURCES; i++) {
		if (t->entries[i].used &&
		    memcmp(t->entries[i].source, source,
			   LICHEN_SCHC_FT_SOURCE_LEN) == 0) {
			if (t->entries[i].count < t->threshold) {
				t->entries[i].count++;
			}
			bool notify = t->entries[i].count == t->threshold &&
				      !t->entries[i].notified;
			if (notify) {
				t->entries[i].notified = true;
			}
			return notify ? LICHEN_SCHC_FT_NOTIFY
				      : LICHEN_SCHC_FT_OK;
		}
	}
	/* New signer: fail closed when at capacity (no eviction). */
	if (t->entry_count >= t->capacity) {
		t->capacity_events++;
		return LICHEN_SCHC_FT_FULL;
	}
	/* Find a free slot. */
	for (uint16_t i = 0; i < LICHEN_SCHC_FT_MAX_SOURCES; i++) {
		if (!t->entries[i].used) {
			t->entries[i].used = true;
			memcpy(t->entries[i].source, source,
			       LICHEN_SCHC_FT_SOURCE_LEN);
			t->entries[i].count = 1;
			t->entries[i].notified = (t->threshold == 1);
			t->entry_count++;
			return t->threshold == 1 ? LICHEN_SCHC_FT_NOTIFY
						 : LICHEN_SCHC_FT_OK;
		}
	}
	/* Should not reach here (entry_count == capacity guard above). */
	t->capacity_events++;
	return LICHEN_SCHC_FT_FULL;
}

void lichen_schc_failure_tracker_record_success(
	struct lichen_schc_failure_tracker *t,
	const uint8_t source[LICHEN_SCHC_FT_SOURCE_LEN])
{
	if (t == NULL || source == NULL) {
		return;
	}
	for (uint16_t i = 0; i < LICHEN_SCHC_FT_MAX_SOURCES; i++) {
		if (t->entries[i].used &&
		    memcmp(t->entries[i].source, source,
			   LICHEN_SCHC_FT_SOURCE_LEN) == 0) {
			t->entries[i].used = false;
			t->entries[i].count = 0;
			t->entries[i].notified = false;
			t->entry_count--;
			return;
		}
	}
}

void lichen_schc_failure_tracker_retire(
	struct lichen_schc_failure_tracker *t,
	const uint8_t source[LICHEN_SCHC_FT_SOURCE_LEN])
{
	lichen_schc_failure_tracker_record_success(t, source);
}

uint64_t lichen_schc_failure_tracker_capacity_events(
	const struct lichen_schc_failure_tracker *t)
{
	return (t != NULL) ? t->capacity_events : 0;
}
