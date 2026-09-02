/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rpl_sf_assignment.h>

#include <string.h>

#include <lichen/link.h>
#include <lichen/rpl_messages.h>

void lichen_rpl_sf_assignment_init(struct lichen_rpl_sf_assignment *s)
{
	if (s == NULL) {
		return;
	}
	s->assigned_sf_dio = 0;
	s->joined = false;
}

bool lichen_rpl_sf_is_valid(uint8_t sf)
{
	return sf >= LICHEN_SF_MIN && sf <= LICHEN_SF_MAX;
}

bool lichen_rpl_sf_assignment_make(uint8_t sf, uint8_t out[3])
{
	if (out == NULL || !lichen_rpl_sf_is_valid(sf)) {
		return false;
	}
	out[0] = LICHEN_DIO_OPTION_ASSIGNED_SF;
	out[1] = 1;
	out[2] = sf;
	return true;
}

uint8_t lichen_rpl_sf_assignment_parse(const uint8_t *data, size_t len)
{
	if (data == NULL || len < 3 || data[0] != LICHEN_DIO_OPTION_ASSIGNED_SF ||
	    data[1] != 1) {
		return 0;
	}
	return lichen_rpl_sf_is_valid(data[2]) ? data[2] : 0;
}

uint8_t lichen_rpl_sf_effective(const struct lichen_rpl_sf_assignment *s,
				const uint8_t iid[8])
{
	if (s != NULL && lichen_rpl_sf_is_valid(s->assigned_sf_dio)) {
		return s->assigned_sf_dio;
	}
	if (s == NULL || !s->joined) {
		return 10;
	}
	return (uint8_t)(7 + (lichen_hash_32(iid, 8) % 6));
}

/* ------------------------------------------------------------------ */
/* Gateway least-loaded SF tracker (rust GatewaySfTracker parity).     */
/* ------------------------------------------------------------------ */

void lichen_rpl_sf_tracker_init(struct lichen_rpl_sf_tracker *t)
{
	if (t == NULL) {
		return;
	}
	memset(t, 0, sizeof(*t));
}

static void tracker_remove(const struct lichen_rpl_sf_tracker *t,
			   const uint8_t iid[8])
{
	struct lichen_rpl_sf_tracker *mutable_t =
		(struct lichen_rpl_sf_tracker *)t;

	for (unsigned int i = 0; i < mutable_t->count;) {
		if (memcmp(mutable_t->iids[i], iid, 8) == 0) {
			size_t move_count =
				(size_t)(mutable_t->count - i - 1);
			memmove(&mutable_t->iids[i], &mutable_t->iids[i + 1],
				move_count * sizeof(mutable_t->iids[0]));
			memmove(&mutable_t->node_sf[i],
				&mutable_t->node_sf[i + 1],
				move_count * sizeof(mutable_t->node_sf[0]));
			mutable_t->count--;
			continue;
		}
		i++;
	}
}

bool lichen_rpl_sf_tracker_register(struct lichen_rpl_sf_tracker *t,
				    const uint8_t iid[8], uint8_t sf)
{
	if (t == NULL || iid == NULL || !lichen_rpl_sf_is_valid(sf)) {
		return false;
	}
	lichen_rpl_sf_tracker_unregister(t, iid);
	if (t->count >= LICHEN_SF_TRACKER_CAPACITY) {
		return false;
	}
	memcpy(t->iids[t->count], iid, 8);
	t->node_sf[t->count] = sf;
	t->count++;
	return true;
}

void lichen_rpl_sf_tracker_unregister(struct lichen_rpl_sf_tracker *t,
				      const uint8_t iid[8])
{
	if (t == NULL || iid == NULL) {
		return;
	}
	tracker_remove(t, iid);
}

void lichen_rpl_sf_tracker_load(const struct lichen_rpl_sf_tracker *t,
				uint32_t out[6])
{
	if (t == NULL || out == NULL) {
		return;
	}
	memset(out, 0, 6 * sizeof(out[0]));
	for (unsigned int i = 0; i < t->count; i++) {
		unsigned int idx = t->node_sf[i] - 7u;
		if (idx < 6u) {
			out[idx]++;
		}
	}
}

uint8_t lichen_rpl_sf_tracker_assign(struct lichen_rpl_sf_tracker *t,
				     const uint8_t iid[8])
{
	uint32_t load[6];
	uint8_t best_sf = 7;
	uint32_t best_load = 0;

	if (t == NULL || iid == NULL) {
		return 0;
	}
	lichen_rpl_sf_tracker_load(t, load);
	best_load = load[0];
	for (unsigned int i = 1; i < 6; i++) {
		if (load[i] < best_load) {
			best_load = load[i];
			best_sf = (uint8_t)(7 + i);
		}
	}
	if (!lichen_rpl_sf_tracker_register(t, iid, best_sf)) {
		return 0;
	}
	return best_sf;
}

int lichen_rpl_dio_validate_assigned_sf(const uint8_t *option)
{
	if (option == NULL) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}
	return lichen_rpl_sf_assignment_parse(option, 3) != 0
		       ? 0
		       : LICHEN_RPL_ERR_BAD_OPT;
}
