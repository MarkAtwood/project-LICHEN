/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file dodag.c
 * @brief RPL DODAG state machine with MRHOF parent selection
 *
 * Ported from rust/lichen-rpl/src/dodag.rs
 *
 * ETX is stored as fixed-point (scaled by 256) to avoid floats on embedded.
 * path_cost = parent_rank + (link_etx * min_hop_rank_increase) / 256
 */

#include <lichen/rpl_dodag.h>
#include <string.h>

/* ── Helpers ───────────────────────────────────────────────────────────────── */

static bool addr_eq(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, 16) == 0;
}

/**
 * Calculate path cost via this parent (MRHOF, RFC 6719 appendix B.1).
 *
 * path_cost = rank + (link_etx * mhri) / 256
 *
 * Using fixed-point: link_etx=256 means ETX=1.0, so we divide by 256.
 */
static uint16_t path_cost(const struct lichen_rpl_parent *p, uint16_t mhri)
{
	uint32_t increment = ((uint32_t)p->link_etx * mhri) / 256;
	uint32_t cost = (uint32_t)p->rank + increment;
	return (cost > 0xFFFF) ? 0xFFFF : (uint16_t)cost;
}

static struct lichen_rpl_parent *find_parent(struct lichen_rpl_dodag *d,
					     const uint8_t *addr)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		if (d->parents[i].valid && addr_eq(d->parents[i].addr, addr)) {
			return &d->parents[i];
		}
	}
	return NULL;
}

static struct lichen_rpl_parent *find_free_slot(struct lichen_rpl_dodag *d)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		if (!d->parents[i].valid) {
			return &d->parents[i];
		}
	}
	return NULL;
}

/**
 * Check if a candidate is admissible (MaxRankIncrease check).
 */
static bool is_admissible(const struct lichen_rpl_dodag *d,
			  const struct lichen_rpl_parent *p)
{
	uint16_t cost = path_cost(p, d->min_hop_rank_increase);

	if (d->lowest_rank == LICHEN_RPL_INFINITE_RANK) {
		return true;
	}

	uint32_t max_allowed = (uint32_t)d->lowest_rank + d->max_rank_increase;
	if (max_allowed > 0xFFFF) {
		max_allowed = 0xFFFF;
	}

	return cost <= max_allowed;
}

static void adopt_version(struct lichen_rpl_dodag *d,
			  const struct lichen_rpl_dio *dio)
{
	memcpy(d->dodag_id, dio->dodag_id, 16);
	d->rpl_instance_id = dio->rpl_instance_id;
	d->version = dio->version;

	/* Clear all parent state */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		d->parents[i].valid = false;
	}
	d->has_preferred_parent = false;
	d->rank = LICHEN_RPL_INFINITE_RANK;
	d->lowest_rank = LICHEN_RPL_INFINITE_RANK;
	d->role = LICHEN_RPL_UNJOINED;
}

/* ── Public API ────────────────────────────────────────────────────────────── */

void lichen_rpl_dodag_init(struct lichen_rpl_dodag *d,
			   uint8_t rpl_instance_id,
			   const uint8_t *dodag_id,
			   uint8_t version)
{
	memset(d, 0, sizeof(*d));

	d->rpl_instance_id = rpl_instance_id;
	memcpy(d->dodag_id, dodag_id, 16);
	d->version = version;
	d->role = LICHEN_RPL_UNJOINED;
	d->rank = LICHEN_RPL_INFINITE_RANK;
	d->has_preferred_parent = false;

	d->min_hop_rank_increase = LICHEN_RPL_DEFAULT_MIN_HOP_RANK;
	d->max_rank_increase = LICHEN_RPL_DEFAULT_MAX_RANK_INC;
	d->parent_switch_threshold = LICHEN_RPL_DEFAULT_SWITCH_THRESH;
	d->lowest_rank = LICHEN_RPL_INFINITE_RANK;
}

void lichen_rpl_dodag_init_root(struct lichen_rpl_dodag *d,
				uint8_t rpl_instance_id,
				const uint8_t *dodag_id,
				uint8_t version)
{
	lichen_rpl_dodag_init(d, rpl_instance_id, dodag_id, version);
	d->role = LICHEN_RPL_ROOT;
	d->rank = LICHEN_RPL_ROOT_RANK;
	d->lowest_rank = LICHEN_RPL_ROOT_RANK;
}

void lichen_rpl_dodag_select_parent(struct lichen_rpl_dodag *d)
{
	uint16_t mhri = d->min_hop_rank_increase;
	uint16_t threshold = d->parent_switch_threshold;

	/* Find best admissible parent */
	struct lichen_rpl_parent *best = NULL;
	uint16_t best_cost = 0xFFFF;

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		struct lichen_rpl_parent *p = &d->parents[i];
		if (!p->valid || !is_admissible(d, p)) {
			continue;
		}
		uint16_t cost = path_cost(p, mhri);
		if (best == NULL || cost < best_cost) {
			best = p;
			best_cost = cost;
		}
	}

	/* No valid parent? */
	if (best == NULL) {
		if (d->role != LICHEN_RPL_ROOT) {
			d->role = LICHEN_RPL_UNJOINED;
			d->has_preferred_parent = false;
			d->rank = LICHEN_RPL_INFINITE_RANK;
		}
		return;
	}

	uint8_t *best_addr = best->addr;

	/* Hysteresis: only switch if improvement exceeds threshold */
	uint8_t *chosen_addr = best_addr;
	uint16_t chosen_cost = best_cost;

	if (d->has_preferred_parent && !addr_eq(d->preferred_parent, best_addr)) {
		struct lichen_rpl_parent *cur = find_parent(d, d->preferred_parent);
		if (cur != NULL) {
			uint16_t cur_cost = path_cost(cur, mhri);
			/* improvement = cur_cost - best_cost */
			/* switch only if best_cost < cur_cost - threshold */
			if (cur_cost > threshold &&
			    best_cost > cur_cost - threshold) {
				/* Not enough improvement - stay with current */
				chosen_addr = cur->addr;
				chosen_cost = cur_cost;
			}
		}
	}

	memcpy(d->preferred_parent, chosen_addr, 16);
	d->has_preferred_parent = true;
	d->rank = chosen_cost;
	d->role = LICHEN_RPL_JOINED;

	if (chosen_cost < d->lowest_rank) {
		d->lowest_rank = chosen_cost;
	}
}

void lichen_rpl_dodag_process_dio(struct lichen_rpl_dodag *d,
				  const struct lichen_rpl_dio *dio,
				  const uint8_t *neighbor_addr,
				  uint16_t link_etx)
{
	/* Root ignores DIOs */
	if (d->role == LICHEN_RPL_ROOT) {
		return;
	}

	/* Only accept DIOs from the same DODAG once joined */
	if (lichen_rpl_dodag_is_joined(d) &&
	    !addr_eq(dio->dodag_id, d->dodag_id)) {
		return;
	}

	/* Newer version or first DIO? Rejoin. */
	if (dio->version > d->version || !lichen_rpl_dodag_is_joined(d)) {
		adopt_version(d, dio);
	} else if (dio->version < d->version) {
		/* Stale version */
		return;
	}

	/* Poisoned route? Drop this candidate. */
	if (dio->rank == LICHEN_RPL_INFINITE_RANK) {
		struct lichen_rpl_parent *p = find_parent(d, neighbor_addr);
		if (p != NULL) {
			p->valid = false;
		}
		lichen_rpl_dodag_select_parent(d);
		return;
	}

	/* Update or add parent candidate */
	struct lichen_rpl_parent *p = find_parent(d, neighbor_addr);
	if (p == NULL) {
		p = find_free_slot(d);
		if (p == NULL) {
			/* No room - could evict worst, but for now just ignore */
			return;
		}
		memcpy(p->addr, neighbor_addr, 16);
	}

	p->rank = dio->rank;
	p->link_etx = link_etx;
	p->valid = true;

	lichen_rpl_dodag_select_parent(d);
}

void lichen_rpl_dodag_remove_parent(struct lichen_rpl_dodag *d,
				    const uint8_t *addr)
{
	struct lichen_rpl_parent *p = find_parent(d, addr);
	if (p != NULL) {
		p->valid = false;
	}
	lichen_rpl_dodag_select_parent(d);
}

int lichen_rpl_dodag_parent_count(const struct lichen_rpl_dodag *d)
{
	int count = 0;
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		if (d->parents[i].valid) {
			count++;
		}
	}
	return count;
}
