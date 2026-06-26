/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file routing.c
 * @brief RPL routing table and DAO manager implementation
 *
 * Ported from rust/lichen-rpl/src/routing.rs
 */

#include <lichen/rpl_routing.h>
#include <string.h>

/* Maximum chain depth for loop detection */
#define MAX_CHAIN 64

/* ── Helpers ───────────────────────────────────────────────────────────────── */

static bool addr_eq(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, 16) == 0;
}

static void addr_copy(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 16);
}

/* ── Source Routing Header ─────────────────────────────────────────────────── */

int lichen_rpl_srh_write(const struct lichen_rpl_srh *srh,
			 uint8_t *buf, size_t len)
{
	size_t needed = 6 + (size_t)srh->num_addresses * 16;
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = 3;  /* routing type */
	buf[1] = srh->segments_left;
	buf[2] = 0;  /* CmprI */
	buf[3] = 0;  /* CmprE */
	buf[4] = 0;  /* reserved */
	buf[5] = 0;

	for (int i = 0; i < srh->num_addresses; i++) {
		memcpy(&buf[6 + i * 16], srh->addresses[i], 16);
	}

	return (int)needed;
}

int lichen_rpl_srh_parse(struct lichen_rpl_srh *srh,
			 const uint8_t *data, size_t len)
{
	if (len < 6) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	if (data[0] != 3) {
		return LICHEN_RPL_ERR_BAD_RT;
	}

	size_t addr_bytes = len - 6;
	if (addr_bytes % 16 != 0) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	size_t num_addrs = addr_bytes / 16;
	if (num_addrs > LICHEN_RPL_MAX_HOPS) {
		return LICHEN_RPL_ERR_OVERRUN;
	}

	srh->segments_left = data[1];
	srh->num_addresses = (uint8_t)num_addrs;

	for (size_t i = 0; i < num_addrs; i++) {
		memcpy(srh->addresses[i], &data[6 + i * 16], 16);
	}

	return LICHEN_RPL_OK;
}

/* ── Routing Table ─────────────────────────────────────────────────────────── */

void lichen_rpl_routing_table_init(struct lichen_rpl_routing_table *rt)
{
	memset(rt, 0, sizeof(*rt));
}

static struct lichen_rpl_route *
find_route(struct lichen_rpl_routing_table *rt, const uint8_t *target)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (rt->routes[i].valid && addr_eq(rt->routes[i].target, target)) {
			return &rt->routes[i];
		}
	}
	return NULL;
}

static struct lichen_rpl_route *find_free_route(struct lichen_rpl_routing_table *rt)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (!rt->routes[i].valid) {
			return &rt->routes[i];
		}
	}
	return NULL;
}

int lichen_rpl_routing_table_add(struct lichen_rpl_routing_table *rt,
				 const uint8_t *target,
				 const uint8_t path[][16],
				 uint8_t path_len)
{
	if (path_len > LICHEN_RPL_MAX_HOPS) {
		return -1;
	}

	struct lichen_rpl_route *r = find_route(rt, target);
	if (r == NULL) {
		r = find_free_route(rt);
		if (r == NULL) {
			return -1;  /* Table full */
		}
	}

	addr_copy(r->target, target);
	for (int i = 0; i < path_len; i++) {
		addr_copy(r->path[i], path[i]);
	}
	r->path_len = path_len;
	r->valid = true;

	return 0;
}

void lichen_rpl_routing_table_remove(struct lichen_rpl_routing_table *rt,
				     const uint8_t *target)
{
	struct lichen_rpl_route *r = find_route(rt, target);
	if (r != NULL) {
		r->valid = false;
	}
}

const struct lichen_rpl_route *
lichen_rpl_routing_table_lookup(const struct lichen_rpl_routing_table *rt,
				const uint8_t *target)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (rt->routes[i].valid && addr_eq(rt->routes[i].target, target)) {
			return &rt->routes[i];
		}
	}
	return NULL;
}

int lichen_rpl_routing_table_count(const struct lichen_rpl_routing_table *rt)
{
	int count = 0;
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (rt->routes[i].valid) {
			count++;
		}
	}
	return count;
}

/* ── DAO Manager ───────────────────────────────────────────────────────────── */

void lichen_rpl_dao_manager_init(struct lichen_rpl_dao_manager *dm,
				 const uint8_t *node_address,
				 uint8_t rpl_instance_id,
				 const uint8_t *dodag_id)
{
	memset(dm, 0, sizeof(*dm));
	addr_copy(dm->node_address, node_address);
	dm->rpl_instance_id = rpl_instance_id;
	addr_copy(dm->dodag_id, dodag_id);
	dm->is_root = false;
	dm->dao_sequence = 0;
}

void lichen_rpl_dao_manager_init_root(struct lichen_rpl_dao_manager *dm,
				      const uint8_t *node_address,
				      uint8_t rpl_instance_id,
				      const uint8_t *dodag_id)
{
	lichen_rpl_dao_manager_init(dm, node_address, rpl_instance_id, dodag_id);
	dm->is_root = true;
	lichen_rpl_routing_table_init(&dm->routing_table);
}

int lichen_rpl_dao_manager_build_dao(struct lichen_rpl_dao_manager *dm,
				     const uint8_t *parent_addr,
				     uint8_t *buf, size_t len)
{
	/* Need: DAO(20) + Target(20) + TransitInfo(22) = 62 bytes */
	if (len < 64) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	dm->dao_sequence++;

	struct lichen_rpl_dao dao = {
		.rpl_instance_id = dm->rpl_instance_id,
		.ack_requested = false,
		.flags = 0,
		.dao_sequence = dm->dao_sequence,
	};
	addr_copy(dao.dodag_id, dm->dodag_id);

	int pos = lichen_rpl_dao_write(&dao, buf, len);
	if (pos < 0) {
		return pos;
	}

	/* RPL Target option: advertise self */
	struct lichen_rpl_target target = {
		.prefix_len = 128,
	};
	addr_copy(target.prefix, dm->node_address);

	int n = lichen_rpl_target_write(&target, &buf[pos], len - pos);
	if (n < 0) {
		return n;
	}
	pos += n;

	/* Transit Info option: via parent */
	struct lichen_rpl_transit_info transit = {
		.path_control = 0,
		.path_sequence = 0,
		.path_lifetime = 255,
	};
	addr_copy(transit.parent_address, parent_addr);

	n = lichen_rpl_transit_info_write(&transit, &buf[pos], len - pos);
	if (n < 0) {
		return n;
	}
	pos += n;

	return pos;
}

/* Extract target → parent edge from DAO options */
static bool extract_edge(const uint8_t *dao_bytes, size_t len,
			 uint8_t *target_out, uint8_t *parent_out)
{
	const uint8_t *opts = lichen_rpl_dao_options(dao_bytes, len);
	size_t opts_len = lichen_rpl_dao_options_len(len);

	if (opts == NULL || opts_len == 0) {
		return false;
	}

	struct lichen_rpl_opt_iter it;
	lichen_rpl_opt_iter_init(&it, opts, opts_len);

	bool have_target = false;
	bool have_parent = false;
	uint8_t target[16];
	uint8_t parent[16];

	struct lichen_rpl_raw_opt opt;
	while (lichen_rpl_opt_iter_next(&it, &opt) == LICHEN_RPL_OK) {
		if (opt.opt_type == LICHEN_RPL_OPT_RPL_TARGET) {
			struct lichen_rpl_target t;
			if (lichen_rpl_target_parse(&t, opt.data, opt.data_len) == LICHEN_RPL_OK) {
				addr_copy(target, t.prefix);
				have_target = true;
			}
		} else if (opt.opt_type == LICHEN_RPL_OPT_TRANSIT_INFO) {
			struct lichen_rpl_transit_info ti;
			if (lichen_rpl_transit_info_parse(&ti, opt.data, opt.data_len) == LICHEN_RPL_OK) {
				addr_copy(parent, ti.parent_address);
				have_parent = true;
			}
		}
	}

	if (have_target && have_parent) {
		addr_copy(target_out, target);
		addr_copy(parent_out, parent);
		return true;
	}

	return false;
}

/* Find parent edge entry by target */
static struct lichen_rpl_parent_edge *
find_edge(struct lichen_rpl_dao_manager *dm, const uint8_t *target)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (dm->parent_map[i].valid &&
		    addr_eq(dm->parent_map[i].target, target)) {
			return &dm->parent_map[i];
		}
	}
	return NULL;
}

static struct lichen_rpl_parent_edge *find_free_edge(struct lichen_rpl_dao_manager *dm)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (!dm->parent_map[i].valid) {
			return &dm->parent_map[i];
		}
	}
	return NULL;
}

/**
 * Walk target → parent → ... → root and return the downward path.
 * Returns path_len, or 0 if chain is incomplete or has a loop.
 */
static int assemble_path(struct lichen_rpl_dao_manager *dm,
			 const uint8_t *target,
			 uint8_t path[][16])
{
	uint8_t chain[LICHEN_RPL_MAX_HOPS][16];
	int chain_len = 0;

	uint8_t node[16];
	addr_copy(node, target);

	/* Simple loop detection using linear search */
	for (int depth = 0; depth < MAX_CHAIN; depth++) {
		if (addr_eq(node, dm->node_address)) {
			/* Reached root - reverse chain into path */
			for (int i = 0; i < chain_len; i++) {
				addr_copy(path[i], chain[chain_len - 1 - i]);
			}
			return chain_len;
		}

		/* Check for loop */
		for (int i = 0; i < chain_len; i++) {
			if (addr_eq(chain[i], node)) {
				return 0;  /* Loop detected */
			}
		}

		if (chain_len >= LICHEN_RPL_MAX_HOPS) {
			return 0;  /* Too many hops */
		}

		addr_copy(chain[chain_len], node);
		chain_len++;

		/* Look up parent */
		struct lichen_rpl_parent_edge *edge = find_edge(dm, node);
		if (edge == NULL) {
			return 0;  /* Incomplete chain */
		}

		addr_copy(node, edge->parent);
	}

	return 0;  /* Chain too long */
}

static void rebuild_routes(struct lichen_rpl_dao_manager *dm)
{
	/* Iterate all edges and try to assemble paths */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (!dm->parent_map[i].valid) {
			continue;
		}

		uint8_t path[LICHEN_RPL_MAX_HOPS][16];
		int path_len = assemble_path(dm, dm->parent_map[i].target, path);

		if (path_len > 0) {
			lichen_rpl_routing_table_add(&dm->routing_table,
						     dm->parent_map[i].target,
						     path, (uint8_t)path_len);
		}
	}
}

bool lichen_rpl_dao_manager_process_dao(struct lichen_rpl_dao_manager *dm,
					const uint8_t *dao_bytes, size_t len)
{
	if (!dm->is_root) {
		return false;
	}

	uint8_t target[16];
	uint8_t parent[16];

	if (!extract_edge(dao_bytes, len, target, parent)) {
		return false;
	}

	/* Update or add edge */
	struct lichen_rpl_parent_edge *edge = find_edge(dm, target);
	if (edge == NULL) {
		edge = find_free_edge(dm);
		if (edge == NULL) {
			return false;  /* Map full */
		}
	}

	addr_copy(edge->target, target);
	addr_copy(edge->parent, parent);
	edge->valid = true;

	rebuild_routes(dm);

	return lichen_rpl_routing_table_lookup(&dm->routing_table, target) != NULL;
}
