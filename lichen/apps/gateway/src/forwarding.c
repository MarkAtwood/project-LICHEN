/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "forwarding.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys_clock.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_pkt.h>

#if defined(CONFIG_LICHEN_TUNNEL_AUTH)
#include <lichen/gateway/tunnel_auth.h>
#endif

LOG_MODULE_REGISTER(lichen_forwarding, LOG_LEVEL_INF);

#define LICHEN_MESH_MTU 200

static struct k_mutex s_stats_mutex;
static struct lichen_forwarding_stats s_stats;

static bool s_initialized;

static struct net_if *s_mesh_iface;

#if defined(CONFIG_LICHEN_TUNNEL_AUTH)
static struct lichen_tunnel_auth_ctx s_tunnel_ctx;
static bool s_tunnel_ready;
#endif

static void forwarding_stats_init(struct lichen_forwarding_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
}

static void forwarding_mgmt_event_handler(struct net_mgmt_event_callback *cb,
					   uint32_t mgmt_event,
					   struct net_if *iface)
{
	ARG_UNUSED(cb);

	if (mgmt_event == NET_EVENT_IPV6_CMD_ROUTE_ADD) {
		LOG_DBG("Route added on iface %p", (void *)iface);
	} else if (mgmt_event == NET_EVENT_IPV6_CMD_ROUTE_DEL) {
		LOG_DBG("Route removed on iface %p", (void *)iface);
	}
}

int lichen_forwarding_init(void)
{
	if (s_initialized) {
		return -EALREADY;
	}

	static struct net_mgmt_event_callback fwd_mgmt_cb;

	k_mutex_init(&s_stats_mutex);
	forwarding_stats_init(&s_stats);

	net_mgmt_init_event_callback(&fwd_mgmt_cb, forwarding_mgmt_event_handler,
				     NET_EVENT_IPV6_CMD_ROUTE_ADD |
				     NET_EVENT_IPV6_CMD_ROUTE_DEL);
	net_mgmt_add_event_callback(&fwd_mgmt_cb);

	LOG_INF("IPv6 forwarding active: mesh MTU=%u", LICHEN_MESH_MTU);

	s_initialized = true;
	return 0;
}

void lichen_forwarding_set_mesh_iface(struct net_if *iface)
{
	s_mesh_iface = iface;
}

#if defined(CONFIG_LICHEN_TUNNEL_AUTH)
int lichen_gateway_tunnel_auth_init(const uint8_t egress_iid[8],
				    const uint8_t root_iid[8],
				    const uint8_t root_pubkey[32])
{
	struct lichen_tunnel_crypto crypto;
	int ret = lichen_tunnel_auth_default_crypto(&crypto);

	if (ret != 0) {
		return ret;
	}
	ret = lichen_tunnel_auth_init(&s_tunnel_ctx, egress_iid, root_iid,
				      root_pubkey, &crypto);
	s_tunnel_ready = (ret == 0);
	return ret;
}

struct lichen_tunnel_result lichen_gateway_tunnel_auth_receive(
	const uint8_t *body, size_t body_len, bool oscore_authenticated,
	const uint8_t oscore_sender_iid[8], uint64_t now_seconds)
{
	return lichen_tunnel_auth_receive(&s_tunnel_ctx, body, body_len,
					  oscore_authenticated,
					  oscore_sender_iid, now_seconds);
}
#endif

static void tunnel_stats_denied(void)
{
	k_mutex_lock(&s_stats_mutex, K_FOREVER);
	s_stats.tunnel_auth_denied++;
	k_mutex_unlock(&s_stats_mutex);
}

void lichen_forwarding_handle(struct net_pkt *pkt, struct net_if *in_iface,
			      struct net_if *out_iface)
{
	uint32_t pkt_len;

	if (pkt == NULL || in_iface == NULL || out_iface == NULL) {
		return;
	}

	if (in_iface == out_iface) {
		return;
	}

#if defined(CONFIG_LICHEN_TUNNEL_AUTH)
	if (s_tunnel_ready) {
		/* Fail closed if the mesh iface was never identified: with
		 * tunnel authorization on, unclassified cross-iface traffic
		 * is not forwardable. */
		if (s_mesh_iface == NULL) {
			tunnel_stats_denied();
			LOG_WRN("Egress dropped: mesh iface unidentified");
			return;
		}
		if (in_iface == s_mesh_iface) {
			uint8_t ip6[40];
			struct net_pkt_cursor backup;
			struct lichen_tunnel_result r;
			int rread;

			net_pkt_cursor_save(pkt, &backup);
			rread = net_pkt_read(pkt, ip6, sizeof(ip6));
			net_pkt_cursor_restore(pkt, &backup);
			if (rread != 0) {
				tunnel_stats_denied();
				LOG_WRN("Egress dropped: unreadable IPv6 header");
				return;
			}
			/* Single-hop route: this gateway is the egress.
			 * ponytail: multi-hop SRH route extraction is not
			 * wired, so grants issued over longer routes fail
			 * closed here; upgrade path is SRH parsing at the
			 * L2 decapsulation site. Uptime seconds stand in
			 * for unix time (expiry dormant, replay floors not). */
			r = lichen_tunnel_auth_decapsulate(
				&s_tunnel_ctx, ip6 + 8, ip6 + 24,
				s_tunnel_ctx.egress_iid, 1,
				LICHEN_TUNNEL_MESH_TO_EXTERNAL,
				(uint64_t)k_uptime_get() / MSEC_PER_SEC);
			if (!r.allowed) {
				tunnel_stats_denied();
				LOG_WRN("Egress dropped: tunnel denial %d",
					(int)r.denial);
				return;
			}
		}
	}
#endif

	pkt_len = net_pkt_get_len(pkt);

	k_mutex_lock(&s_stats_mutex, K_FOREVER);

	if (pkt_len > LICHEN_MESH_MTU) {
		s_stats.backhaul_to_mesh_dropped_mtu++;
		LOG_WRN("Forwarding: packet %u B exceeds mesh MTU %u, dropping",
			pkt_len, LICHEN_MESH_MTU);
	}

	k_mutex_unlock(&s_stats_mutex);
}

int lichen_forwarding_stats_get(struct lichen_forwarding_stats *stats)
{
	if (stats == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_stats_mutex, K_FOREVER);
	*stats = s_stats;
	k_mutex_unlock(&s_stats_mutex);

	return 0;
}

int lichen_forwarding_stats_clear(void)
{
	k_mutex_lock(&s_stats_mutex, K_FOREVER);
	forwarding_stats_init(&s_stats);
	k_mutex_unlock(&s_stats_mutex);

	return 0;
}
