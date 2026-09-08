/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_FORWARDING_H_
#define LICHEN_GATEWAY_FORWARDING_H_

#include <stdint.h>
#include <stddef.h>

#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>

struct lichen_forwarding_stats {
	uint64_t mesh_to_backhaul;
	uint64_t backhaul_to_mesh;
	uint64_t backhaul_to_mesh_dropped_mtu;
	uint64_t tunnel_auth_denied;
};

int lichen_forwarding_init(void);

void lichen_forwarding_handle(struct net_pkt *pkt, struct net_if *in_iface,
			      struct net_if *out_iface);

/**
 * Identify the mesh interface for the tunnel egress gate. Egress
 * (mesh iface -> any other iface) requires a valid root-issued grant
 * when CONFIG_LICHEN_TUNNEL_AUTH is on; backhaul -> mesh passes through
 * (border-router ingress is out of tunnel scope).
 */
void lichen_forwarding_set_mesh_iface(struct net_if *iface);

#ifdef CONFIG_LICHEN_TUNNEL_AUTH
#include <lichen/gateway/tunnel_auth.h>

/**
 * Initialize the gateway tunnel authorization context (egress gate).
 * Root material: on a root gateway these are the node's own identity.
 */
int lichen_gateway_tunnel_auth_init(const uint8_t egress_iid[8],
				    const uint8_t root_iid[8],
				    const uint8_t root_pubkey[32]);

/** Adapter for the /.well-known/tunnel-auth CoAP handler. */
struct lichen_tunnel_result lichen_gateway_tunnel_auth_receive(
	const uint8_t *body, size_t body_len, bool oscore_authenticated,
	const uint8_t oscore_sender_iid[8], uint64_t now_seconds);
#endif

int lichen_forwarding_stats_get(struct lichen_forwarding_stats *stats);

int lichen_forwarding_stats_clear(void);

#endif
