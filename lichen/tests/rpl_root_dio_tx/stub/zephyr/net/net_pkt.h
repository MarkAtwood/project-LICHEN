/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TEST_ZEPHYR_NET_PKT_H_
#define TEST_ZEPHYR_NET_PKT_H_

/* Minimal host-test stub for <zephyr/net/net_pkt.h>: a fixed flat buffer
 * the test can capture after the DIO builder writes the packet. */

#include <stddef.h>
#include <stdint.h>

#define K_NO_WAIT 0

struct net_if;

struct net_pkt {
	uint8_t data[1600];
	size_t len;
};

struct net_pkt *net_pkt_rx_alloc_with_buffer(struct net_if *iface,
					     size_t size, int family, int proto,
					     int timeout);
int net_pkt_write(struct net_pkt *pkt, const void *src, size_t len);
void net_pkt_unref(struct net_pkt *pkt);

#endif
