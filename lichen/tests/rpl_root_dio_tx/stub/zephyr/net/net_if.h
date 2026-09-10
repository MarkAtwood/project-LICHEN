/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TEST_ZEPHYR_NET_IF_H_
#define TEST_ZEPHYR_NET_IF_H_

/* Minimal host-test stub for <zephyr/net/net_if.h>: the rpl_root DIO
 * builder only carries an opaque interface pointer through to
 * net_recv_data(). */

struct net_if {
	int dummy;
};

struct net_pkt;

int net_recv_data(struct net_if *iface, struct net_pkt *pkt);

#endif
