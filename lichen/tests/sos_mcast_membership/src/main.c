/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/kernel.h>
#include <zephyr/net/dummy.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/ztest.h>

/*
 * R-12-036 (spec/12-apps.md 18.4): SOS MUST be postable to
 * coap://[ff02::1]/sos. The /sos handler (coap_server.c) is
 * transport-agnostic; delivery depends on the node having joined the
 * ff02::1 all-nodes multicast group. Zephyr joins it in
 * join_mcast_allnodes() (subsys/net/ip/net_if.c), which exists only under
 * CONFIG_NET_IPV6_MLD and runs when a unicast IPv6 address is added on an
 * L2 that advertises NET_L2_MULTICAST. These suites pin that mechanism on
 * both sides of the CONFIG_NET_IPV6_MLD switch.
 */

static struct net_if *test_iface;

static int dev_init(const struct device *dev)
{
	ARG_UNUSED(dev);

	return 0;
}

static void iface_init(struct net_if *iface)
{
	static uint8_t mac[6] = { 0x02, 0x00, 0x5e, 0x10, 0x20, 0x30 };

	net_if_set_link_addr(iface, mac, sizeof(mac), NET_LINK_ETHERNET);
	test_iface = iface;
}

static int dummy_send(const struct device *dev, struct net_pkt *pkt)
{
	ARG_UNUSED(dev);

	net_pkt_unref(pkt);

	return 0;
}

static struct dummy_api dummy_if_api = {
	.iface_api.init = iface_init,
	.send = dummy_send,
};

NET_DEVICE_INIT(sos_mcast_dev, "sos_mcast_dev", dev_init, NULL, NULL, NULL,
		CONFIG_KERNEL_INIT_PRIORITY_DEVICE, &dummy_if_api, DUMMY_L2,
		NET_L2_GET_CTX_TYPE(DUMMY_L2), 127);

ZTEST(sos_mcast_membership, test_ff02_1_membership_tracks_mld)
{
	const struct in6_addr all_nodes = { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0x01 } } };
	struct in6_addr link_local = { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
					   0x02, 0x00, 0x5e, 0xff, 0xfe,
					   0x10, 0x20, 0x30 } } };
	struct net_if_addr *ifaddr;

	zassert_not_null(test_iface, "dummy interface not initialized");
	zassert_true(net_if_is_up(test_iface), "interface must be up");

	/* join_mcast_nodes() runs when a unicast IPv6 address is added
	 * (net_if.c:2074), mirroring how the LICHEN L2 interface joins
	 * ff02::1 when its link-local address comes up.
	 */
	ifaddr = net_if_ipv6_addr_add(test_iface, &link_local,
				      NET_ADDR_MANUAL, 0);
	zassert_not_null(ifaddr, "link-local address not added");

	zassert_true(net_ipv6_is_my_addr(&link_local),
		     "link-local address not registered");

#ifdef CONFIG_NET_IPV6_MLD
	zassert_not_null(net_if_ipv6_maddr_lookup(&all_nodes, &test_iface),
			 "ff02::1 must be joined under CONFIG_NET_IPV6_MLD=y: "
			 "coap://[ff02::1]/sos (R-12-036) delivery "
			 "prerequisite");
#else
	zassert_is_null(net_if_ipv6_maddr_lookup(&all_nodes, &test_iface),
			"ff02::1 must NOT be joined under "
			"CONFIG_NET_IPV6_MLD=n: multicast /sos POSTs cannot "
			"be delivered, apps must not expect R-12-036");
#endif
}

ZTEST_SUITE(sos_mcast_membership, NULL, NULL, NULL, NULL, NULL);
