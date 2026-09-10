/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/sys/byteorder.h>
#include <lichen/hal.h>
#include "lichen_l2.h"
#include "ipv6_addr.h"

/* A fixed test identity provisions real production signing/verification. */
static const uint8_t seed[32] = {0x51, 0x03};
/* Python Identity.from_seed(bytes([0x51, 4]) + bytes(30)).pubkey. */
static const uint8_t peer_pubkey[32] = {
	0xb5, 0x47, 0x08, 0xc3, 0x0b, 0x7f, 0xe9, 0x46,
	0xd4, 0x03, 0x14, 0xf4, 0xf8, 0x48, 0xb8, 0xc7,
	0x98, 0x7c, 0xbf, 0x97, 0xbe, 0x87, 0xaa, 0xe6,
	0xb3, 0xda, 0x71, 0x32, 0xda, 0x5e, 0x03, 0xd1,
};
static const uint8_t request[] = {0x50, 0x02, 0x51, 0x03, 0xff, 'c', 't', 'x'};
static const uint8_t response[] = {0x60, 0x45, 0x51, 0x03, 0xff, 'p', 'y', '!'};

static void udp_checksum(uint8_t packet[56])
{
	uint32_t sum = 16 + IPPROTO_UDP;

	packet[46] = 0;
	packet[47] = 0;
	for (size_t i = 8; i < 56; i += 2) {
		sum += sys_get_be16(packet + i);
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	uint16_t checksum = (uint16_t)~sum;

	sys_put_be16(checksum == 0 ? 0xffff : checksum, packet + 46);
}

ZTEST(sim_radio_l2, test_signed_tcp_roundtrip)
{
	const struct device *radio;
	struct net_if *iface = net_if_get_first_by_type(&NET_L2_GET_NAME(lichen_l2));
	uint8_t pubkey[32], iid[8], peer_iid[8];
	struct sockaddr_in6 addr = {.sin6_family = AF_INET6,
		.sin6_port = htons(56830)};
	struct zsock_timeval timeout = {.tv_sec = 10};
	struct ifreq ifreq = {0};
	uint8_t packet[56] = {0x60};
	uint8_t expected[56];
	uint8_t received[sizeof(response)];
	struct lichen_l2_test_stats stats;
	struct net_pkt *pkt;
	int ret;
	int sock;

	zassert_ok(lichen_hal_lora_device_get(&radio));
	zassert_not_null(iface);
	zassert_ok(lichen_l2_test_load_key(seed, pubkey));
	zassert_ok(lichen_pubkey_to_iid(pubkey, iid));
	zassert_ok(lichen_pubkey_to_iid(peer_pubkey, peer_iid));
	peer_iid[0] |= 2;
	zassert_ok(lichen_peer_add(peer_iid, peer_pubkey));
	peer_iid[0] &= (uint8_t)~2;
	addr.sin6_addr.s6_addr[0] = 0xfe;
	addr.sin6_addr.s6_addr[1] = 0x80;
	memcpy(&addr.sin6_addr.s6_addr[8], iid, 8);
	zassert_not_null(net_if_ipv6_addr_add(iface, &addr.sin6_addr, NET_ADDR_MANUAL, 0));
	addr.sin6_scope_id = net_if_get_by_iface(iface);
	ret = net_if_up(iface);
	zassert_true(ret == 0 || ret == -EALREADY);

	sock = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	zassert_true(sock >= 0);
	/* Select the native mesh socket before any other socket operation. */
	zassert_true(net_if_get_name(iface, ifreq.ifr_name, sizeof(ifreq.ifr_name)) >= 0);
	ret = zsock_setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof(ifreq));
	zassert_ok(ret, "bind interface %s (index %d): errno=%d", ifreq.ifr_name,
		   net_if_get_by_iface(iface), errno);
	zassert_ok(zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
	zassert_ok(zsock_bind(sock, (struct sockaddr *)&addr, sizeof(addr)));

	/* Independently construct an IPv6/UDP packet and its RFC 8200 checksum. */
	sys_put_be16(16, packet + 4);
	packet[6] = IPPROTO_UDP;
	packet[7] = 64;
	memcpy(packet + 8, &addr.sin6_addr, 16);
	memcpy(packet + 24, &addr.sin6_addr, 16);
	memcpy(packet + 32, peer_iid, 8);
	sys_put_be16(56830, packet + 40);
	sys_put_be16(56830, packet + 42);
	sys_put_be16(16, packet + 44);
	memcpy(packet + 48, request, sizeof(request));
	udp_checksum(packet);
	memcpy(expected, packet, sizeof(expected));
	memcpy(expected + 8, packet + 24, 16);
	memcpy(expected + 24, packet + 8, 16);
	memcpy(expected + 48, response, sizeof(response));
	udp_checksum(expected);
	lichen_l2_test_reset_stats();
	pkt = net_pkt_alloc_with_buffer(iface, sizeof(packet), AF_INET6, IPPROTO_UDP, K_SECONDS(1));
	zassert_not_null(pkt);
	ret = net_pkt_write(pkt, packet, sizeof(packet));
	if (ret < 0) {
		net_pkt_unref(pkt);
	}
	zassert_ok(ret);
	net_pkt_cursor_init(pkt);
	ret = net_if_l2(iface)->send(iface, pkt);
	if (ret < 0) {
		net_pkt_unref(pkt);
	}
	zassert_true(ret >= 0);
	zassert_equal(zsock_recv(sock, received, sizeof(received), 0), sizeof(response));
	zassert_mem_equal(received, response, sizeof(response));
	zassert_ok(zsock_close(sock));
	lichen_l2_test_get_stats(&stats);
	zassert_true(stats.tx_packets > 0 && stats.rx_frames > 0 && stats.rx_injected_packets > 0);
	zassert_equal(stats.last_injected_len, sizeof(expected));
	zassert_mem_equal(stats.last_injected, expected, sizeof(expected));
}

ZTEST_SUITE(sim_radio_l2, NULL, NULL, NULL, NULL, NULL);
