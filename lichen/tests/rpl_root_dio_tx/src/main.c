/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief TX-side regression test for the gateway RPL root DIO
 *        (draft-lichen-rpl-lora-00 4.1 / R-RPL-007; bead b7z9.183): the
 *        emitted DIO's MOP field MUST be 1 (Non-Storing Mode). The C RX
 *        admission gate (subsys rpl dodag.c) silently rejects any DIO
 *        with MOP != 1, so a C root emitting MOP=0 is ignored by every C
 *        leaf — a self-interop break.
 *
 *        apps/gateway/src/rpl_root.c is compiled against host stubs for
 *        the Zephyr net_pkt/net_if APIs; the stub net_recv_data()
 *        captures the exact bytes the root hands to the network stack.
 *        Assertions use the RFC 6550 Section 6.3.1 wire layout as the
 *        independent oracle (raw flags byte), cross-checked with the
 *        implementation's own parser.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rpl_root.h"

#include <lichen/rpl_messages.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>

/* ---- net_pkt / net_if stub implementations (capture TX bytes) ---------- */

static uint8_t captured[2048];
static size_t captured_len;
static unsigned recv_calls;
static struct net_pkt stub_pkt;

struct net_pkt *net_pkt_rx_alloc_with_buffer(struct net_if *iface, size_t size,
					     int family, int proto, int timeout)
{
	(void)iface;
	(void)family;
	(void)proto;
	(void)timeout;
	if (size > sizeof(stub_pkt.data)) {
		return NULL;
	}
	stub_pkt.len = size;
	return &stub_pkt;
}

int net_pkt_write(struct net_pkt *pkt, const void *src, size_t len)
{
	if (pkt == NULL || src == NULL || len > sizeof(pkt->data)) {
		return -1;
	}
	memcpy(pkt->data, src, len);
	pkt->len = len;
	return 0;
}

void net_pkt_unref(struct net_pkt *pkt)
{
	(void)pkt;
}

int net_recv_data(struct net_if *iface, struct net_pkt *pkt)
{
	(void)iface;
	if (pkt->len > sizeof(captured)) {
		return -1;
	}
	memcpy(captured, pkt->data, pkt->len);
	captured_len = pkt->len;
	recv_calls++;
	return 0;
}

/* Layering bridge consumed by dodag.c (same stub pattern as rpl_dodag). */
void lora_l2_assign_sf(uint8_t sf)
{
	(void)sf;
}

/* ---- test scaffolding ---------------------------------------------------- */

static int tests_run;
static int tests_passed;

#define RUN_TEST(fn)                        \
	do {                                \
		printf("  %s...", #fn);     \
		tests_run++;                \
		if (fn()) {                 \
			printf(" OK\n");    \
			tests_passed++;     \
		}                           \
	} while (0)

#define CHECK(cond, msg)                          \
	do {                                      \
		if (!(cond)) {                    \
			printf(" FAIL: %s\n", msg); \
			return 0;                 \
		}                                 \
	} while (0)

#define IPV6_HDR_LEN   40
#define ICMPV6_HDR_LEN  4

/* RFC 6550 Section 5.1 */
#define ICMPV6_TYPE_RPL     155
#define ICMPV6_CODE_RPL_DIO   1

/* RFC 6550 Section 6.3.1 DIO base: InstanceID(1) Version(1) Rank(2), then a
 * flags byte of G(1) | 0(1) | MOP(3) | Prf(3), then DTSN(1), Flags(1),
 * Reserved(1), DODAGID(16). */
#define DIO_G_MOP_PRF_OFFSET (IPV6_HDR_LEN + ICMPV6_HDR_LEN + 4)
#define DIO_MOP_NON_STORING   1

/* DODAGID is the root's routable identity (0200::/8 per the Yggdrasil
 * addressing decision); DIOs originate from the link-local address. */
static const uint8_t DODAG_ID[16] = {
	0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
};
static const uint8_t NODE_ADDR[16] = {
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
};

static struct lichen_rpl_root root;
static struct net_if iface;

static int test_send_dio_emits_one_packet(void)
{
	memset(&iface, 0, sizeof(iface));
	CHECK(lichen_rpl_root_init(&root, &iface, DODAG_ID, NODE_ADDR) ==
		      &root,
	      "root init");
	CHECK(lichen_rpl_root_send_dio(&root), "send_dio returns true");
	CHECK(recv_calls == 1, "exactly one packet handed to net_recv_data");
	CHECK(captured_len >
		      IPV6_HDR_LEN + ICMPV6_HDR_LEN + LICHEN_RPL_DIO_BASE_LEN,
	      "packet holds IPv6 + ICMPv6 + DIO base + options");
	CHECK(captured[IPV6_HDR_LEN] == ICMPV6_TYPE_RPL,
	      "ICMPv6 type is RPL (155)");
	CHECK(captured[IPV6_HDR_LEN + 1] == ICMPV6_CODE_RPL_DIO,
	      "ICMPv6 code is DIO (1)");
	return 1;
}

static int test_dio_mop_is_non_storing_on_wire(void)
{
	uint8_t g_mop_prf = captured[DIO_G_MOP_PRF_OFFSET];
	uint8_t mop = (g_mop_prf >> 3) & 0x7;

	CHECK(mop == DIO_MOP_NON_STORING,
	      "wire MOP field is 1 (non-storing), not 0");
	CHECK((g_mop_prf & 0x80) != 0, "grounded bit set (root is grounded)");
	CHECK((g_mop_prf & 0x40) == 0, "reserved G/MOP zero bit clear");
	return 1;
}

static int test_dio_parses_back_with_mop1(void)
{
	struct lichen_rpl_dio dio;

	memset(&dio, 0, sizeof(dio));
	CHECK(captured_len >= IPV6_HDR_LEN + ICMPV6_HDR_LEN,
	      "captured packet covers IPv6 + ICMPv6 headers");
	CHECK(lichen_rpl_dio_parse(&dio, captured + IPV6_HDR_LEN + ICMPV6_HDR_LEN,
				   captured_len - IPV6_HDR_LEN - ICMPV6_HDR_LEN) ==
		      0,
	      "emitted DIO parses cleanly (options framing-valid)");
	CHECK(dio.mode_of_operation == DIO_MOP_NON_STORING,
	      "parsed MOP is 1: passes the C RX admission gate (dodag.c "
	      "rejects MOP != 1), so C leaves accept a C root's DIO");
	CHECK(memcmp(dio.dodag_id, DODAG_ID, 16) == 0, "DODAGID round-trips");
	return 1;
}

static int test_dio_advertises_required_options(void)
{
	/* Presence, not just framing: a C leaf's admission gate requires the
	 * DODAG config and SCHC rule version options (dodag.c), and spec 3.4
	 * R-02-016 requires ASSIGNED_SF for parent selection. If rpl_root.c
	 * stopped emitting any of them, framing-clean parse would still pass
	 * while every C leaf rejected the root — the self-interop break this
	 * suite exists to pin. Walk the raw TLV chain as the independent
	 * oracle. */
	CHECK(captured_len >= IPV6_HDR_LEN + ICMPV6_HDR_LEN + LICHEN_RPL_DIO_BASE_LEN,
	      "captured packet covers the DIO base");
	const uint8_t *opt =
		captured + IPV6_HDR_LEN + ICMPV6_HDR_LEN + LICHEN_RPL_DIO_BASE_LEN;
	const uint8_t *end = captured + captured_len;
	bool have_config = false;
	bool have_rule_version = false;
	bool have_assigned_sf = false;

	while (opt < end) {
		uint8_t otype = opt[0];

		if (otype == 0) { /* PAD1: no length byte */
			opt++;
			continue;
		}
		CHECK(end - opt >= 2, "TLV header in bounds");
		uint8_t olen = opt[1];

		CHECK((size_t)(end - opt - 2) >= olen, "TLV value in bounds");
		if (otype == LICHEN_RPL_OPT_DODAG_CONFIG) {
			have_config = true;
		} else if (otype == LICHEN_RPL_OPT_SCHC_RULE_VERSION) {
			have_rule_version = true;
			CHECK(olen == 1 && opt[2] == LICHEN_SCHC_RULE_SET_VERSION,
			      "rule version matches LICHEN_SCHC_RULE_SET_VERSION");
		} else if (otype == LICHEN_RPL_OPT_ASSIGNED_SF) {
			have_assigned_sf = true;
			CHECK(olen == 1 && opt[2] >= 7 && opt[2] <= 12,
			      "advertised SF in spec 3.4 range 7..12");
		}
		opt += 2 + olen;
	}
	CHECK(have_config, "DODAG config option present (RPL admission)");
	CHECK(have_rule_version,
	      "SCHC rule version option present (spec 5.7; C admission gate)");
	CHECK(have_assigned_sf,
	      "ASSIGNED_SF option present (spec 3.4 R-02-016)");
	return 1;
}

static int test_dio_int_min_matches_runtime_trickle(void)
{
	/* R-RPL: the DODAG config dio_int_min is log2 of the Trickle Imin in
	 * milliseconds (RFC 6550 6.7.6). The runtime Trickle runs
	 * CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS, and a receiver derives
	 * imin = 1 << dio_int_min. The advertised value MUST therefore equal
	 * floor(log2(Imin_ms)); advertising Imin_ms/1000 (e.g. 4 for 4000 ms)
	 * tells receivers a 16 ms Imin while the root runs 4000 ms. Walk the
	 * TLV chain and read the wire value as the independent oracle. */
	const uint8_t *opt =
		captured + IPV6_HDR_LEN + ICMPV6_HDR_LEN + LICHEN_RPL_DIO_BASE_LEN;
	const uint8_t *end = captured + captured_len;
	bool found = false;
	uint8_t advertised = 0;

	while (opt < end) {
		uint8_t otype = opt[0];

		if (otype == 0) { /* PAD1: no length byte */
			opt++;
			continue;
		}
		CHECK(end - opt >= 2, "TLV header in bounds");
		uint8_t olen = opt[1];

		CHECK((size_t)(end - opt - 2) >= olen, "TLV value in bounds");
		if (otype == LICHEN_RPL_OPT_DODAG_CONFIG) {
			/* config data: [flags, doublings, dio_int_min, ...] */
			CHECK(olen >= 3, "config option holds dio_int_min");
			advertised = opt[4];
			found = true;
		}
		opt += 2 + olen;
	}
	CHECK(found, "DODAG config option present");

	/* Independent oracle: floor(log2(CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS)). */
	uint8_t expected = 0;
	uint32_t ms = CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS;
	while (ms > 1U) {
		ms >>= 1;
		expected++;
	}
	if (expected < 1U) {
		expected = 1U;
	} else if (expected > 30U) {
		expected = 30U;
	}
	CHECK(advertised == expected,
	      "advertised dio_int_min is log2(Imin_ms), matching runtime");
	/* The derived interval 1<<dio_int_min must be the same order as the
	 * configured Imin (within one doubling, since floor(log2) rounds
	 * down). */
	CHECK((1UL << advertised) <= CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS,
	      "derived Imin does not exceed configured Imin");
	CHECK((1UL << (advertised + 1)) > CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS,
	      "derived Imin is the tightest power-of-two lower bound");
	return 1;
}

static int test_send_dio_without_iface_fails_clean(void)
{
	struct lichen_rpl_root no_iface;
	unsigned before = recv_calls;

	CHECK(lichen_rpl_root_init(&no_iface, NULL, DODAG_ID, NODE_ADDR) !=
		      NULL,
	      "init accepts NULL iface");
	CHECK(!lichen_rpl_root_send_dio(&no_iface),
	      "send_dio fails cleanly with NULL iface");
	CHECK(recv_calls == before, "nothing emitted on the failure path");
	return 1;
}

int main(void)
{
	printf("rpl_root_dio_tx tests (RPL root DIO MOP=1, R-RPL-007):\n");
	RUN_TEST(test_send_dio_emits_one_packet);
	RUN_TEST(test_dio_mop_is_non_storing_on_wire);
	RUN_TEST(test_dio_parses_back_with_mop1);
	RUN_TEST(test_dio_advertises_required_options);
	RUN_TEST(test_dio_int_min_matches_runtime_trickle);
	RUN_TEST(test_send_dio_without_iface_fails_clean);
	printf("rpl_root_dio_tx: %d/%d passed\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
