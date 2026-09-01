/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief SCHC round-trip tests using test vectors from Rust implementation
 *
 * Test vectors are hex-encoded IPv6 packets and their expected SCHC-compressed
 * forms. Each test verifies:
 *   1. compress(packet) == expected_compressed
 *   2. decompress(compressed) == packet
 *
 * Note: This test uses 1500-byte buffers (4x per round_trip call) to handle
 * arbitrary MTU-sized packets. This is intentional for test coverage of
 * edge cases. Production code should use appropriately sized buffers.
 */

#include <lichen/schc.h>
#include "schc_internal.h"
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "schc_internal.h"

/* ─── hex helpers ─────────────────────────────────────────────────────────── */

static int hex_to_byte(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
	size_t len = strlen(hex);
	if (len % 2 != 0) {
		return 0;  /* odd-length hex is invalid */
	}
	size_t bytes = len / 2;

	if (bytes > out_len) {
		return 0;
	}

	for (size_t i = 0; i < bytes; i++) {
		int hi = hex_to_byte(hex[i * 2]);
		int lo = hex_to_byte(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0) {
			return 0;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return bytes;
}

/* ─── test framework ──────────────────────────────────────────────────────── */

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
	if (memcmp((a), (b), (len)) != 0) { \
		printf("  FAIL: %s (memory mismatch)\n", msg); \
		return 0; \
	} \
} while (0)

static int round_trip(const char *packet_hex, const char *compressed_hex,
		      uint8_t expected_rule_id)
{
	uint8_t packet[1500];
	uint8_t expected[1500];
	uint8_t comp_buf[1500];
	uint8_t decomp_buf[1500];

	size_t pkt_len = hex_decode(packet_hex, packet, sizeof(packet));
	size_t exp_len = hex_decode(compressed_hex, expected, sizeof(expected));

	if (pkt_len == 0 || exp_len == 0) {
		printf("  FAIL: hex decode error\n");
		return 0;
	}

	/* Test compression */
	int n = lichen_schc_compress(packet, pkt_len, comp_buf, sizeof(comp_buf));
	ASSERT_EQ(n, (int)exp_len, "compress length");
	ASSERT_EQ(comp_buf[0], expected_rule_id, "rule_id");
	ASSERT_MEM_EQ(comp_buf, expected, exp_len, "compress output");

	/* Test decompression */
	int m = lichen_schc_decompress(expected, exp_len, decomp_buf, sizeof(decomp_buf));
	ASSERT_EQ(m, (int)pkt_len, "decompress length");
	ASSERT_MEM_EQ(decomp_buf, packet, pkt_len, "decompress output");

	return 1;
}

/* ─── test vectors (from test/vectors/schc_compression.json) ─────────────── */

static int test_coap_linklocal(void)
{
	return round_trip(
		/* IPv6 + UDP + CoAP link-local packet */
		"6000000000131140fe800000000000000000000000000001"
		"fe80000000000000000000000000000216331633001328dd"
		"40011234ff737461747573",
		/* Expected compressed */
		"00400000000000000001000000000000000233000448d0"
		"ff737461747573",
		0 /* SCHC_RULE_LINK_LOCAL_COAP */
	);
}

static int test_coap_global(void)
{
	return round_trip(
		/* IPv6 + UDP + CoAP canonical global 0200::/8 addresses */
		"6000000000131140"
		"027dd5cfc679ab637dd5cfc679ab6342"
		"02f77a7baa1226b5f57a7baa1226b50c"
		"1633163300132a9b40011234ff737461747573",
		/* Expected Rule Set Version 3 residue. */
		"01407dd5cfc679ab637dd5cfc679ab6342"
		"f77a7baa1226b5f57a7baa1226b50c33000448d0"
		"ff737461747573",
		1 /* SCHC_RULE_GLOBAL_COAP */
	);
}

static int test_icmpv6_echo(void)
{
	return round_trip(
		/* IPv6 + ICMPv6 Echo Request link-local */
		"60000000000c3a40fe800000000000000000000000000001"
		"fe8000000000000000000000000000028000f80eabcd0007"
		"70696e67",
		/* Expected compressed */
		"02400000000000000001000000000000000280abcd0007"
		"70696e67",
		2 /* SCHC_RULE_ICMPV6_ECHO */
	);
}

static int test_rpl_dio(void)
{
	return round_trip(
		/* IPv6 + ICMPv6 RPL DIO */
		"60000000001c3a40fe800000000000000000000000000001"
		"fe8000000000000000000000000000029b01e01f00010100"
		"88000000fe800000000000000000000000000001",
		/* Expected compressed */
		"034000000000000000010000000000000002000101008800"
		"fe800000000000000000000000000001",
		3 /* SCHC_RULE_RPL_DIO */
	);
}

static int test_rpl_dao(void)
{
	return round_trip(
		/* RPL DAO with link-local addresses (matching test/vectors/schc_compression.json) */
		"6000000000183a40fe800000000000000000000000000001"
		"fe8000000000000000000000000000029b0268df00400005"
		"fe800000000000000000000000000001",
		/* Expected compressed per schc_compression.json */
		"044000000000000000010000000000000002004005"
		"fe800000000000000000000000000001",
		4 /* SCHC_RULE_RPL_DAO */
	);
}

static int test_oscore_linklocal(void)
{
	return round_trip(
		/* IPv6 + UDP + OSCORE-protected CoAP link-local (rule 5) */
		"6000000000161140fe800000000000000000000000000001"
		"fe800000000000000000000000000002163316330016517b42"
		"0112340001920900ffdeadbeef",
		/* Expected compressed */
		"05400000000000000001000000000000000233080448d0"
		"0001920900ffdeadbeef",
		5 /* SCHC_RULE_LINK_LOCAL_OSCORE */
	);
}

static int test_oscore_global(void)
{
	return round_trip(
		/* IPv6 + UDP + OSCORE-protected CoAP global (rule 6) */
		"6000000000161140"
		"027dd5cfc679ab637dd5cfc679ab6342"
		"02f77a7baa1226b5f57a7baa1226b50c"
		"163316330016533942"
		"0112340001920900ffdeadbeef",
		/* Expected Rule Set Version 3 residue. */
		"06407dd5cfc679ab637dd5cfc679ab6342"
		"f77a7baa1226b5f57a7baa1226b50c33080448d0"
		"0001920900ffdeadbeef",
		6 /* SCHC_RULE_GLOBAL_OSCORE */
	);
}

static int test_reject_non_ipv6_input(void)
{
	uint8_t comp_buf[8];
	uint8_t decomp_buf[8];
	uint8_t big_comp_buf[128];
	uint8_t big_decomp_buf[128];
	/* Compress accepts full IPv6 packets only (Python/Rust reference
	 * behavior): short garbage and non-IPv6 versions must be rejected,
	 * never emitted as Rule255 - a Rust/Python peer fatals on such
	 * datagrams at decode_rule255. */
	static const uint8_t garbage[4] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t ipv4ish[45] = { 0 };
	int n;

	ipv4ish[0] = 0x45; /* IPv4 version 4, IHL 5 */

	n = lichen_schc_compress(garbage, sizeof(garbage), comp_buf,
				 sizeof(comp_buf));
	if (n != SCHC_ERR_INVALID_ARGUMENT) {
		printf("  FAIL: short garbage expected SCHC_ERR_INVALID_ARGUMENT (got %d)\n",
		       n);
		return 0;
	}

	/* Rule 255 RX validates the payload as a complete IPv6 packet, so a
	 * non-IPv6 rule255 wire (rule byte + garbage) must be rejected by the
	 * payload validator itself — not by a length/ceiling accident. */
	static const uint8_t bad_rule255[5] = { 0xff, 0xde, 0xad, 0xbe, 0xef };
	int m = lichen_schc_decompress(bad_rule255, sizeof(bad_rule255),
				       decomp_buf, sizeof(decomp_buf));
	if (m >= 0) {
		printf("  FAIL: non-IPv6 rule255 payload decoded (%d)\n", m);
		return 0;
	}

	/* Legitimate fallback: a valid IPv6 packet whose ports match no rule
	 * round-trips byte-preserving. */
	uint8_t v6[52];
	memset(v6, 0, sizeof(v6));
	v6[0] = 0x60;
	v6[5] = 12;
	v6[6] = 17;
	v6[7] = 64;
	memcpy(&v6[8], "\xfe\x80\x00\x00\x00\x00\x00\x00"
		      "\x00\x00\x00\x00\x00\x00\x00\x01", 16);
	memcpy(&v6[24], "\xfe\x80\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x02", 16);
	v6[40] = 0x13;
	v6[41] = 0x88; /* src port 5000: matches no rule */
	v6[42] = 0x13;
	v6[43] = 0x89; /* dst port 5001 */
	v6[44] = 0;
	v6[45] = 12;
	memcpy(&v6[48], "ping", 4);
	uint16_t checksum = 0;
	if (udp_checksum(&v6[8], &v6[24], 5000, 5001, &v6[48], 4,
			 &checksum) != SCHC_OK) {
		printf("  FAIL: udp_checksum helper\n");
		return 0;
	}
	v6[46] = (uint8_t)(checksum >> 8);
	v6[47] = (uint8_t)(checksum & 0xff);

	n = lichen_schc_compress(v6, sizeof(v6), big_comp_buf,
				 sizeof(big_comp_buf));
	if (n != (int)sizeof(v6) + 1 || big_comp_buf[0] != 255) {
		printf("  FAIL: valid fallback emit (got %d)\n", n);
		return 0;
	}
	m = lichen_schc_decompress(big_comp_buf, n, big_decomp_buf,
				   sizeof(big_decomp_buf));
	if (m != (int)sizeof(v6) || memcmp(big_decomp_buf, v6, sizeof(v6)) != 0) {
		printf("  FAIL: valid fallback round-trip (got %d)\n", m);
		return 0;
	}

	n = lichen_schc_compress(ipv4ish, sizeof(ipv4ish), comp_buf,
				 sizeof(comp_buf));
	if (n != SCHC_ERR_INVALID_ARGUMENT) {
		printf("  FAIL: version-4 input expected SCHC_ERR_INVALID_ARGUMENT (got %d)\n",
		       n);
		return 0;
	}

	return 1;
}

static int test_unknown_rule_id(void)
{
	uint8_t data[5] = { 0x7e, 0xde, 0xad, 0xbe, 0xef };
	uint8_t out[64];

	int ret = lichen_schc_decompress(data, 5, out, sizeof(out));
	if (ret != SCHC_ERR_UNKNOWN_RULE_ID) {
		printf("  FAIL: expected SCHC_ERR_UNKNOWN_RULE_ID (got %d)\n", ret);
		return 0;
	}
	return 1;
}

static int test_truncated_coap_linklocal(void)
{
	/* Rule 0 needs 23 bytes (one Rule ID plus 174 residue bits). */
	uint8_t data[22] = { 0 };
	uint8_t out[64];

	int ret = lichen_schc_decompress(data, sizeof(data), out, sizeof(out));
	if (ret != SCHC_ERR_TOO_SHORT) {
		printf("  FAIL: expected SCHC_ERR_TOO_SHORT for 22-byte input (got %d)\n", ret);
		return 0;
	}
	return 1;
}

static int test_truncated_coap_global(void)
{
	/* Rule 1 needs 37 bytes (one Rule ID plus 286 residue bits). */
	uint8_t data[36] = { 1 };
	uint8_t out[64];

	int ret = lichen_schc_decompress(data, sizeof(data), out, sizeof(out));
	if (ret != SCHC_ERR_TOO_SHORT) {
		printf("  FAIL: expected SCHC_ERR_TOO_SHORT for 36-byte input (got %d)\n", ret);
		return 0;
	}
	return 1;
}

static int test_null_public_args(void)
{
	uint8_t packet[40] = { 0x60 };
	uint8_t data[1] = { SCHC_RULE_UNCOMPRESSED };
	uint8_t out[64];
	volatile uint8_t *null_ptr = NULL;
	int ret;

	ret = lichen_schc_compress((const uint8_t *)null_ptr,
				    sizeof(packet), out, sizeof(out));
	if (ret != SCHC_ERR_INVALID_ARGUMENT) {
		printf("  FAIL: compress NULL packet expected SCHC_ERR_INVALID_ARGUMENT (got %d)\n", ret);
		return 0;
	}

	ret = lichen_schc_compress(packet, sizeof(packet),
				    (uint8_t *)null_ptr, sizeof(out));
	if (ret != SCHC_ERR_BUFFER_TOO_SMALL) {
		printf("  FAIL: compress NULL out expected SCHC_ERR_BUFFER_TOO_SMALL (got %d)\n", ret);
		return 0;
	}

	ret = lichen_schc_decompress((const uint8_t *)null_ptr,
				      sizeof(data), out, sizeof(out));
	if (ret != SCHC_ERR_TOO_SHORT) {
		printf("  FAIL: decompress NULL data expected SCHC_ERR_TOO_SHORT (got %d)\n", ret);
		return 0;
	}

	ret = lichen_schc_decompress(data, sizeof(data),
				      (uint8_t *)null_ptr, sizeof(out));
	if (ret != SCHC_ERR_BUFFER_TOO_SMALL) {
		printf("  FAIL: decompress NULL out expected SCHC_ERR_BUFFER_TOO_SMALL (got %d)\n", ret);
		return 0;
	}

	return 1;
}

static int test_reject_bad_ipv6_payload_len(void)
{
	uint8_t packet[1500];
	uint8_t comp_buf[1500];
	size_t pkt_len = hex_decode(
		"6000000000131140fe800000000000000000000000000001"
		"fe80000000000000000000000000000216331633001328dd"
		"40011234ff737461747573",
		packet, sizeof(packet));

	if (pkt_len == 0) {
		printf("  FAIL: hex decode error\n");
		return 0;
	}

	packet[5]--; /* IPv6 Payload Length no longer matches pkt_len. */

	int ret = lichen_schc_compress(packet, pkt_len, comp_buf, sizeof(comp_buf));
	if (ret != SCHC_ERR_NO_MATCHING_RULE) {
		printf("  FAIL: bad IPv6 Payload Length expected SCHC_ERR_NO_MATCHING_RULE (got %d)\n",
		       ret);
		return 0;
	}

	return 1;
}

static int test_reject_bad_udp_len(void)
{
	uint8_t packet[1500];
	uint8_t comp_buf[1500];
	size_t pkt_len = hex_decode(
		"6000000000131140fe800000000000000000000000000001"
		"fe80000000000000000000000000000216331633001328dd"
		"40011234ff737461747573",
		packet, sizeof(packet));

	if (pkt_len == 0) {
		printf("  FAIL: hex decode error\n");
		return 0;
	}

	packet[45]--; /* UDP Length no longer matches the IPv6 payload length. */

	int ret = lichen_schc_compress(packet, pkt_len, comp_buf, sizeof(comp_buf));
	if (ret != SCHC_ERR_NO_MATCHING_RULE) {
		printf("  FAIL: bad UDP Length expected SCHC_ERR_NO_MATCHING_RULE (got %d)\n",
		       ret);
		return 0;
	}

	return 1;
}

static int test_validator_direct_call_self_defense(void)
{
	/* Direct-call contract of validate_ipv6_transport_lengths (internal
	 * validator, schc_internal.h): must be self-defending regardless of
	 * caller guarantees - truncation shorter than the IPv6 header must
	 * reject without reading past the buffer (regression guard for the
	 * latent stack OOB tracked by project-LICHEN-worker6-nyx7), and a
	 * non-IPv6 version must reject without relying on the caller's
	 * version check (bead project-LICHEN-worker6-uylk), mirroring the
	 * internal checks of the Python and Rust validators. */
	static const uint8_t truncated[4] = { 0x60, 0x00, 0x00, 0x00 };
	static const uint8_t version4[40] = { [0] = 0x45, [6] = 59 };
	/* version nibble 4 with a chain-terminating next-header so the version
	 * check is the ONLY rejection path: pre-uylk code returned SCHC_OK
	 * here (non-UDP terminal, zero payload length consistent), so this
	 * fixture discriminates a revert of the self-check. Addresses are
	 * valid link-locals: the structural address constraints (unspecified
	 * or multicast source, unspecified destination) must not fire on this
	 * fixture — it targets the version self-check only. */
	static const uint8_t minimal_v6[40] = { [0] = 0x60,
						[6] = 59,
						[8] = 0xfe,
						[9] = 0x80,
						[24] = 0xfe,
						[25] = 0x80 };
	uint8_t coap[64];
	size_t coap_len;
	int ret;

	coap_len = hex_decode(
		"6000000000131140fe800000000000000000000000000001"
		"fe80000000000000000000000000000216331633001328dd"
		"40011234ff737461747573",
		coap, sizeof(coap));
	if (coap_len == 0) {
		printf("  FAIL: hex decode error\n");
		return 0;
	}

	ret = validate_ipv6_transport_lengths(truncated, sizeof(truncated));
	if (ret != SCHC_ERR_NO_MATCHING_RULE) {
		printf("  FAIL: truncated input expected SCHC_ERR_NO_MATCHING_RULE (got %d)\n",
		       ret);
		return 0;
	}

	ret = validate_ipv6_transport_lengths(version4, sizeof(version4));
	if (ret != SCHC_ERR_NO_MATCHING_RULE) {
		printf("  FAIL: version-4 input expected SCHC_ERR_NO_MATCHING_RULE (got %d)\n",
		       ret);
		return 0;
	}

	ret = validate_ipv6_transport_lengths(minimal_v6, sizeof(minimal_v6));
	if (ret != SCHC_OK) {
		printf("  FAIL: minimal version-6 header expected SCHC_OK (got %d)\n", ret);
		return 0;
	}

	ret = validate_ipv6_transport_lengths(coap, coap_len);
	if (ret != SCHC_OK) {
		printf("  FAIL: valid CoAP packet expected SCHC_OK (got %d)\n", ret);
		return 0;
	}

	return 1;
}

static int test_uncompressed_length_exceeds_int(void)
{
	static const uint8_t packet = 0;
	volatile size_t pkt_len = (size_t)INT_MAX;
	uint8_t out;
	int ret = lichen_schc_compress(&packet, pkt_len, &out, SIZE_MAX);

	ASSERT_EQ(ret, SCHC_ERR_BUFFER_TOO_SMALL, "uncompressed int length overflow");
	return 1;
}

static int test_rule255_fallback_profile_ceiling(void)
{
	/* A valid version-6 packet that matches no rule falls back to Rule
	 * 255; its encoded output (1 + raw) must fit the profile ceiling.
	 * TCP next-header matches no rule, so payload length drives raw size:
	 * raw 22553 encodes to 22554 (exactly the ceiling); raw 22554 would
	 * encode to 22555 and must be rejected (Rust encode_rule255 parity). */
	static uint8_t packet[SCHC_FRAGMENT_MAX_PACKET_SIZE];
	uint8_t comp_buf[SCHC_FRAGMENT_MAX_PACKET_SIZE + 2];
	size_t pkt_len;

	memset(packet, 0, sizeof(packet));
	packet[0] = 0x60; /* version 6, TC/FL zero */
	packet[6] = 6;    /* TCP: no compression rule matches */
	/* src/dst fe80::1 / fe80::2 (policy-clean), payload = 22553 - 40. */
	memcpy(&packet[8], "\xfe\x80\x00\x00\x00\x00\x00\x00"
			  "\x00\x00\x00\x00\x00\x00\x00\x01", 16);
	memcpy(&packet[24], "\xfe\x80\x00\x00\x00\x00\x00\x00"
			    "\x00\x00\x00\x00\x00\x00\x00\x02", 16);
	packet[4] = (uint8_t)((22553u - 40u) >> 8);
	packet[5] = (uint8_t)((22553u - 40u) & 0xff);

	pkt_len = 22553;
	int ret = lichen_schc_compress(packet, pkt_len, comp_buf, sizeof(comp_buf));
	ASSERT_EQ(ret, SCHC_FRAGMENT_MAX_PACKET_SIZE, "fallback at ceiling");
	ASSERT_EQ(comp_buf[0], SCHC_RULE_UNCOMPRESSED, "fallback rule id");

	pkt_len = 22554;
	packet[5] = (uint8_t)((22554u - 40u) & 0xff);
	memset(comp_buf, 0xA5, sizeof(comp_buf));
	ret = lichen_schc_compress(packet, pkt_len, comp_buf, sizeof(comp_buf));
	ASSERT_EQ(ret, SCHC_ERR_BUFFER_TOO_SMALL, "fallback over ceiling");
	ASSERT_EQ(comp_buf[0], 0xA5, "fallback over ceiling atomic");
	return 1;
}

static int test_rule255_ingress_profile_ceiling(void)
{
	/* Decompress ingress enforces the encoded-SCHC-packet profile ceiling
	 * for every rule including Rule 255 (mirrors Rust decompress,
	 * codec.rs:2270): exactly-ceiling input decodes; ceiling+1 rejects
	 * without touching the output buffer. */
	static uint8_t data[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	static uint8_t out[SCHC_FRAGMENT_MAX_PACKET_SIZE];
	static uint8_t sentinel[SCHC_FRAGMENT_MAX_PACKET_SIZE];

	memset(data, 0x41, sizeof(data));
	data[0] = SCHC_RULE_UNCOMPRESSED;
	/* Payload must be a valid IPv6 packet (Rule 255 RX contract): build a
	 * TCP packet (no UDP checksum needed) filling the ceiling exactly.
	 * data[1..41] is the IPv6 header, payload 22553 - 40 = 22513 bytes. */
	data[1] = 0x60;
	data[5] = (uint8_t)((22553u - 40u) >> 8);
	data[6] = (uint8_t)((22553u - 40u) & 0xff);
	data[7] = 6; /* next header: TCP */
	memcpy(&data[9], "\xfe\x80\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x01", 16);
	memcpy(&data[25], "\xfe\x80\x00\x00\x00\x00\x00\x00"
			  "\x00\x00\x00\x00\x00\x00\x00\x02", 16);
	memset(sentinel, 0xA5, sizeof(sentinel));

	int m = lichen_schc_decompress(data, SCHC_FRAGMENT_MAX_PACKET_SIZE,
				       out, sizeof(out));
	ASSERT_EQ(m, SCHC_FRAGMENT_MAX_PACKET_SIZE - 1, "rule255 at ceiling");

	memset(out, 0xA5, sizeof(out));
	m = lichen_schc_decompress(data, SCHC_FRAGMENT_MAX_PACKET_SIZE + 1,
				   out, sizeof(out));
	ASSERT_EQ(m, SCHC_ERR_BUFFER_TOO_SMALL, "rule255 over ceiling");
	ASSERT_MEM_EQ(out, sentinel, sizeof(out), "rule255 over ceiling atomic");
	return 1;
}

/* ─── test runner ─────────────────────────────────────────────────────────── */

#define RUN_TEST(fn) do { \
	printf("  %s...", #fn); \
	tests_run++; \
	if (fn()) { \
		printf(" OK\n"); \
		tests_passed++; \
	} \
} while (0)

int main(void)
{
	printf("SCHC Round-Trip Tests\n");
	printf("=====================\n\n");

	RUN_TEST(test_coap_linklocal);
	RUN_TEST(test_coap_global);
	RUN_TEST(test_icmpv6_echo);
	RUN_TEST(test_rpl_dio);
	RUN_TEST(test_rpl_dao);
	RUN_TEST(test_oscore_linklocal);
	RUN_TEST(test_oscore_global);
	RUN_TEST(test_reject_non_ipv6_input);
	RUN_TEST(test_validator_direct_call_self_defense);
	RUN_TEST(test_unknown_rule_id);
	RUN_TEST(test_truncated_coap_linklocal);
	RUN_TEST(test_truncated_coap_global);
	RUN_TEST(test_null_public_args);
	RUN_TEST(test_reject_bad_ipv6_payload_len);
	RUN_TEST(test_reject_bad_udp_len);
	RUN_TEST(test_uncompressed_length_exceeds_int);
	RUN_TEST(test_rule255_fallback_profile_ceiling);
	RUN_TEST(test_rule255_ingress_profile_ceiling);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
