/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <string.h>
#include <zephyr/ztest.h>
#include <lichen/coap_oscore.h>

BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_COAP_KEYS), "Exercise optional-store absence");

ZTEST_SUITE(endpoint_no_keys, NULL, NULL, NULL, NULL, NULL);

ZTEST(endpoint_no_keys, test_routable_fails_closed_even_with_suffix_context)
{
	/* Pinned yggdrasil-go 422836ee address_test.go origin. */
	struct sockaddr_in6 source = {.sin6_family = AF_INET6};
	const uint8_t upstream[16] = {
		0x02, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e,
		0x43, 0x84, 0x65, 0xdb, 0x8d, 0xb6, 0x68, 0x95,
	};
	uint8_t peer[8];
	/* RFC 8613 C.4: ciphertext and context, not a local encrypt/decrypt oracle. */
	const uint8_t secret[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	const uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
	const uint8_t ciphertext[] = {
		0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c,
		0x16, 0x68, 0xb3, 0x82, 0x5e,
	};
	uint8_t wire[64];
	struct coap_packet request;
	struct coap_option options[4];
	struct oscore_ctx *ctx;
	static struct coap_oscore_unprotect_result result;
	const struct coap_oscore_origin empty = {0};

	oscore_init();
	memcpy(source.sin6_addr.s6_addr, upstream, 16);
	memcpy(peer, upstream + 8, 8);
	peer[0] ^= 2;
	zassert_ok(oscore_ctx_create_with_eui64(secret, salt, sizeof(salt),
		(uint8_t[]){1}, 1, NULL, 0, peer, &ctx));
	zassert_ok(coap_packet_init(&request, wire, sizeof(wire), 1,
		COAP_TYPE_CON, 0, NULL, COAP_METHOD_POST, 1));
	zassert_ok(coap_packet_append_option(&request, COAP_OPTION_OSCORE,
		(uint8_t[]){0x09, 0x14}, 2));
	zassert_ok(coap_packet_append_payload_marker(&request));
	zassert_ok(coap_packet_append_payload(&request, ciphertext, sizeof(ciphertext)));
	zassert_ok(coap_packet_parse(&request, wire, request.offset, options, 4));
	zassert_equal(coap_oscore_unprotect_resource_request(NULL, &request,
		(struct sockaddr *)&source, sizeof(source), COAP_METHOD_GET, &result),
		COAP_RESPONSE_CODE_UNAUTHORIZED);
	zassert_mem_equal(&result.origin, &empty, sizeof(empty));
	const uint8_t *payload;
	zassert_equal(coap_oscore_authorize_mutating_with_origin(NULL, &request,
		(struct sockaddr *)&source, sizeof(source), COAP_METHOD_GET,
		result.plainbuf, sizeof(result.plainbuf), &payload, &result.payload_len,
		&result.ctx, result.piv, &result.piv_len, &result.is_protected, &result.origin),
		COAP_RESPONSE_CODE_UNAUTHORIZED);
	zassert_mem_equal(&result.origin, &empty, sizeof(empty));
	zassert_is_null(result.ctx);
	/* Same already provisioned context is usable through established LL handling. */
	memset(source.sin6_addr.s6_addr, 0, 8);
	source.sin6_addr.s6_addr[0] = 0xfe;
	source.sin6_addr.s6_addr[1] = 0x80;
	zassert_ok(coap_oscore_unprotect_resource_request(NULL, &request,
		(struct sockaddr *)&source, sizeof(source), COAP_METHOD_GET, &result));
	zassert_true(result.origin.authenticated);
	oscore_ctx_free(ctx);
}
