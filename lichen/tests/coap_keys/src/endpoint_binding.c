/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <string.h>
#include <zephyr/ztest.h>
#include <lichen/coap_keys.h>
#include <lichen/coap_oscore.h>

/* yggdrasil-go 422836eeb21a99790caa286aa63d493bbc4766d7,
 * src/address/address_test.go; also test/vectors/yggdrasil_address.json.
 * IID independently calculated with Python hashlib.sha512, U/L cleared. */
static const uint8_t key[32] = {
	0xbd, 0xba, 0xcf, 0xd8, 0x22, 0x40, 0xde, 0x3d,
	0xcd, 0x12, 0x39, 0x24, 0xcb, 0xb5, 0x52, 0x56,
	0xfb, 0x8d, 0xab, 0x08, 0xaa, 0x98, 0xe3, 0x05,
	0x52, 0x8a, 0xb8, 0x4f, 0x41, 0x9e, 0x6e, 0xfb,
};
static const uint8_t iid[8] = {0xcd, 0x97, 0x71, 0xd9, 0xdd, 0x74, 0x59, 0x46};
static const uint8_t upstream[16] = {
	0x02, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e,
	0x43, 0x84, 0x65, 0xdb, 0x8d, 0xb6, 0x68, 0x95,
};

/* RFC 8613 Appendix C.1/C.4, GET /tv1, no payload, PIV 20. */
static const uint8_t secret[16] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
};
static const uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
static const uint8_t ciphertext[] = {
	0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c,
	0x16, 0x68, 0xb3, 0x82, 0x5e,
};

static struct oscore_ctx *ctx;
void oscore_test_exhaust_generations(void);
static struct coap_oscore_unprotect_result result;
static struct sockaddr_in6 source;
static struct coap_packet request;
static uint8_t wire[64];
static uint16_t wire_len;

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	lichen_key_store_test_reset();
	oscore_init();
	oscore_nvm_register_callbacks(NULL, NULL);
	ctx = NULL;
	memset(&source, 0, sizeof(source));
	source.sin6_family = AF_INET6;
	memcpy(source.sin6_addr.s6_addr, upstream, 16);
	zassert_ok(coap_packet_init(&request, wire, sizeof(wire), 1,
		COAP_TYPE_CON, 0, NULL, COAP_METHOD_POST, 1));
	zassert_ok(coap_packet_append_option(&request, COAP_OPTION_OSCORE,
		(uint8_t[]){0x09, 0x14}, 2));
	zassert_ok(coap_packet_append_payload_marker(&request));
	zassert_ok(coap_packet_append_payload(&request, ciphertext, sizeof(ciphertext)));
	wire_len = request.offset;
}

static void after(void *fixture)
{
	ARG_UNUSED(fixture);
	if (ctx != NULL) {
		oscore_ctx_free(ctx);
	}
	lichen_key_store_test_reset();
}

static void provision(const uint8_t peer[8])
{
	zassert_ok(lichen_key_store_put(iid, key, LICHEN_KEY_TRUST_VERIFIED));
	int ret = oscore_ctx_create_with_eui64(secret, salt, sizeof(salt),
		(uint8_t[]){1}, 1, NULL, 0, peer, &ctx);
	zassert_equal(ret, OSCORE_OK, "context creation: %d", ret);
}

static int authorize(bool legacy, uint8_t method)
{
	struct coap_option options[4];
	zassert_ok(coap_packet_parse(&request, wire, wire_len, options, 4));
	memset(&result, 0xa5, sizeof(result));
	if (legacy) {
		const uint8_t *payload;
		int ret = coap_oscore_authorize_mutating_with_origin(NULL, &request,
			(struct sockaddr *)&source, sizeof(source), method,
			result.plainbuf, sizeof(result.plainbuf), &payload,
			&result.payload_len, &result.ctx, result.piv, &result.piv_len,
			&result.is_protected, &result.origin);
		return ret;
	}
	return coap_oscore_unprotect_resource_request(NULL, &request,
		(struct sockaddr *)&source, sizeof(source), method, &result);
}

static void no_evidence(void)
{
	const struct coap_oscore_origin empty = {0};
	zassert_mem_equal(&result.origin, &empty, sizeof(empty));
	zassert_is_null(result.ctx);
}

ZTEST_SUITE(endpoint_binding, NULL, NULL, before, after, NULL);

ZTEST(endpoint_binding, test_upstream_lookup_is_copied_and_read_only)
{
	struct lichen_key_entry entry;
	struct lichen_key_entry original;

	provision(iid);
	zassert_ok(lichen_key_store_get(iid, &original));
	zassert_ok(lichen_key_store_get_by_ygg_addr(upstream, &entry));
	zassert_mem_equal(&entry, &original, sizeof(entry));
	entry.iid[0] ^= 1;
	zassert_ok(lichen_key_store_get_by_ygg_addr(upstream, &entry));
	zassert_mem_equal(&entry, &original, sizeof(entry));
	zassert_equal(lichen_key_store_count(), 1);
}

ZTEST(endpoint_binding, test_both_helpers_authenticate_full_origin)
{
	for (int legacy = 0; legacy < 2; legacy++) {
		provision(iid);
		zassert_ok(authorize(legacy, COAP_METHOD_GET));
		zassert_true(result.origin.authenticated);
		zassert_mem_equal(result.origin.iid, iid, 8);
		zassert_mem_equal(result.origin.address, upstream, 16);
		zassert_equal(result.ctx, ctx);
		zassert_equal(result.payload_len, 0);
		zassert_equal(result.piv_len, 1);
		zassert_equal(result.piv[0], 20);
		oscore_ctx_free(ctx);
		ctx = NULL;
	}
}

ZTEST(endpoint_binding, test_aliases_and_unsupported_classes_fail)
{
	provision(iid);
	for (int legacy = 0; legacy < 2; legacy++) {
		/* Same full suffix, different prefix within 0200::/8. */
		source.sin6_addr.s6_addr[2] ^= 1;
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
		memcpy(source.sin6_addr.s6_addr, upstream, 16);
		/* A forged routable address carrying the canonical IID. */
		memcpy(source.sin6_addr.s6_addr + 8, iid, 8);
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
		memcpy(source.sin6_addr.s6_addr, upstream, 16);
		const uint8_t classes[] = {3, 0xfd, 0xff, 0x20, 0};
		for (size_t i = 0; i < sizeof(classes); i++) {
			source.sin6_addr.s6_addr[0] = classes[i];
			zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
			no_evidence();
		}
		memcpy(source.sin6_addr.s6_addr, upstream, 16);
	}
}

ZTEST(endpoint_binding, test_unknown_missing_and_wrong_binding_no_creation)
{
	for (int legacy = 0; legacy < 2; legacy++) {
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
		zassert_ok(lichen_key_store_put(iid, key, LICHEN_KEY_TRUST_TOFU));
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
		struct oscore_ctx *absent = NULL;
		zassert_not_equal(oscore_ctx_get_by_eui64(iid, &absent), OSCORE_OK);
		zassert_is_null(absent);
		uint8_t wrong[8];
		memcpy(wrong, iid, 8);
		wrong[0] ^= 2;
		provision(wrong);
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
		oscore_ctx_free(ctx);
		ctx = NULL;
		lichen_key_store_test_reset();
	}
}

ZTEST(endpoint_binding, test_auth_and_method_failure_publish_no_evidence)
{
	for (int legacy = 0; legacy < 2; legacy++) {
		provision(iid);
		wire[wire_len - 1] ^= 1;
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
		wire[wire_len - 1] ^= 1;
		zassert_equal(authorize(legacy, COAP_METHOD_POST), COAP_RESPONSE_CODE_NOT_ALLOWED);
		no_evidence();
		oscore_ctx_free(ctx);
		ctx = NULL;
	}
}

ZTEST(endpoint_binding, test_plaintext_policies_publish_no_evidence)
{
	zassert_ok(coap_packet_init(&request, wire, sizeof(wire), 1,
		COAP_TYPE_CON, 0, NULL, COAP_METHOD_GET, 1));
	wire_len = request.offset;
	zassert_ok(authorize(false, COAP_METHOD_GET));
	no_evidence();
	zassert_equal(authorize(true, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
	no_evidence();
	memset(source.sin6_addr.s6_addr, 0, 16);
	source.sin6_addr.s6_addr[15] = 1;
	zassert_ok(authorize(true, COAP_METHOD_GET));
	no_evidence();
}

ZTEST(endpoint_binding, test_invalid_origin_shape)
{
	provision(iid);
	struct coap_option options[4];
	zassert_ok(coap_packet_parse(&request, wire, wire_len, options, 4));
	zassert_equal(coap_oscore_unprotect_resource_request(NULL, &request,
		NULL, 0, COAP_METHOD_GET, &result), COAP_RESPONSE_CODE_UNAUTHORIZED);
	no_evidence();
	zassert_equal(coap_oscore_unprotect_resource_request(NULL, &request,
		(struct sockaddr *)&source, sizeof(source) - 1, COAP_METHOD_GET, &result),
		COAP_RESPONSE_CODE_UNAUTHORIZED);
	no_evidence();
	source.sin6_family = AF_INET;
	for (int legacy = 0; legacy < 2; legacy++) {
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
	}
}

ZTEST(endpoint_binding, test_known_wrong_origin_context_cannot_authenticate)
{
	/* RFC 8032 TEST 1 key and upstream address from the conformance corpus. */
	const uint8_t other_key[32] = {
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
	};
	const uint8_t other_iid[8] = {0x0c, 0x02, 0xa5, 0x02, 0x25, 0xb4, 0xba, 0xaa};
	const uint8_t other_addr[16] = {
		0x02, 0x00, 0x51, 0x4a, 0xcf, 0xfc, 0xfa, 0x9d,
		0xea, 0x90, 0x55, 0x68, 0x02, 0x58, 0x6d, 0x37,
	};
	uint8_t other_secret[16];
	struct oscore_ctx *other_ctx;
	provision(iid);
	memcpy(other_secret, secret, sizeof(secret));
	other_secret[0] ^= 1;
	zassert_ok(lichen_key_store_put(other_iid, other_key, LICHEN_KEY_TRUST_TOFU));
	zassert_ok(oscore_ctx_create_with_eui64(other_secret, salt, sizeof(salt),
		(uint8_t[]){1}, 1, NULL, 0, other_iid, &other_ctx));
	memcpy(source.sin6_addr.s6_addr, other_addr, 16);
	for (int legacy = 0; legacy < 2; legacy++) {
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
	}
	oscore_ctx_free(other_ctx);
	/* The failed wrong-origin requests must not consume the true context. */
	memcpy(source.sin6_addr.s6_addr, upstream, 16);
	zassert_ok(authorize(false, COAP_METHOD_GET));
}

ZTEST(endpoint_binding, test_established_linklocal_context)
{
	uint8_t peer[8];
	memcpy(peer, iid, 8);
	peer[0] ^= 2;
	memset(source.sin6_addr.s6_addr, 0, 16);
	source.sin6_addr.s6_addr[0] = 0xfe;
	source.sin6_addr.s6_addr[1] = 0x80;
	memcpy(source.sin6_addr.s6_addr + 8, iid, 8);
	for (int legacy = 0; legacy < 2; legacy++) {
		provision(peer);
		zassert_ok(authorize(legacy, COAP_METHOD_GET));
		zassert_mem_equal(result.origin.iid, iid, 8);
		zassert_mem_equal(result.origin.address, source.sin6_addr.s6_addr, 16);
		oscore_ctx_free(ctx);
		ctx = NULL;
	}
}

ZTEST(endpoint_binding, test_ambiguous_upstream_address)
{
	/* Independent degenerate upstream vectors: all-zero and all-ff keys
	 * both map to 0200::, with distinct SHA-512 canonical IIDs. */
	const uint8_t zero[32] = {0};
	uint8_t ones[32];
	const uint8_t zero_iid[8] = {0x50, 0x46, 0xad, 0xc1, 0xdb, 0xa8, 0x38, 0x86};
	const uint8_t ones_iid[8] = {0x25, 0xcd, 0x69, 0x35, 0x86, 0x47, 0x16, 0xa7};
	const uint8_t ambiguous[16] = {2};
	struct lichen_key_entry entry = {0};
	const struct lichen_key_entry empty = {0};
	memset(ones, 0xff, sizeof(ones));
	zassert_ok(lichen_key_store_put(zero_iid, zero, LICHEN_KEY_TRUST_TOFU));
	zassert_ok(lichen_key_store_put(ones_iid, ones, LICHEN_KEY_TRUST_TOFU));
	zassert_equal(lichen_key_store_get_by_ygg_addr(ambiguous, &entry), -EEXIST);
	zassert_mem_equal(&entry, &empty, sizeof(entry));
	memcpy(source.sin6_addr.s6_addr, ambiguous, 16);
	for (int legacy = 0; legacy < 2; legacy++) {
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
	}
}

ZTEST(endpoint_binding, test_duplicate_contexts_rejected_before_kid_selection)
{
	struct oscore_ctx *duplicate;
	uint8_t other_secret[16] = {0x42};
	provision(iid);
	zassert_ok(oscore_ctx_create_with_eui64(other_secret, NULL, 0,
		(uint8_t[]){3}, 1, (uint8_t[]){4}, 1, iid, &duplicate));
	for (int legacy = 0; legacy < 2; legacy++) {
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
	}
	oscore_ctx_free(duplicate);
	zassert_ok(authorize(false, COAP_METHOD_GET));
}

ZTEST(endpoint_binding, test_reference_response_matches_rfc8613_c7)
{
	const uint8_t expected[] = {0xdb, 0xaa, 0xd1, 0xe9, 0xa7, 0xe7, 0xb2,
		0xa8, 0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37, 0x83, 0x03,
		0xcd, 0xaf, 0xae, 0x11, 0x91, 0x06};
	uint8_t ct[32], opt[8];
	size_t ct_len = sizeof(ct), opt_len = sizeof(opt);
	provision(iid);
	zassert_ok(authorize(false, COAP_METHOD_GET));
	zassert_ok(oscore_protect_response_ref(&result.origin.response_ctx,
		(uint8_t[]){20}, 1, 69, NULL, 0, (const uint8_t *)"Hello World!", 12,
		ct, &ct_len, opt, &opt_len));
	zassert_equal(ct_len, sizeof(expected));
	zassert_mem_equal(ct, expected, sizeof(expected));
	zassert_equal(opt_len, 0);
}

ZTEST(endpoint_binding, test_id_context_construction_captures_new_generation)
{
	/* RFC 8613 C.6. */
	const uint8_t id_context[] = {0x37, 0xcb, 0xf3, 0x21, 0, 0x17, 0xa2, 0xd3};
	const uint8_t option[] = {0x19, 0x14, 8, 0x37, 0xcb, 0xf3, 0x21, 0, 0x17, 0xa2, 0xd3};
	const uint8_t ct[] = {0x72, 0xcd, 0x72, 0x73, 0xfd, 0x33, 0x1a,
		0xc4, 0x5c, 0xff, 0xbe, 0x55, 0xc3};
	uint64_t previous = 0;
	for (int i = 0; i < 2; i++) {
		struct oscore_ctx_ref ref;
		uint8_t code, opts[8], payload[8];
		size_t opts_len = sizeof(opts), payload_len = sizeof(payload);
		zassert_ok(oscore_ctx_create_with_id_context(secret, salt, sizeof(salt),
			(uint8_t[]){1}, 1, NULL, 0, id_context, sizeof(id_context), &ctx));
		zassert_ok(oscore_ctx_set_peer_eui64(ctx, iid));
		zassert_ok(oscore_unprotect_request_by_peer(iid, option, sizeof(option),
			ct, sizeof(ct), &code, opts, &opts_len, payload, &payload_len, &ref));
		zassert_equal(code, COAP_METHOD_GET);
		zassert_true(ref.generation > previous);
		previous = ref.generation;
		oscore_ctx_free(ctx);
		ctx = NULL;
	}
}

static void stale_response(const struct oscore_ctx_ref *ref)
{
	uint8_t ciphertext_out[32], option[8];
	size_t ct_len = sizeof(ciphertext_out), opt_len = sizeof(option);
	memset(ciphertext_out, 0xa5, sizeof(ciphertext_out));
	zassert_equal(oscore_protect_response_ref(ref, (uint8_t[]){20}, 1,
		COAP_RESPONSE_CODE_CONTENT, NULL, 0, NULL, 0,
		ciphertext_out, &ct_len, option, &opt_len), OSCORE_ERR_CONTEXT_STALE);
	for (size_t i = 0; i < sizeof(ciphertext_out); i++) {
		zassert_equal(ciphertext_out[i], 0xa5);
	}
}

ZTEST(endpoint_binding, test_free_reuse_init_and_response_fallback_are_stale)
{
	provision(iid);
	zassert_ok(authorize(false, COAP_METHOD_GET));
	struct oscore_ctx_ref old = result.origin.response_ctx;
	oscore_ctx_free(ctx);
	ctx = NULL;
	stale_response(&old);
	zassert_ok(oscore_init());
	provision(iid);
	zassert_equal(ctx, old.ctx, "test must force same-slot reuse");
	stale_response(&old);
	/* Both normal and empty-500 retry must retain the stale token, without
	 * dereferencing the NULL resource to send anything. */
	zassert_equal(coap_oscore_respond_resource(NULL, &request,
		(struct sockaddr *)&source, sizeof(source), &result,
		COAP_RESPONSE_CODE_CONTENT, 0, NULL, 0), OSCORE_ERR_CONTEXT_STALE);
	zassert_ok(authorize(false, COAP_METHOD_GET));
	zassert_not_equal(result.origin.response_ctx.generation, old.generation);
}

ZTEST(endpoint_binding, test_rebind_away_and_back_invalidates_reference)
{
	uint8_t other[8] = {7};
	provision(iid);
	zassert_ok(authorize(true, COAP_METHOD_GET));
	struct oscore_ctx_ref old = result.origin.response_ctx;
	zassert_ok(oscore_ctx_set_peer_eui64(ctx, other));
	stale_response(&old);
	zassert_ok(oscore_ctx_set_peer_eui64(ctx, iid));
	stale_response(&old);
}

ZTEST(endpoint_binding, test_recycled_wrong_peer_cannot_supply_origin_evidence)
{
	provision(iid);
	struct oscore_ctx *slot = ctx;
	oscore_ctx_free(ctx);
	ctx = NULL;
	uint8_t other[8] = {7};
	/* Valid RFC ciphertext and keys in exactly the recycled slot, but B's
	 * binding must never be authenticated as the requested origin A. */
	provision(other);
	zassert_equal(ctx, slot);
	for (int legacy = 0; legacy < 2; legacy++) {
		zassert_equal(authorize(legacy, COAP_METHOD_GET), COAP_RESPONSE_CODE_UNAUTHORIZED);
		no_evidence();
	}
}

ZTEST(endpoint_binding, test_zz_generation_exhaustion_is_irreversible)
{
	provision(iid);
	zassert_ok(authorize(false, COAP_METHOD_GET));
	struct oscore_ctx_ref old = result.origin.response_ctx;
	uint8_t other[8] = {7};
	oscore_test_exhaust_generations();
	zassert_equal(oscore_ctx_set_peer_eui64(ctx, other), OSCORE_ERR_CONTEXT_STALE);
	oscore_ctx_free(ctx);
	ctx = NULL;
	zassert_ok(oscore_init());
	zassert_equal(oscore_ctx_create_with_eui64(secret, salt, sizeof(salt),
		(uint8_t[]){1}, 1, NULL, 0, iid, &ctx), OSCORE_ERR_CONTEXT_STALE);
	zassert_is_null(ctx);
	zassert_equal(oscore_ctx_create_with_id_context(secret, salt, sizeof(salt),
		(uint8_t[]){1}, 1, NULL, 0, (uint8_t[]){2}, 1, &ctx), OSCORE_ERR_CONTEXT_STALE);
	zassert_is_null(ctx);
	stale_response(&old);
}
