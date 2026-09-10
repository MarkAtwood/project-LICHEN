/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: The contributors to the LICHEN project
 *
 * bead project-LICHEN-worker6-dsrv: handler-level authorization gate for
 * PUT /config in the standalone CoAP server (coap_server.c).
 *
 * History: config_put() called coap_oscore_authorize_mutating() and used
 * its payload without ever checking is_protected or a local-admin fallback.
 * Whenever the helper's plaintext contract regresses (it has shifted under
 * merges before), an unauthenticated plaintext PUT commits. The handler
 * must hold its own gate: OSCORE-protected OR local-admin, else 4.01.
 *
 * Strategy: mock the OSCORE helper via --wrap so its "regressed" state
 * (return 0, is_protected=false, publish raw payload — exactly what the
 * jy0a review observed) can be driven deterministically, and assert the
 * handler gate refuses non-admin callers anyway. Responses are captured at
 * coap_resource_send (--wrap; lichen_coap_respond is called from inside
 * its own TU so it cannot be wrapped); the remaining OSCORE entry points
 * are plain mocks because coap_oscore.c is not linked.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/ztest.h>

#include <lichen/coap_server.h>
#include <lichen/coap_keys.h>
#include <lichen/coap_oscore.h>
#include <lichen/oscore.h>
#include <lichen/gateway/tunnel_auth.h>
#include <lichen/sos_origin.h>
#include <lichen/sos_alert.h>
#include <lichen/sos_ratelimit.h>

/* Resource under test (COAP_RESOURCE_DEFINE in coap_server.c). */
extern struct coap_resource lichen_server_config;
extern struct coap_resource lichen_sos;

/* ------------------------------------------------------------------ */
/* Captured responses                                                  */
/* ------------------------------------------------------------------ */

static struct {
	unsigned int calls;
	uint8_t code;
} plain_response;

static struct {
	unsigned int calls;
	uint8_t code;
} protected_response;

/* lichen_coap_respond() (real, in coap_server.c) builds the response
 * packet and hands it to coap_resource_send(); capturing at that boundary
 * asserts on the code that would actually go on the wire. */
int __wrap_coap_resource_send(
	const struct coap_resource *resource, const struct coap_packet *packet,
	const struct sockaddr *addr, socklen_t addr_len,
	const struct coap_transmission_parameters *params)
{
	ARG_UNUSED(resource);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	ARG_UNUSED(params);

	plain_response.calls++;
	plain_response.code = coap_header_get_code(packet);
	return 0;
}

int coap_oscore_send_protected(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len,
			       struct oscore_ctx *ctx,
			       const uint8_t *piv, size_t piv_len, uint8_t code)
{
	ARG_UNUSED(resource);
	ARG_UNUSED(request);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	ARG_UNUSED(ctx);
	ARG_UNUSED(piv);
	ARG_UNUSED(piv_len);

	protected_response.calls++;
	protected_response.code = code;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Controllable local-admin verdict                                    */
/* ------------------------------------------------------------------ */

static bool mock_admin;
static const uint8_t expected_origin_ipv6[16] = {
	0x02, 0x00, 0x30, 0xad, 0x22, 0x1f, 0x03, 0x32,
	0x2a, 0xdb, 0x90, 0x1f, 0x8b, 0x73, 0x16, 0x88,
};
static unsigned int sos_verify_calls;
static bool sos_verify_address_ok;

int lichen_identity_ygg_addr_from_ed25519(const uint8_t *pubkey,
					  uint8_t ygg_addr[16])
{
	ARG_UNUSED(pubkey);
	memcpy(ygg_addr, expected_origin_ipv6, sizeof(expected_origin_ipv6));
	return 0;
}

bool lichen_coap_is_local_admin(const struct sockaddr *addr, socklen_t addr_len)
{
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	return mock_admin;
}

/* ------------------------------------------------------------------ */
/* --wrap of the OSCORE authorization helper                          */
/*                                                                     */
/* AUTH_MODE_REGRESSED: the state the jy0a review observed — success  */
/* with is_protected=false and the raw payload published, regardless  */
/* of the caller's identity.                                          */
/* AUTH_MODE_CONTRACT: the documented contract — plaintext from a     */
/* non-admin peer is rejected with 4.01 by the helper itself.         */
/* ------------------------------------------------------------------ */

#define AUTH_MODE_REGRESSED 0
#define AUTH_MODE_CONTRACT 1

static int authorize_mode;

int __wrap_coap_oscore_authorize_mutating(struct coap_resource *resource,
					  struct coap_packet *request,
					  struct sockaddr *addr, socklen_t addr_len,
					  uint8_t expected_method,
					  uint8_t *plain_buf, size_t plain_buf_len,
					  const uint8_t **payload_out,
					  uint16_t *payload_len_out,
					  struct oscore_ctx **ctx_out,
					  uint8_t *piv_out, size_t *piv_len_out,
					  bool *is_protected)
{
	ARG_UNUSED(resource);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	ARG_UNUSED(expected_method);
	ARG_UNUSED(plain_buf);
	ARG_UNUSED(plain_buf_len);
	ARG_UNUSED(piv_out);

	*ctx_out = NULL;
	*piv_len_out = 0U;
	*is_protected = false;

	if (authorize_mode == AUTH_MODE_CONTRACT && !mock_admin) {
		*payload_out = NULL;
		*payload_len_out = 0U;
		return COAP_RESPONSE_CODE_UNAUTHORIZED;
	}

	*payload_out = coap_packet_get_payload(request, payload_len_out);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Stubs for symbols coap_server.c references from unlinked modules   */
/* ------------------------------------------------------------------ */

size_t lichen_key_store_list(struct lichen_key_entry *entries,
			     size_t max_entries)
{
	ARG_UNUSED(entries);
	ARG_UNUSED(max_entries);
	return 0U;
}

uint8_t lichen_tunnel_auth_coap_code(uint16_t coap_code)
{
	ARG_UNUSED(coap_code);
	return 0U;
}

/* Stubs for the sos_post handler's dependencies (link-layer SOS module is
 * not linked; sos_post is not under test). */
int sos_origin_signature_parse(struct sos_origin_signature *out,
			       const uint8_t *data, size_t len)
{
	memset(out, 0, sizeof(*out));
	ARG_UNUSED(data);
	ARG_UNUSED(len);
	return 0;
}

bool sos_origin_verify(const uint8_t *pubkey,
		       const uint8_t *origin_ipv6,
		       const uint8_t *payload_cbor,
		       size_t payload_len,
		       const struct sos_origin_signature *sig)
{
	ARG_UNUSED(pubkey);
	ARG_UNUSED(payload_cbor);
	ARG_UNUSED(payload_len);
	ARG_UNUSED(sig);
	sos_verify_calls++;
	sos_verify_address_ok = memcmp(origin_ipv6, expected_origin_ipv6,
					 sizeof(expected_origin_ipv6)) == 0;
	return sos_verify_address_ok;
}

int sos_alert_from_cbor(const uint8_t *buf, size_t buf_len,
			struct sos_alert *alert)
{
	ARG_UNUSED(buf);
	ARG_UNUSED(buf_len);
	memset(alert, 0, sizeof(*alert));
	memcpy(alert->node, "0011223344556677", 17);
	return 0;
}

void sos_ratelimit_config_init(struct sos_ratelimit_config *config)
{
	ARG_UNUSED(config);
}

enum sos_ratelimit_result sos_ratelimit_check(
	const struct sos_ratelimit_state *state,
	int64_t now_ms,
	const struct sos_ratelimit_config *config,
	uint32_t *remaining_ms)
{
	ARG_UNUSED(state);
	ARG_UNUSED(now_ms);
	ARG_UNUSED(config);
	ARG_UNUSED(remaining_ms);
	return SOS_RATELIMIT_ALLOWED;
}

void sos_ratelimit_record(struct sos_ratelimit_state *state, int64_t now_ms)
{
	ARG_UNUSED(state);
	ARG_UNUSED(now_ms);
}

/* ------------------------------------------------------------------ */
/* Test fixture                                                        */
/* ------------------------------------------------------------------ */

static unsigned int config_put_calls;
static uint8_t last_payload[64];
static size_t last_payload_len;

static int test_config_put(const uint8_t *payload, size_t payload_len)
{
	config_put_calls++;
	if (payload_len <= sizeof(last_payload)) {
		memcpy(last_payload, payload, payload_len);
		last_payload_len = payload_len;
	}
	return 0;
}

static const struct lichen_coap_server_handlers test_handlers = {
	.config_put = test_config_put,
};

static const uint8_t put_body[] = {0xa1, 0x01, 0x02}; /* opaque CBOR-ish */

static void init_put(struct coap_packet *request, uint8_t *buf,
		     size_t buf_size)
{
	zassert_ok(coap_packet_init(request, buf, (uint16_t)buf_size,
				    COAP_VERSION_1, COAP_TYPE_CON, 0U, NULL,
				    COAP_METHOD_PUT, 0x1234U));
	zassert_ok(coap_packet_append_payload_marker(request));
	zassert_ok(coap_packet_append_payload(request, put_body,
					      (uint16_t)sizeof(put_body)));
	/* Handlers receive parsed datagrams, whose max_len is the received
	 * length; coap_packet_init keeps the output buffer capacity. */
	request->max_len = request->offset;
}

static void init_sos(struct coap_packet *request, uint8_t *buf,
			     size_t buf_size)
{
	static const uint8_t sos_body[56] = { 0xa0 };

	zassert_ok(coap_packet_init(request, buf, (uint16_t)buf_size,
				    COAP_VERSION_1, COAP_TYPE_CON, 0U, NULL,
				    COAP_METHOD_POST, 0x4321U));
	zassert_ok(coap_packet_append_payload_marker(request));
	zassert_ok(coap_packet_append_payload(request, sos_body,
					      sizeof(sos_body)));
	request->max_len = request->offset;
}

static void init_global_addr(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_port = htons(5683U);
	/* 2001:db8::1 — documentation range, never local-admin */
	addr->sin6_addr.s6_addr[0] = 0x20U;
	addr->sin6_addr.s6_addr[1] = 0x01U;
	addr->sin6_addr.s6_addr[2] = 0x0dU;
	addr->sin6_addr.s6_addr[3] = 0xb8U;
	addr->sin6_addr.s6_addr[15] = 0x01U;
}

static int call_config_put(struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	return lichen_server_config.put(&lichen_server_config, request,
					addr, addr_len);
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);

	memset(&plain_response, 0, sizeof(plain_response));
	memset(&protected_response, 0, sizeof(protected_response));
	config_put_calls = 0U;
	last_payload_len = 0U;
	sos_verify_calls = 0U;
	sos_verify_address_ok = false;
	mock_admin = false;
	authorize_mode = AUTH_MODE_REGRESSED;
	/* Registers test_handlers in s_handlers. The service start inside
	 * init is irrelevant here: handlers are invoked directly, never
	 * through a socket; a repeated start returns -EALREADY. */
	(void)lichen_coap_server_init(&test_handlers);
}

ZTEST_SUITE(coap_config_put_auth, NULL, NULL, before, NULL, NULL);

ZTEST(coap_config_put_auth, test_sos_uses_upstream_addr_for_key)
{
	struct coap_packet request;
	struct sockaddr_in6 addr;
	uint8_t request_buf[96];

	init_sos(&request, request_buf, sizeof(request_buf));
	init_global_addr(&addr);
	(void)lichen_sos.post(&lichen_sos, &request, (struct sockaddr *)&addr,
				      sizeof(addr));

	zassert_equal(sos_verify_calls, 1U);
	zassert_true(sos_verify_address_ok,
			    "SOS origin verification must use AddrForKey(pubkey)");
}

/*
 * Core regression test for bead dsrv: even with the OSCORE helper in the
 * regressed state the jy0a review observed (success + is_protected=false +
 * raw payload for ANY caller), the handler's own gate must refuse a
 * non-admin peer with 4.01 and never commit the config write.
 *
 * This test FAILS on the pre-fix coap_server.c (no gate: the callback
 * fires and a 2.04 CHANGED response is sent).
 */
ZTEST(coap_config_put_auth,
      test_regressed_helper_plaintext_non_admin_rejected)
{
	struct coap_packet request;
	struct sockaddr_in6 addr;
	uint8_t request_buf[64];
	int ret;

	init_put(&request, request_buf, sizeof(request_buf));
	init_global_addr(&addr);
	mock_admin = false;

	ret = call_config_put(&request, (struct sockaddr *)&addr, sizeof(addr));

	zassert_ok(ret);
	zassert_equal(plain_response.calls, 1U,
		      "rejection must go through lichen_coap_respond");
	zassert_equal(plain_response.code, COAP_RESPONSE_CODE_UNAUTHORIZED,
		      "non-admin plaintext PUT must get 4.01, got 0x%02x",
		      plain_response.code);
	zassert_equal(config_put_calls, 0U,
		      "config write must never commit for non-admin plaintext");
	zassert_equal(protected_response.calls, 0U);
}

/* The same gate must not over-block: a local-admin plaintext PUT (the LCI
 * use case) still reaches the callback and gets 2.04 CHANGED. */
ZTEST(coap_config_put_auth,
      test_regressed_helper_plaintext_local_admin_allowed)
{
	struct coap_packet request;
	struct sockaddr_in6 addr;
	uint8_t request_buf[64];
	int ret;

	init_put(&request, request_buf, sizeof(request_buf));
	init_global_addr(&addr);
	mock_admin = true;

	ret = call_config_put(&request, (struct sockaddr *)&addr, sizeof(addr));

	zassert_ok(ret);
	zassert_equal(config_put_calls, 1U,
		      "local-admin plaintext PUT must reach the callback");
	zassert_equal(last_payload_len, sizeof(put_body));
	zassert_mem_equal(last_payload, put_body, sizeof(put_body));
	zassert_equal(protected_response.calls, 1U);
	zassert_equal(protected_response.code, COAP_RESPONSE_CODE_CHANGED);
	zassert_equal(plain_response.calls, 0U,
		      "admin path must not take the rejection branch");
}

/* With the helper honoring its documented contract (plaintext from a
 * non-admin peer is rejected by the helper itself), the handler must
 * propagate the 4.01 return value and never respond twice. */
ZTEST(coap_config_put_auth,
      test_contract_helper_non_admin_rejection_propagated)
{
	struct coap_packet request;
	struct sockaddr_in6 addr;
	uint8_t request_buf[64];
	int ret;

	init_put(&request, request_buf, sizeof(request_buf));
	init_global_addr(&addr);
	mock_admin = false;
	authorize_mode = AUTH_MODE_CONTRACT;

	ret = call_config_put(&request, (struct sockaddr *)&addr, sizeof(addr));

	zassert_equal(ret, COAP_RESPONSE_CODE_UNAUTHORIZED,
		      "helper rejection must propagate, got %d", ret);
	zassert_equal(config_put_calls, 0U);
	zassert_equal(plain_response.calls, 0U);
	zassert_equal(protected_response.calls, 0U);
}

/* The pre-existing NOT_FOUND behavior (no callback registered) must be
 * unaffected by the new gate: the NULL check runs before it. */
ZTEST(coap_config_put_auth, test_no_callback_registered_is_not_found)
{
	struct coap_packet request;
	struct sockaddr_in6 addr;
	uint8_t request_buf[64];
	int ret;

	(void)lichen_coap_server_init(NULL);
	init_put(&request, request_buf, sizeof(request_buf));
	init_global_addr(&addr);
	mock_admin = true;

	ret = call_config_put(&request, (struct sockaddr *)&addr, sizeof(addr));

	zassert_equal(ret, COAP_RESPONSE_CODE_NOT_FOUND,
		      "missing callback must stay 4.04, got %d", ret);
	zassert_equal(plain_response.calls, 0U);
	zassert_equal(protected_response.calls, 0U);
}
