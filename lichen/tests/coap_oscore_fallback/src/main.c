/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Failure semantics of coap_oscore_respond_resource().
 *
 * Regression coverage for the cleartext-downgrade fix: when
 * coap_oscore_protect_response() fails for an OSCORE-protected request, the
 * helper must never send a cleartext reply. It must retry once with a
 * protected empty 5.00 through the same context and correlation, and drop
 * the response silently if that retry also fails. The plain (unprotected)
 * request path must keep its cleartext behavior.
 *
 * The test drives the real helper and captures what it sends through the
 * real Zephyr CoAP service socket: a UDP client socket bound to the IPv6
 * loopback receives exactly what coap_resource_send() emits.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/posix/fcntl.h>

#include <lichen/coap_oscore.h>
#include <lichen/oscore.h>

#define CAPTURE_BUF_LEN 256
#define CAPTURE_TIMEOUT_MS 1000
#define DROP_TIMEOUT_MS 200

/* Guaranteed to exceed the protect plaintext budget, so the first
 * protect_response attempt fails with OSCORE_ERR_BUFFER_TOO_SMALL. */
#define OVERSIZE_EXTRA 64

static const uint8_t master_secret[16] = {
	0x4e, 0x0f, 0x28, 0x1b, 0xc5, 0x77, 0x93, 0x62,
	0xa1, 0x38, 0xd4, 0x50, 0x6b, 0x7c, 0x19, 0xef,
};
static const uint8_t master_salt[8] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
};

static struct oscore_ctx *server_ctx;
static struct oscore_ctx *client_ctx;

static int client_fd = -1;
static struct sockaddr_in6 client_addr;

static uint8_t oversize_payload[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX + OVERSIZE_EXTRA];

static const uint16_t fb_svc_port = 56831;
COAP_SERVICE_DEFINE(fb_svc, NULL, &fb_svc_port, 0);

static const char * const fb_path[] = { "fb", NULL };

/*
 * Test-local replacement for lichen_coap_server.c's lichen_coap_respond()
 * (house pattern from tests/coap_config): mirrors the real implementation's
 * observable behavior — packet init, content-format option, payload — and
 * sends through the real coap_resource_send() capture path.
 */
int lichen_coap_respond(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len,
			uint8_t resp_code, uint16_t content_format,
			const uint8_t *payload, size_t payload_len)
{
	static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet response;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint16_t id;
	uint8_t tkl;
	int ret;

	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;

	ret = coap_packet_init(&response, buf, sizeof(buf), COAP_VERSION_1,
			       type, tkl, token, resp_code, id);
	if (ret < 0) {
		return ret;
	}

	if (payload != NULL && payload_len > 0) {
		ret = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT,
					     content_format);
		if (ret < 0) {
			return ret;
		}

		ret = coap_packet_append_payload_marker(&response);
		if (ret < 0) {
			return ret;
		}

		ret = coap_packet_append_payload(&response, payload,
						 (uint16_t)payload_len);
		if (ret < 0) {
			return ret;
		}
	}

	return coap_resource_send(resource, &response, addr, addr_len, NULL);
}

static int fb_handler(struct coap_resource *resource, struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	ARG_UNUSED(resource);
	ARG_UNUSED(request);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);

	return 0;
}

COAP_RESOURCE_DEFINE(fb_res, fb_svc, {
	.path = fb_path,
	.get = fb_handler,
	.post = fb_handler,
});

static void *suite_setup(void)
{
	int ret;

	oscore_init();
	oscore_nvm_register_callbacks(NULL, NULL);

	/* Server context: sender_id = {0x01}, recipient_id = "" */
	ret = oscore_ctx_create(master_secret, master_salt, sizeof(master_salt),
				(uint8_t[]){0x01}, 1, NULL, 0, &server_ctx);
	zassert_equal(ret, OSCORE_OK, "server ctx create failed: %d", ret);
	zassert_not_null(server_ctx);
	/* Client context: sender_id = "", recipient_id = {0x01} */
	ret = oscore_ctx_create(master_secret, master_salt, sizeof(master_salt),
				NULL, 0, (uint8_t[]){0x01}, 1, &client_ctx);
	zassert_equal(ret, OSCORE_OK, "client ctx create failed: %d", ret);
	zassert_not_null(client_ctx);

	client_fd = zsock_socket(AF_INET6, SOCK_DGRAM, 0);
	zassert_true(client_fd >= 0, "client socket failed: %d", -errno);

	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin6_family = AF_INET6;
	client_addr.sin6_addr = in6addr_loopback;
	client_addr.sin6_port = 0;

	ret = zsock_bind(client_fd, (struct sockaddr *)&client_addr,
			 sizeof(client_addr));
	zassert_equal(ret, 0, "client bind failed: %d", -errno);

	socklen_t alen = sizeof(client_addr);
	ret = zsock_getsockname(client_fd, (struct sockaddr *)&client_addr, &alen);
	zassert_equal(ret, 0, "getsockname failed: %d", -errno);

	/*
	 * Attach the service socket by hand instead of coap_service_start():
	 * the observable contract the helper relies on is that
	 * coap_resource_send() finds fb_svc in the service section and
	 * sendto()s through data->sock_fd. (coap_service_start() deadlocks
	 * under this test's threading on qemu_x86; the manual wiring keeps
	 * everything the helper touches real.)
	 */
	int svc_fd = zsock_socket(AF_INET6, SOCK_DGRAM, 0);

	zassert_true(svc_fd >= 0, "service socket failed: %d", -errno);

	struct sockaddr_in6 svc_addr;

	memset(&svc_addr, 0, sizeof(svc_addr));
	svc_addr.sin6_family = AF_INET6;
	svc_addr.sin6_addr = in6addr_any;
	svc_addr.sin6_port = htons(fb_svc_port);

	ret = zsock_bind(svc_fd, (struct sockaddr *)&svc_addr, sizeof(svc_addr));
	zassert_equal(ret, 0, "service bind failed: %d", -errno);

	ret = zsock_fcntl(svc_fd, F_SETFL, O_NONBLOCK);
	zassert_equal(ret, 0, "service fcntl failed: %d", -errno);

	fb_svc.data->sock_fd = svc_fd;

	return NULL;
}

static int build_request(struct coap_packet *req, uint8_t *buf, size_t buflen,
			 uint16_t mid, const uint8_t *token, uint8_t tkl)
{
	return coap_packet_init(req, buf, (uint16_t)buflen, COAP_VERSION_1,
				COAP_TYPE_CON, tkl, token, COAP_METHOD_POST, mid);
}

/* Receive and parse one response on the client socket; false on timeout. */
static bool capture_response(struct coap_packet *resp, uint8_t *buf,
			     size_t buflen, size_t *recv_len, int timeout_ms)
{
	struct zsock_pollfd pfd = {
		.fd = client_fd,
		.events = ZSOCK_POLLIN,
		.revents = 0,
	};
	static struct coap_option opts[8];

	int ret = zsock_poll(&pfd, 1, timeout_ms);
	if (ret < 1) {
		return false;
	}

	ssize_t n = zsock_recv(client_fd, buf, buflen, ZSOCK_MSG_DONTWAIT);
	if (n <= 0) {
		return false;
	}
	*recv_len = (size_t)n;

	return coap_packet_parse(resp, buf, *recv_len, opts, 8) == 0;
}

static bool has_oscore_option(const struct coap_packet *resp)
{
	struct coap_option opt;

	return coap_find_options(resp, COAP_OPTION_OSCORE, &opt, 1) > 0;
}

ZTEST_SUITE(coap_oscore_fallback, NULL, suite_setup, NULL, NULL, NULL);

/*
 * A protected request with a normal payload round-trips: the response
 * arrives OSCORE-protected and decrypts to the requested code and payload.
 */
ZTEST(coap_oscore_fallback, test_protected_response_roundtrip)
{
	static const uint8_t token[] = {0xA1, 0xA2, 0xA3, 0xA4};
	static const uint8_t piv[] = {0x11};
	static const uint8_t payload[] = "lich-en";

	uint8_t req_buf[64];
	uint8_t cap_buf[CAPTURE_BUF_LEN];
	struct coap_packet req;
	struct coap_packet resp;
	struct coap_oscore_unprotect_result result;
	size_t recv_len = 0;
	int ret;

	ret = build_request(&req, req_buf, sizeof(req_buf), 1001,
			    token, sizeof(token));
	zassert_equal(ret, 0, "request build failed: %d", ret);

	memset(&result, 0, sizeof(result));
	result.is_protected = true;
	result.ctx = server_ctx;
	memcpy(result.piv, piv, sizeof(piv));
	result.piv_len = sizeof(piv);

	ret = coap_oscore_respond_resource(&fb_res, &req,
					   (struct sockaddr *)&client_addr,
					   sizeof(client_addr), &result,
					   COAP_RESPONSE_CODE_CHANGED, 0,
					   payload, sizeof(payload) - 1);
	zassert_equal(ret, 0, "respond failed: %d", ret);

	ret = capture_response(&resp, cap_buf, sizeof(cap_buf), &recv_len,
			       CAPTURE_TIMEOUT_MS);
	zassert_true(ret, "no response captured");
	zassert_true(has_oscore_option(&resp), "response must carry OSCORE option");

	uint16_t ct_len16 = 0;
	size_t ct_len;
	const uint8_t *ct = coap_packet_get_payload(&resp, &ct_len16);

	ct_len = ct_len16;
	zassert_not_null(ct, "no ciphertext in response");

	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	zassert_equal(coap_oscore_get_option(&resp, oscore_opt, &opt_len),
		      OSCORE_OK, "missing OSCORE option");

	uint8_t code = 0;
	uint8_t dopts[32];
	size_t dopts_len = sizeof(dopts);
	uint8_t dpl[64];
	size_t dpl_len = sizeof(dpl);
	ret = oscore_unprotect_response(client_ctx, piv, sizeof(piv),
					oscore_opt, opt_len, ct, ct_len,
					&code, dopts, &dopts_len, dpl, &dpl_len);
	zassert_equal(ret, OSCORE_OK, "client unprotect failed: %d", ret);
	zassert_equal(code, COAP_RESPONSE_CODE_CHANGED, "inner code mismatch");
	zassert_equal(dpl_len, sizeof(payload) - 1U, "inner payload length mismatch");
	zassert_mem_equal(dpl, payload, sizeof(payload) - 1U, "inner payload mismatch");
}

/*
 * The bead's fix: protect failure for a protected request (payload beyond
 * the plaintext budget) must produce a PROTECTED empty 5.00, never a
 * cleartext reply.
 */
ZTEST(coap_oscore_fallback, test_protect_failure_sends_protected_empty_500)
{
	static const uint8_t token[] = {0xB1, 0xB2, 0xB3, 0xB4};
	static const uint8_t piv[] = {0x12};

	uint8_t req_buf[64];
	uint8_t cap_buf[CAPTURE_BUF_LEN];
	struct coap_packet req;
	struct coap_packet resp;
	struct coap_oscore_unprotect_result result;
	size_t recv_len = 0;
	int ret;

	ret = build_request(&req, req_buf, sizeof(req_buf), 1002,
			    token, sizeof(token));
	zassert_equal(ret, 0, "request build failed: %d", ret);

	memset(&result, 0, sizeof(result));
	result.is_protected = true;
	result.ctx = server_ctx;
	memcpy(result.piv, piv, sizeof(piv));
	result.piv_len = sizeof(piv);

	ret = coap_oscore_respond_resource(&fb_res, &req,
					   (struct sockaddr *)&client_addr,
					   sizeof(client_addr), &result,
					   COAP_RESPONSE_CODE_CHANGED, 0,
					   oversize_payload, sizeof(oversize_payload));
	zassert_equal(ret, 0, "respond with fallback failed: %d", ret);

	ret = capture_response(&resp, cap_buf, sizeof(cap_buf), &recv_len,
			       CAPTURE_TIMEOUT_MS);
	zassert_true(ret, "no fallback response captured");
	zassert_true(has_oscore_option(&resp),
		     "fallback response must be OSCORE-protected, not cleartext");

	uint16_t ct_len16 = 0;
	size_t ct_len;
	const uint8_t *ct = coap_packet_get_payload(&resp, &ct_len16);

	ct_len = ct_len16;
	zassert_not_null(ct, "no ciphertext in fallback response");

	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	zassert_equal(coap_oscore_get_option(&resp, oscore_opt, &opt_len),
		      OSCORE_OK, "missing OSCORE option");

	uint8_t code = 0;
	uint8_t dopts[32];
	size_t dopts_len = sizeof(dopts);
	uint8_t dpl[64];
	size_t dpl_len = sizeof(dpl);
	ret = oscore_unprotect_response(client_ctx, piv, sizeof(piv),
					oscore_opt, opt_len, ct, ct_len,
					&code, dopts, &dopts_len, dpl, &dpl_len);
	zassert_equal(ret, OSCORE_OK, "client unprotect of fallback failed: %d", ret);
	zassert_equal(code, COAP_RESPONSE_CODE_INTERNAL_ERROR,
		      "fallback inner code must be 5.00");
	zassert_equal(dpl_len, 0U, "fallback payload must be empty");
}

/*
 * If even the protected empty 5.00 cannot be built (here: the request
 * correlation was already consumed, so the retry hits OSCORE_ERR_REPLAY),
 * the response is dropped silently: negative return, nothing sent.
 */
ZTEST(coap_oscore_fallback, test_protect_failure_twice_drops_silently)
{
	static const uint8_t token[] = {0xC1, 0xC2, 0xC3, 0xC4};
	static const uint8_t piv[] = {0x13};

	uint8_t req_buf[64];
	uint8_t cap_buf[CAPTURE_BUF_LEN];
	static uint8_t consume_buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet req;
	struct coap_packet resp;
	struct coap_oscore_unprotect_result result;
	size_t recv_len = 0;
	int ret;

	ret = build_request(&req, req_buf, sizeof(req_buf), 1003,
			    token, sizeof(token));
	zassert_equal(ret, 0, "request build failed: %d", ret);

	/* Consume the request correlation with a successful protect. */
	struct coap_packet consume_resp;

	ret = coap_oscore_protect_response(server_ctx, piv, sizeof(piv), &req,
					   COAP_RESPONSE_CODE_CHANGED,
					   NULL, 0, &consume_resp, consume_buf,
					   sizeof(consume_buf));
	zassert_equal(ret, 0, "correlation consume failed: %d", ret);

	memset(&result, 0, sizeof(result));
	result.is_protected = true;
	result.ctx = server_ctx;
	memcpy(result.piv, piv, sizeof(piv));
	result.piv_len = sizeof(piv);

	/* First protect fails (oversized), retry hits the consumed
	 * correlation: the helper must drop the response silently. */
	ret = coap_oscore_respond_resource(&fb_res, &req,
					   (struct sockaddr *)&client_addr,
					   sizeof(client_addr), &result,
					   COAP_RESPONSE_CODE_CHANGED, 0,
					   oversize_payload, sizeof(oversize_payload));
	zassert_true(ret < 0, "double protect failure must return a negative error");
	zassert_false(capture_response(&resp, cap_buf, sizeof(cap_buf), &recv_len,
				       DROP_TIMEOUT_MS),
		      "nothing may be sent to the peer on silent drop");
}

/* A protected request with no context is dropped, never answered in cleartext. */
ZTEST(coap_oscore_fallback, test_protected_no_context_drops)
{
	static const uint8_t token[] = {0xD1, 0xD2, 0xD3, 0xD4};
	static const uint8_t piv[] = {0x14};

	uint8_t req_buf[64];
	uint8_t cap_buf[CAPTURE_BUF_LEN];
	struct coap_packet req;
	struct coap_packet resp;
	struct coap_oscore_unprotect_result result;
	size_t recv_len = 0;
	int ret;

	ret = build_request(&req, req_buf, sizeof(req_buf), 1004,
			    token, sizeof(token));
	zassert_equal(ret, 0, "request build failed: %d", ret);

	memset(&result, 0, sizeof(result));
	result.is_protected = true;
	result.ctx = NULL;
	memcpy(result.piv, piv, sizeof(piv));
	result.piv_len = sizeof(piv);

	ret = coap_oscore_respond_resource(&fb_res, &req,
					   (struct sockaddr *)&client_addr,
					   sizeof(client_addr), &result,
					   COAP_RESPONSE_CODE_CHANGED, 0,
					   NULL, 0);
	zassert_equal(ret, OSCORE_ERR_CONTEXT_STALE,
		      "no-context drop must return CONTEXT_STALE: %d", ret);

	zassert_false(capture_response(&resp, cap_buf, sizeof(cap_buf), &recv_len,
				       DROP_TIMEOUT_MS),
		      "nothing may be sent to the peer on silent drop");
}

/* A protected request with an empty correlation is dropped, never in cleartext. */
ZTEST(coap_oscore_fallback, test_protected_no_piv_drops)
{
	static const uint8_t token[] = {0xE1, 0xE2, 0xE3, 0xE4};

	uint8_t req_buf[64];
	uint8_t cap_buf[CAPTURE_BUF_LEN];
	struct coap_packet req;
	struct coap_packet resp;
	struct coap_oscore_unprotect_result result;
	size_t recv_len = 0;
	int ret;

	ret = build_request(&req, req_buf, sizeof(req_buf), 1005,
			    token, sizeof(token));
	zassert_equal(ret, 0, "request build failed: %d", ret);

	memset(&result, 0, sizeof(result));
	result.is_protected = true;
	result.ctx = server_ctx;
	result.piv_len = 0;

	ret = coap_oscore_respond_resource(&fb_res, &req,
					   (struct sockaddr *)&client_addr,
					   sizeof(client_addr), &result,
					   COAP_RESPONSE_CODE_CHANGED, 0,
					   NULL, 0);
	zassert_equal(ret, OSCORE_ERR_CONTEXT_STALE,
		      "no-piv drop must return CONTEXT_STALE: %d", ret);

	zassert_false(capture_response(&resp, cap_buf, sizeof(cap_buf), &recv_len,
				       DROP_TIMEOUT_MS),
		      "nothing may be sent to the peer on silent drop");
}

/*
 * The plain (unprotected) request path is unchanged: cleartext response,
 * code, token, and payload delivered as requested.
 */
ZTEST(coap_oscore_fallback, test_plain_request_keeps_cleartext)
{
	static const uint8_t token[] = {0xF1, 0xF2, 0xF3, 0xF4};
	static const uint8_t payload[] = "plain";

	uint8_t req_buf[64];
	uint8_t cap_buf[CAPTURE_BUF_LEN];
	struct coap_packet req;
	struct coap_packet resp;
	struct coap_oscore_unprotect_result result;
	size_t recv_len = 0;
	int ret;

	ret = build_request(&req, req_buf, sizeof(req_buf), 1006,
			    token, sizeof(token));
	zassert_equal(ret, 0, "request build failed: %d", ret);

	memset(&result, 0, sizeof(result));
	result.is_protected = false;

	ret = coap_oscore_respond_resource(&fb_res, &req,
					   (struct sockaddr *)&client_addr,
					   sizeof(client_addr), &result,
					   COAP_RESPONSE_CODE_NOT_FOUND, 0,
					   payload, sizeof(payload) - 1);
	zassert_equal(ret, 0, "plain respond failed: %d", ret);

	ret = capture_response(&resp, cap_buf, sizeof(cap_buf), &recv_len,
			       CAPTURE_TIMEOUT_MS);
	zassert_true(ret, "no plain response captured");
	zassert_false(has_oscore_option(&resp),
		      "plain request must not receive an OSCORE-protected response");
	zassert_equal(coap_header_get_code(&resp), COAP_RESPONSE_CODE_NOT_FOUND,
		      "plain code mismatch");

	uint8_t echo_token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(&resp, echo_token);

	zassert_equal(tkl, sizeof(token), "token length mismatch");
	zassert_mem_equal(echo_token, token, sizeof(token), "token mismatch");

	uint16_t plen = 0;
	const uint8_t *pl = coap_packet_get_payload(&resp, &plen);

	zassert_not_null(pl, "plain payload missing");
	zassert_equal(plen, sizeof(payload) - 1U, "plain payload length mismatch");
	zassert_mem_equal(pl, payload, sizeof(payload) - 1U, "plain payload mismatch");
}
