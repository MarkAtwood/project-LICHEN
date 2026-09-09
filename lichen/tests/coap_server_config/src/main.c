/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief /config PUT authorization gate regression tests (dsrv).
 *
 * coap_server.c config_put commits configuration via s_handlers.config_put.
 * The security contract: an unprotected (plaintext) PUT from a source that
 * is not a local admin (loopback or the SLIP LCI interface) must never
 * reach that commit; only local admin plaintext or a verified
 * OSCORE-protected request may commit.
 *
 * The handlers are static, so the tests call the lichen_server_config
 * resource's .put entry point directly and observe the counting stub
 * handler: the commit is the security-relevant side effect. Response
 * packet capture is not needed for the contract — test_plain_non_admin
 * and test_oscore_unknown_peer assert the stub is never invoked.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>

#include <lichen/coap_server.h>
#include <lichen/oscore.h>

/* Section-placed by COAP_RESOURCE_DEFINE in coap_server.c. */
extern const struct coap_resource lichen_server_config;

static int config_put_calls;
static uint8_t last_payload[LICHEN_COAP_SERVER_MAX_PAYLOAD];
static size_t last_payload_len;

static int stub_config_put(const uint8_t *payload, size_t payload_len)
{
	config_put_calls++;
	last_payload_len = payload_len;
	if (payload_len > 0) {
		memcpy(last_payload, payload, payload_len);
	}
	return 0;
}

static int stub_config_get(uint8_t *buf, size_t buf_len)
{
	ARG_UNUSED(buf);
	ARG_UNUSED(buf_len);
	return 0;
}

static const struct lichen_coap_server_handlers test_handlers = {
	.config_get = stub_config_get,
	.config_put = stub_config_put,
};

static void *suite_setup(void)
{
	oscore_init();
	oscore_nvm_register_callbacks(NULL, NULL);

	int ret = lichen_coap_server_init(&test_handlers);

	zassert_equal(ret, 0, "server init failed: %d", ret);
	return NULL;
}

static void before_each(void *fixture)
{
	ARG_UNUSED(fixture);
	config_put_calls = 0;
	last_payload_len = 0;
}

static void addr_loopback(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr = in6addr_loopback;
	addr->sin6_port = htons(12345);
}

/* fe80::1 with scope 0: link-local but not from the SLIP LCI interface
 * (SLIP is not started in this fixture, so iface_get() is NULL and
 * is_local_admin rejects). */
static void addr_mesh_linklocal(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr[0] = 0xfe;
	addr->sin6_addr.s6_addr[1] = 0x80;
	addr->sin6_addr.s6_addr[15] = 0x01;
	addr->sin6_port = htons(12345);
	addr->sin6_scope_id = 0;
}

static int build_plain_put(struct coap_packet *req, uint8_t *buf, size_t buflen,
			   const uint8_t *payload, uint16_t payload_len)
{
	static const uint8_t token[] = { 0xaa };
	int ret;

	ret = coap_packet_init(req, buf, (uint16_t)buflen, COAP_VERSION_1,
			       COAP_TYPE_CON, sizeof(token), token,
			       COAP_METHOD_PUT, 0x1234);
	if (ret < 0) {
		return ret;
	}
	ret = coap_packet_append_payload_marker(req);
	if (ret < 0) {
		return ret;
	}
	return coap_packet_append_payload(req, payload, payload_len);
}

ZTEST_SUITE(coap_server_config, NULL, suite_setup, before_each, NULL, NULL);

/*
 * The dsrv hole: an unprotected PUT /config from a non-admin source must
 * not commit. Assert the counting stub is never invoked.
 */
ZTEST(coap_server_config, test_plain_non_admin_never_commits)
{
	static const uint8_t payload[] = { 0xa1, 0x01, 0x02 };
	uint8_t buf[128];
	struct coap_packet req;
	struct sockaddr_in6 src;
	int ret;

	addr_mesh_linklocal(&src);
	ret = build_plain_put(&req, buf, sizeof(buf), payload, sizeof(payload));
	zassert_equal(ret, 0, "request build failed: %d", ret);

	ret = lichen_server_config.put(&lichen_server_config, &req,
				       (struct sockaddr *)&src, sizeof(src));

	zassert_equal(config_put_calls, 0,
		      "non-admin plaintext PUT reached config commit (ret=%d)", ret);
}

/*
 * Positive control: local admin (loopback) plaintext PUT must pass the
 * gate and reach the commit with the payload intact.
 */
ZTEST(coap_server_config, test_plain_loopback_admin_commits)
{
	static const uint8_t payload[] = { 0xa1, 0x01, 0x02 };
	uint8_t buf[128];
	struct coap_packet req;
	struct sockaddr_in6 src;
	int ret;

	addr_loopback(&src);
	ret = build_plain_put(&req, buf, sizeof(buf), payload, sizeof(payload));
	zassert_equal(ret, 0, "request build failed: %d", ret);

	ret = lichen_server_config.put(&lichen_server_config, &req,
				       (struct sockaddr *)&src, sizeof(src));

	zassert_equal(config_put_calls, 1,
		      "loopback admin PUT did not reach config commit");
	zassert_equal(last_payload_len, sizeof(payload),
		      "payload length mismatch");
	zassert_mem_equal(last_payload, payload, sizeof(payload),
			  "payload content mismatch");
	zassert_equal(ret, 0, "2.04 Changed response send failed: %d", ret);
}

/*
 * A request carrying an OSCORE option from a peer with no established
 * context is rejected by the authorize helper before the commit.
 */
ZTEST(coap_server_config, test_oscore_unknown_peer_rejected)
{
	static const uint8_t payload[] = { 0xa1, 0x01, 0x02 };
	static const uint8_t oscore_val[] = { 0x01, 0x01 };
	uint8_t buf[128];
	struct coap_packet req;
	struct sockaddr_in6 src;
	static const uint8_t token[] = { 0xbb };
	int ret;

	addr_mesh_linklocal(&src);
	ret = coap_packet_init(&req, buf, sizeof(buf), COAP_VERSION_1,
			       COAP_TYPE_CON, sizeof(token), token,
			       COAP_METHOD_PUT, 0x1235);
	zassert_equal(ret, 0, "packet init failed: %d", ret);
	ret = coap_packet_append_option(&req, COAP_OPTION_OSCORE,
					oscore_val, sizeof(oscore_val));
	zassert_equal(ret, 0, "oscore option failed: %d", ret);
	ret = coap_packet_append_payload_marker(&req);
	zassert_equal(ret, 0, "payload marker failed: %d", ret);
	ret = coap_packet_append_payload(&req, payload, sizeof(payload));
	zassert_equal(ret, 0, "payload append failed: %d", ret);

	ret = lichen_server_config.put(&lichen_server_config, &req,
				       (struct sockaddr *)&src, sizeof(src));

	zassert_equal(ret, COAP_RESPONSE_CODE_UNAUTHORIZED,
		      "unknown OSCORE peer not rejected: %#x", ret);
	zassert_equal(config_put_calls, 0,
		      "unknown OSCORE peer reached config commit");
}
