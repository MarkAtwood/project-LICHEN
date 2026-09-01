/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_server.c
 * @brief CoAP server for LICHEN nodes
 *
 * Implements CoAP server using Zephyr's CoAP service APIs.
 *
 * Resources exposed:
 * - /.well-known/core - Resource discovery (RFC 6690)
 * - /status - Node status (GET)
 * - /config - Node configuration (GET/PUT)
 * - /neighbors - Neighbor table (GET)
 * - /keys - Peer key store (GET/PUT/DELETE, per LCI spec; see coap_keys.c)
 * - /msg/inbox - Messages (GET/POST)
 * - /diag/rangetest - Range testing (GET/POST, spec 18.7, when enabled)
 * - /diag/traceroute - Mesh path discovery (GET, spec 18.7.4, when enabled)
 * - /deaddrop - DTN dead drop (POST, GET?recipient=...) when enabled
 * - /confessions - Anonymous board (POST/GET, rate-limited RAM-only, per project-LICHEN-2nnd.4.2)
 *
 * All payloads use CBOR (content-format 60) for compact encoding.
 */

#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/coap_link_format.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <lichen/coap_server.h>
#include <lichen/senml.h>
#include <lichen/sos_alert.h>
#include <lichen/sos_origin.h>
#include <lichen/schnorr48.h>
#include <lichen/coap_keys.h>
#include <lichen/sos_ratelimit.h>
#include <lichen/oscore.h>
#include <lichen/coap_oscore.h>

/* Plaintext staging for the mutating handlers' authorize helper (the old
 * per-handler unprotect result carried an equivalent on-stack buffer). */
static uint8_t server_plain_buf[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
#include <lichen/l2/ipv6_addr.h>
#include <lichen/transport/slip_transport.h>

LOG_MODULE_REGISTER(lichen_coap_server, CONFIG_LICHEN_COAP_SERVER_LOG_LEVEL);

/* CBOR content-format code */
#define CBOR_CONTENT_FORMAT 60

/* CoAP server port */
static uint16_t s_coap_port = 5683;

static struct lichen_coap_server_handlers s_handlers;

/*
 * Common response helper for all CoAP resources (including deaddrop_post).
 * Centralizes duplicated logic from coap_*.c files. Matches Python/Rust reference
 * behavior and spec/18-applications for DTN. Type=ACK for CON requests.
 * Uses per-call static buffer to avoid both shared race and stack use-after-return.
 * Zephyr coap_resource_send + pending slab performs synchronous memcpy of packet data.
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

	ret = coap_packet_init(&response, buf, sizeof(buf),
			       COAP_VERSION_1, type, tkl, token, resp_code, id);
	if (ret < 0) {
		LOG_ERR("Failed to init response packet: %d", ret);
		return ret;
	}

	if (payload != NULL && payload_len > 0) {
		ret = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT,
					     content_format);
		if (ret < 0) {
			LOG_ERR("Failed to add content-format: %d", ret);
			return ret;
		}

		ret = coap_packet_append_payload_marker(&response);
		if (ret < 0) {
			LOG_ERR("Failed to add payload marker: %d", ret);
			return ret;
		}

		ret = coap_packet_append_payload(&response, payload, (uint16_t)payload_len);
		if (ret < 0) {
			LOG_ERR("Failed to add payload: %d", ret);
			return ret;
		}
	}

	ret = coap_resource_send(resource, &response, addr, addr_len, NULL);
	return ret;
}

/*
 * /status resource - GET returns node status as CBOR
 */
static int status_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t payload[LICHEN_COAP_SERVER_MAX_PAYLOAD];
	int len;

	if (s_handlers.status == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	len = s_handlers.status(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Status callback failed: %d", len);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	int ret = lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, payload, len);
	return ret < 0 ? ret : 0;
}

static const char * const status_path[] = { "status", NULL };
static const char * const status_attrs[] = {
	"rt=\"status\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_status, lichen_coap_server, {
	.get = status_get,
	.path = status_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = status_attrs,
	}),
});

/*
 * /config resource - GET returns config, PUT updates config
 */
static int config_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t payload[LICHEN_COAP_SERVER_MAX_PAYLOAD];
	int len;

	if (s_handlers.config_get == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	len = s_handlers.config_get(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Config GET callback failed: %d", len);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	int ret = lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, payload, len);
	return ret < 0 ? ret : 0;
}

static int config_put(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = 0;
	struct oscore_ctx *oscore_ctx = NULL;
	const uint8_t *payload = NULL;
	uint16_t payload_len = 0;
	bool is_protected = false;
	int ret;

	if (s_handlers.config_put == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	ret = coap_oscore_authorize_mutating(resource, request, addr, addr_len,
					     COAP_METHOD_PUT,
					     server_plain_buf,
					     sizeof(server_plain_buf), &payload,
					     &payload_len, &oscore_ctx, piv,
					     &piv_len, &is_protected);
	if (ret != 0) {
		return ret;
	}

	if (payload == NULL || payload_len == 0) {
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_BAD_REQUEST);
	}

	ret = s_handlers.config_put(payload, payload_len);
	if (ret < 0) {
		LOG_ERR("Config PUT callback failed: %d", ret);
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_BAD_REQUEST);
	}

	return coap_oscore_send_protected(resource, request, addr, addr_len,
					  oscore_ctx, piv, piv_len,
					  COAP_RESPONSE_CODE_CHANGED);
}

static const char * const config_path[] = { "config", NULL };
static const char * const config_attrs[] = {
	"rt=\"config\"",
	"ct=\"60\"",
	NULL,
};

/* coap_config.c already owns the global symbol lichen_config. */
COAP_RESOURCE_DEFINE(lichen_server_config, lichen_coap_server, {
	.get = config_get,
	.put = config_put,
	.path = config_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = config_attrs,
	}),
});

/*
 * /neighbors resource - GET returns neighbor table as CBOR
 */
static int neighbors_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t payload[LICHEN_COAP_SERVER_MAX_PAYLOAD];
	int len;

	if (s_handlers.neighbors == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	len = s_handlers.neighbors(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Neighbors callback failed: %d", len);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	int ret = lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, payload, len);
	return ret < 0 ? ret : 0;
}

static const char * const neighbors_path[] = { "status", "neighbors", NULL };
static const char * const neighbors_attrs[] = {
	"rt=\"status\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_neighbors, lichen_coap_server, {
	.get = neighbors_get,
	.path = neighbors_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = neighbors_attrs,
	}),
});

/*
 * /msg/inbox resource - GET returns inbox, POST delivers message
 */
static int msg_inbox_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t payload[LICHEN_COAP_SERVER_MAX_PAYLOAD];
	int len;

	if (s_handlers.msg_get == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	len = s_handlers.msg_get(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Message GET callback failed: %d", len);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	int ret = lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, payload, len);
	return ret < 0 ? ret : 0;
}

static int msg_inbox_post(struct coap_resource *resource,
			  struct coap_packet *request,
			  struct sockaddr *addr, socklen_t addr_len)
{
	uint32_t msg_id = 0;
	int ret;

	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = 0;
	struct oscore_ctx *oscore_ctx = NULL;
	const uint8_t *payload = NULL;
	uint16_t payload_len = 0;
	bool is_protected = false;
	ret = coap_oscore_authorize_mutating(resource, request, addr, addr_len,
					     COAP_METHOD_POST, server_plain_buf,
					     sizeof(server_plain_buf), &payload,
					     &payload_len, &oscore_ctx, piv,
					     &piv_len, &is_protected);
	if (ret != 0) return ret;
	if (!is_protected && !lichen_coap_is_local_admin(addr, addr_len)) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_UNAUTHORIZED,
					   0, NULL, 0);
	}

	if (s_handlers.msg_post == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	if (payload == NULL || payload_len == 0) {
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_BAD_REQUEST);
	}

	ret = s_handlers.msg_post(payload, payload_len, &msg_id);
	if (ret < 0) {
		LOG_ERR("Message POST callback failed: %d", ret);
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_BAD_REQUEST);
	}

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && oscore_ctx != NULL && piv_len > 0) {
		/* OSCORE response with Location-Path options */
		uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
		struct coap_packet resp;
		int r = coap_oscore_protect_response(oscore_ctx, piv, piv_len,
						     request,
						     COAP_RESPONSE_CODE_CREATED,
						     NULL, 0, &resp, buf, sizeof(buf));
		if (r < 0) {
			return lichen_coap_respond(resource, request, addr, addr_len,
						   COAP_RESPONSE_CODE_INTERNAL_ERROR,
						   0, NULL, 0);
		}
		r = coap_packet_append_option(&resp, COAP_OPTION_LOCATION_PATH,
					      "msg", 3);
		if (r < 0) return r;
		r = coap_packet_append_option(&resp, COAP_OPTION_LOCATION_PATH,
					      "sent", 4);
		if (r < 0) return r;
		char id_str[12];
		int id_len = snprintf(id_str, sizeof(id_str), "%u", msg_id);
		if (id_len < 0 || (size_t)id_len >= sizeof(id_str)) {
			return -EINVAL;
		}
		r = coap_packet_append_option(&resp, COAP_OPTION_LOCATION_PATH,
					      id_str, id_len);
		if (r < 0) return r;
		return coap_resource_send(resource, &resp, addr, addr_len, NULL);
	}
#endif

	static uint8_t response_buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet response;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint16_t id;
	uint8_t tkl;

	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	ret = coap_packet_init(&response, response_buf, sizeof(response_buf),
			       COAP_VERSION_1, COAP_TYPE_ACK, tkl, token,
			       COAP_RESPONSE_CODE_CREATED, id);
	if (ret < 0) {
		return ret;
	}

	ret = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
					"msg", 3);
	if (ret < 0) {
		return ret;
	}

	ret = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
					"sent", 4);
	if (ret < 0) {
		return ret;
	}

	char id_str[12];
	int id_len = snprintf(id_str, sizeof(id_str), "%u", msg_id);
	if (id_len < 0 || (size_t)id_len >= sizeof(id_str)) {
		return -EINVAL;
	}

	ret = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
					id_str, id_len);
	if (ret < 0) {
		return ret;
	}

	ret = coap_resource_send(resource, &response, addr, addr_len, NULL);
	return ret < 0 ? ret : 0;
}

static const char * const msg_inbox_path[] = { "msg", "inbox", NULL };
static const char * const msg_inbox_attrs[] = {
	"rt=\"msg.inbox\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_msg_inbox, lichen_coap_server, {
	.get = msg_inbox_get,
	.post = msg_inbox_post,
	.path = msg_inbox_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = msg_inbox_attrs,
	}),
});

/*
 * /sos resource (spec/18.4, R-12-041): POST accepts a CBOR SOS alert; GET
 * returns the SOS service status. Verification (Schnorr48
 * verify-before-rebroadcast) and rate limiting are wired by beads
 * l1qw.25.2/l1qw.25.3 before this acceptance point processes alerts.
 */
/* Hex digit -> value, 0xFF on invalid (permissive parse of the node
 * string produced by the SOS codec). */
static uint8_t hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
	if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
	if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
	return 0xFF;
}

/* Extract the 8-byte node IID from the alert's hex node string. */
static void alert_node_iid(const struct sos_alert *alert, uint8_t out[8])
{
	for (size_t i = 0; i < 8; i++) {
		char hi = alert->node[2 * i];
		char lo = alert->node[2 * i + 1];
		out[i] = (uint8_t)((hex_nibble(hi) << 4) | hex_nibble(lo));
	}
}

/* Per-source rate limit state (R-12-036/037/038). Single-source scope:
 * the multi-source per-IID table is follow-up work. */
static struct sos_ratelimit_state s_sos_rl_state;

static int sos_post(struct coap_resource *resource,
		    struct coap_packet *request,
		    struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len;
	struct sos_alert alert;
	const uint8_t *payload;
	int ret;

	payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0U) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}

	/* R-12-034/035 + sos_signature.json: the frame carries the origin
	 * signature (8-byte big-endian sequence + 48-byte Schnorr48) after
	 * the CBOR payload; unsigned or truncated frames are silently
	 * dropped (no error response). */
	if (payload_len < SOS_ORIGIN_SIGNATURE_LEN) {
		return -ENOENT;
	}
	size_t cbor_len = payload_len - SOS_ORIGIN_SIGNATURE_LEN;

	struct sos_origin_signature origin_sig;
	if (sos_origin_signature_parse(&origin_sig, payload + cbor_len,
				       SOS_ORIGIN_SIGNATURE_LEN) != 0) {
		return -ENOENT; /* silent drop: truncated signature */
	}

	ret = sos_alert_from_cbor(payload, cbor_len, &alert);
	if (ret != 0) {
		return -ENOENT; /* silent drop: unparseable payload */
	}

	/* Resolve the sender's pinned key from the key store keyed by the
	 * alert's node IID. This layer is lookup-only (no TOFU pinning);
	 * sos_signature.json sos_unknown_pubkey_tofu acceptance requires the
	 * pin path, so an unknown pubkey is silently dropped here until that
	 * wiring lands (tracked separately). */
	uint8_t node_iid[8];
	alert_node_iid(&alert, node_iid);

	struct lichen_key_entry key_entry;
	if (lichen_key_store_get(node_iid, &key_entry) != 0) {
		return -ENOENT; /* silent drop: unknown pubkey */
	}

	/* Origin signature verify (R-12-034: invalid -> silent drop). The
	 * origin IPv6 is the node IID in the LICHEN native 02xx profile. */
	uint8_t origin_ipv6[16] = { 0x02 };
	memcpy(&origin_ipv6[8], node_iid, 8);
	if (!sos_origin_verify(key_entry.pubkey, origin_ipv6, payload, cbor_len,
			       &origin_sig)) {
		return -ENOENT; /* silent drop: bad signature */
	}

	/* R-12-036/037/038: per-source rate limits (10-min cooldown,
	 * 3/hour) on monotonic uptime gate rebroadcast. Violations are
	 * dropped and logged without relaying. The limiter state persists
	 * across requests for the current source; a per-IID table is the
	 * multi-source follow-up. */
	struct sos_ratelimit_config rl_config;

	sos_ratelimit_config_init(&rl_config);
	int64_t now_ms = k_uptime_get();
	uint32_t remaining_ms = 0U;
	enum sos_ratelimit_result rl =
		sos_ratelimit_check(&s_sos_rl_state, now_ms, &rl_config,
				    &remaining_ms);
	if (rl != SOS_RATELIMIT_ALLOWED) {
		LOG_WRN("SOS rate limited (result %d, retry in %u ms)", rl,
			remaining_ms);
		return -ENOENT; /* drop, do not relay */
	}
	sos_ratelimit_record(&s_sos_rl_state, now_ms);

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CHANGED,
				   CBOR_CONTENT_FORMAT, NULL, 0);
}

static int sos_get(struct coap_resource *resource,
		   struct coap_packet *request,
		   struct sockaddr *addr, socklen_t addr_len)
{
	/* R-12-041 status retrieval: minimal CBOR map {"s": true} until
	 * the SOS state store lands with the verify/ratelimit slices. */
	static const uint8_t status_body[] = { 0xA1, 0x61, 0x73, 0xF5 }; /* {"s": true} */

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   CBOR_CONTENT_FORMAT, status_body,
				   sizeof(status_body));
}

static const char * const sos_path[] = { "sos", NULL };
static const char * const sos_attrs[] = {
	"rt=\"sos\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_sos, lichen_coap_server, {
	.get = sos_get,
	.post = sos_post,
	.path = sos_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = sos_attrs,
	}),
});

/*
 * Define the CoAP service
 *
 * Note: When CONFIG_COAP_SERVER_WELL_KNOWN_CORE is enabled, Zephyr's
 * CoAP server automatically handles /.well-known/core requests using
 * the resources registered with this service.
 */
COAP_SERVICE_DEFINE(lichen_coap_server, NULL, &s_coap_port, 0);

int lichen_coap_server_init(const struct lichen_coap_server_handlers *handlers)
{
	if (handlers != NULL) {
		memcpy(&s_handlers, handlers, sizeof(s_handlers));
	} else {
		memset(&s_handlers, 0, sizeof(s_handlers));
	}

	BUILD_ASSERT(LICHEN_COAP_SERVER_MAX_PAYLOAD + 128 <= CONFIG_COAP_SERVER_MESSAGE_SIZE,
		     "server payload exceeds CoAP capacity");

	LOG_INF("CoAP server initialized on port %u", s_coap_port);
	return lichen_coap_server_start();
}

int lichen_coap_server_start(void)
{
	int ret;

	ret = coap_service_start(&lichen_coap_server);
	if (ret < 0 && ret != -EALREADY) {
		LOG_ERR("Failed to start CoAP server: %d", ret);
		return ret;
	}

	LOG_INF("CoAP server started");
	return 0;
}

int lichen_coap_server_stop(void)
{
	int ret;

	ret = coap_service_stop(&lichen_coap_server);
	if (ret < 0 && ret != -EALREADY) {
		LOG_ERR("Failed to stop CoAP server: %d", ret);
		return ret;
	}

	LOG_INF("CoAP server stopped");
	return 0;
}

int lichen_coap_server_is_running(void)
{
	return coap_service_is_running(&lichen_coap_server);
}
