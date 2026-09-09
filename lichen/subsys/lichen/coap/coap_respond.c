/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * Common response helper for all CoAP resources (including deaddrop_post).
 * Centralizes duplicated logic from coap_*.c files. Matches Python/Rust reference
 * behavior and spec/18-applications for DTN. Type=ACK for CON requests.
 * Uses per-call static buffer to avoid both shared race and stack use-after-return.
 * Zephyr coap_resource_send + pending slab performs synchronous memcpy of packet data.
 *
 * Lives in its own translation unit because both CoAP server modes link it:
 * the standalone subsystem-owned service (coap_server.c) and the modular
 * per-resource mode the gateway app uses (LICHEN_COAP_CONFIG without
 * LICHEN_COAP_SERVER_STANDALONE).
 */

#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <lichen/coap_server.h>

LOG_MODULE_REGISTER(lichen_coap_respond, CONFIG_LICHEN_COAP_SERVER_LOG_LEVEL);

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
