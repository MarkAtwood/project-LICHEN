/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_client.c
 * @brief CoAP client for mesh requests
 *
 * Implements asynchronous CoAP client using Zephyr's coap_client APIs.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_client.h>

#include <lichen/coap_client.h>

LOG_MODULE_REGISTER(lichen_coap_client, LOG_LEVEL_INF);

/* CBOR content-format code */
#define CBOR_CONTENT_FORMAT 60

/* CoAP client socket */
static int s_sock = -1;
static struct coap_client s_client;
static bool s_initialized;

int lichen_coap_client_init(void)
{
	int ret;

	if (s_initialized) {
		return 0;
	}

	/* Create UDP socket for CoAP */
	s_sock = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (s_sock < 0) {
		LOG_ERR("Failed to create socket: %d", errno);
		return -errno;
	}

	/* Initialize CoAP client */
	ret = coap_client_init(&s_client, NULL);
	if (ret < 0) {
		LOG_ERR("CoAP client init failed: %d", ret);
		zsock_close(s_sock);
		s_sock = -1;
		return ret;
	}

	s_initialized = true;
	LOG_INF("CoAP client initialized");
	return 0;
}

/*
 * Internal response handler that maps to user callback.
 */
struct request_ctx {
	lichen_coap_response_cb callback;
	void *user_data;
};

static void coap_response_handler(int16_t code, size_t offset, const uint8_t *payload,
				  size_t len, bool last_block, void *user_data)
{
	struct request_ctx *ctx = user_data;

	if (ctx == NULL || ctx->callback == NULL) {
		return;
	}

	/* For simplicity, only handle non-blockwise responses */
	if (offset == 0 && last_block) {
		ctx->callback(ctx->user_data, (uint8_t)code, payload, len);
	}

	/* Free context after last block */
	if (last_block) {
		k_free(ctx);
	}
}

int lichen_coap_request(const struct lichen_coap_request *req)
{
	struct coap_client_request client_req = {0};
	struct request_ctx *ctx;
	int ret;

	if (!s_initialized) {
		ret = lichen_coap_client_init();
		if (ret < 0) {
			return ret;
		}
	}

	if (req == NULL) {
		return LICHEN_COAP_ERR_NO_MEMORY;
	}

	/* Allocate context for callback */
	ctx = k_malloc(sizeof(*ctx));
	if (ctx == NULL) {
		return LICHEN_COAP_ERR_NO_MEMORY;
	}
	ctx->callback = req->callback;
	ctx->user_data = req->user_data;

	/* Build request */
	client_req.method = req->method;
	client_req.confirmable = req->confirmable;
	client_req.path = req->path[0];  /* First path component */
	client_req.payload = (uint8_t *)req->payload;
	client_req.len = req->payload_len;
	client_req.cb = coap_response_handler;
	client_req.user_data = ctx;

	if (req->content_format != 0) {
		client_req.fmt = req->content_format;
	}

	/* Send request */
	ret = coap_client_req(&s_client, s_sock,
			      (const struct sockaddr *)&req->addr,
			      &client_req, NULL);
	if (ret < 0) {
		LOG_WRN("CoAP request failed: %d", ret);
		k_free(ctx);
		return LICHEN_COAP_ERR_SEND_FAILED;
	}

	return LICHEN_COAP_OK;
}

int lichen_coap_get(const struct sockaddr_in6 *addr,
		    const char * const *path,
		    lichen_coap_response_cb callback,
		    void *user_data)
{
	struct lichen_coap_request req = {
		.method = COAP_METHOD_GET,
		.path = path,
		.confirmable = true,
		.callback = callback,
		.user_data = user_data,
		.timeout_ms = LICHEN_COAP_TIMEOUT_MS,
	};

	memcpy(&req.addr, addr, sizeof(req.addr));

	return lichen_coap_request(&req);
}

int lichen_coap_post_cbor(const struct sockaddr_in6 *addr,
			  const char * const *path,
			  const uint8_t *payload, size_t payload_len,
			  lichen_coap_response_cb callback,
			  void *user_data)
{
	struct lichen_coap_request req = {
		.method = COAP_METHOD_POST,
		.path = path,
		.payload = payload,
		.payload_len = payload_len,
		.content_format = CBOR_CONTENT_FORMAT,
		.confirmable = true,
		.callback = callback,
		.user_data = user_data,
		.timeout_ms = LICHEN_COAP_TIMEOUT_MS,
	};

	memcpy(&req.addr, addr, sizeof(req.addr));

	return lichen_coap_request(&req);
}
