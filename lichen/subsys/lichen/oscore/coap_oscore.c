/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_oscore.c
 * @brief CoAP-OSCORE integration
 *
 * Middleware functions to integrate OSCORE protection with Zephyr's CoAP server.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>

#include <lichen/oscore.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>
#include <lichen/l2/ipv6_addr.h>
#ifdef CONFIG_LICHEN_COAP_KEYS
#include <lichen/coap_keys.h>
#endif

LOG_MODULE_DECLARE(oscore, CONFIG_LICHEN_OSCORE_LOG_LEVEL);

/* Static buffer for OSCORE ciphertext to avoid large stack usage on constrained
 * devices (fixes project-LICHEN-zg2d). Size matches CONFIG + tag. */
static uint8_t coap_response_ciphertext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX + OSCORE_TAG_LEN];

/**
 * @brief Translate Zephyr CoAP errno to OSCORE error space.
 */
static inline int coap_err_to_oscore(int err)
{
	if (err >= 0) {
		return OSCORE_OK;
	}
	switch (err) {
	case -ENOMEM:
		return OSCORE_ERR_BUFFER_TOO_SMALL;
	default:
		return OSCORE_ERR_INVALID_PARAM;
	}
}

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
static int unprotect_request(struct oscore_ctx *ctx, const uint8_t *peer,
	struct oscore_ctx_ref *ref, const struct coap_packet *request,
	uint8_t *original_code, uint8_t *options, size_t *options_len,
	uint8_t *payload, size_t *payload_len,
	uint8_t *request_piv, size_t *request_piv_len);

static int origin_context(const struct sockaddr *addr, socklen_t addr_len,
			  struct coap_oscore_origin *origin,
			  uint8_t peer[8])
{
	static const uint8_t linklocal_prefix[8] = {0xfe, 0x80};

	if (addr == NULL || addr_len < sizeof(struct sockaddr_in6) ||
	    addr->sa_family != AF_INET6) {
		return COAP_RESPONSE_CODE_UNAUTHORIZED;
	}
	const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
	const uint8_t *ip = in6->sin6_addr.s6_addr;

	if (memcmp(ip, linklocal_prefix, sizeof(linklocal_prefix)) == 0) {
		/* Established link-local context indexing uses the converted IID. */
		memcpy(origin->iid, ip + 8, sizeof(origin->iid));
		lichen_eui64_to_iid(origin->iid, peer);
		origin->iid[0] &= (uint8_t)~0x02U;
	} else if (ip[0] == 0x02) {
#ifdef CONFIG_LICHEN_COAP_KEYS
		struct lichen_key_entry entry;

		if (lichen_key_store_get_by_ygg_addr(ip, &entry) != 0) {
			return COAP_RESPONSE_CODE_UNAUTHORIZED;
		}
		memcpy(origin->iid, entry.iid, sizeof(origin->iid));
		memcpy(peer, entry.iid, 8);
#else
		return COAP_RESPONSE_CODE_UNAUTHORIZED;
#endif
	} else {
		return COAP_RESPONSE_CODE_UNAUTHORIZED;
	}
	memcpy(origin->address, ip, sizeof(origin->address));
	return 0;
}
#endif

int coap_oscore_unprotect_resource_request(struct coap_resource *resource,
					   struct coap_packet *request,
					   struct sockaddr *addr, /* cppcheck-suppress constParameterPointer ; non-const to match all callers and test stubs */
					   socklen_t addr_len,
					   uint8_t expected_method,
					   struct coap_oscore_unprotect_result *result)
{
	memset(result, 0, sizeof(*result));

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	result->is_protected = coap_oscore_is_protected(request);
	if (result->is_protected) {
		struct coap_oscore_origin origin = {0};
		uint8_t peer[8];

		if (origin_context(addr, addr_len, &origin, peer) != 0) {
			return COAP_RESPONSE_CODE_UNAUTHORIZED;
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		size_t plain_len = sizeof(result->plainbuf);
		result->piv_len = sizeof(result->piv);
		int r = unprotect_request(NULL, peer, &origin.response_ctx, request, &orig_code,
						      opts, &opt_len, result->plainbuf, &plain_len,
						      result->piv, &result->piv_len);
		if (r != OSCORE_OK) {
			return COAP_RESPONSE_CODE_UNAUTHORIZED;
		}
		if (orig_code != expected_method) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		result->payload = result->plainbuf;
		result->payload_len = (uint16_t)plain_len;
		result->ctx = origin.response_ctx.ctx;
		origin.authenticated = true;
		result->origin = origin;
		return 0;
	}
#endif
	result->payload = (uint8_t *)coap_packet_get_payload(request,
							     &result->payload_len);
	return 0;
}

int coap_oscore_authorize_mutating_result(struct coap_resource *resource,
					  struct coap_packet *request,
					  struct sockaddr *addr, socklen_t addr_len,
					  uint8_t expected_method,
					  struct coap_oscore_unprotect_result *result)
{
	return coap_oscore_unprotect_resource_request(resource, request, addr, addr_len,
						      expected_method, result);
}


#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
/*
 * Encode the Content-Format option (option 12, delta 12) as raw CoAP option
 * bytes for the protected (Class E) inner message. Byte-identical to the
 * Rust gateway's encode_content_format_option (gateway.rs): 0 means "no
 * content format" and omits the option entirely (a zero-length 0xc0 option
 * would decode as value 0 = text/plain;charset=utf-8); CoAP uint values use
 * their shortest big-endian representation (RFC 7252 Section 3.2).
 */
static size_t encode_content_format_option(uint16_t content_format, uint8_t buf[3])
{
	if (content_format == 0) {
		return 0;
	}
	if (content_format <= UINT8_MAX) {
		buf[0] = 0xc1;
		buf[1] = (uint8_t)content_format;
		return 2;
	}
	buf[0] = 0xc2;
	buf[1] = (uint8_t)(content_format >> 8);
	buf[2] = (uint8_t)content_format;
	return 3;
}
#endif

int coap_oscore_respond_resource(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len,
				 const struct coap_oscore_unprotect_result *result,
				 uint8_t resp_code, uint16_t content_format,
				 const uint8_t *payload, size_t payload_len)
{
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (result->is_protected) {
		/* Single shared response buffer: the CoAP server dispatches
		 * requests from one thread, matching the static-buffers
		 * pattern used across the coap subsystem (coap_server.c,
		 * coap_status.c). A 1 KiB+ stack frame is too large for the
		 * constrained thread stacks. */
		static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
		struct coap_packet resp;
		int ret;

		/*
		 * A protected request must never receive a cleartext reply
		 * (that would be a downgrade). Without a usable context or
		 * request correlation no response can be protected, so drop
		 * it silently; the client's retransmission/timeout handles
		 * the loss. OSCORE_ERR_CONTEXT_STALE (-EAGAIN) is used for
		 * every silent drop because the CoAP server framework
		 * translates -EPERM/-ENOENT handler returns into cleartext
		 * 4.05/4.04 replies — that must not happen here.
		 */
		if (result->ctx == NULL || result->piv_len == 0) {
			LOG_ERR("OSCORE response dropped: ctx=%p piv_len=%zu",
				(const void *)result->ctx, result->piv_len);
			return OSCORE_ERR_CONTEXT_STALE;
		}

		/* Content-Format is Class E under OSCORE: it must travel
		 * inside the encrypted inner message, not on the outer one.
		 * The cleartext branch below passes content_format to
		 * lichen_coap_respond; the protected branch mirrors that by
		 * encrypting the encoded option (parity with the Rust
		 * gateway, which emits it whenever nonzero). */
		uint8_t cf_opt[3];
		size_t cf_opt_len = encode_content_format_option(content_format, cf_opt);

		ret = coap_oscore_protect_response_ref(result->origin.response_ctx, result->piv,
						   result->piv_len, request,
						   resp_code, cf_opt, cf_opt_len,
						   payload, payload_len,
						   &resp, buf, sizeof(buf));
		if (ret < 0) {
			/*
			 * Protect failed. Never fall back to cleartext for a
			 * protected request. Retry once with an empty 5.00
			 * through the same context; if that also fails (e.g.
			 * consumed correlation, undersized buffers), drop the
			 * response silently — the client's
			 * retransmission/timeout handles the loss.
			 */
			LOG_ERR("OSCORE protect_response failed (%d), retrying empty 5.00", ret);
			ret = coap_oscore_protect_response_ref(result->origin.response_ctx, result->piv,
							   result->piv_len, request,
							   COAP_RESPONSE_CODE_INTERNAL_ERROR,
							   NULL, 0, NULL, 0,
							   &resp, buf, sizeof(buf));
			if (ret < 0) {
				LOG_ERR("OSCORE empty 5.00 protect failed (%d), dropping response",
					ret);
				return OSCORE_ERR_CONTEXT_STALE;
			}
		}
		return coap_resource_send(resource, &resp, addr, addr_len, NULL);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
				   resp_code, content_format, payload, payload_len);
}

bool coap_oscore_is_protected(const struct coap_packet *request)
{
	struct coap_option opt;
	int ret;

	ret = coap_find_options(request, COAP_OPTION_OSCORE, &opt, 1);
	return ret > 0;
}

/**
 * @brief Get the OSCORE option from a CoAP request.
 *
 * @return 0 on success, OSCORE_ERR_NO_CONTEXT if option not present,
 *         OSCORE_ERR_BUFFER_TOO_SMALL if buffer insufficient
 */
int coap_oscore_get_option(const struct coap_packet *request,
			   uint8_t *opt_data, size_t *opt_len)
{
	struct coap_option opt;
	int ret;

	/*
	 * Note: We trust Zephyr's coap_find_options to return valid
	 * opt.value and opt.len from the parsed packet. If processing
	 * untrusted network packets, Zephyr's CoAP parser provides the
	 * first line of defense against malformed packets.
	 */
	ret = coap_find_options(request, COAP_OPTION_OSCORE, &opt, 1);
	if (ret < 1) {
		return OSCORE_ERR_NO_CONTEXT;
	}

	if (opt.len > *opt_len) {
		return OSCORE_ERR_BUFFER_TOO_SMALL;
	}

	memcpy(opt_data, opt.value, opt.len);
	*opt_len = opt.len;
	return OSCORE_OK;
}

static int unprotect_request(struct oscore_ctx *ctx, const uint8_t *peer,
				  struct oscore_ctx_ref *ref,
				  const struct coap_packet *request,
				  uint8_t *original_code,
				  uint8_t *options, size_t *options_len,
				  uint8_t *payload, size_t *payload_len,
				  uint8_t *request_piv, size_t *request_piv_len)
{
	uint8_t oscore_opt[32];
	size_t oscore_opt_len = sizeof(oscore_opt);
	const uint8_t *ciphertext;
	uint16_t ciphertext_len;
	struct oscore_option opt;
	size_t request_piv_capacity;
	int ret;

	/* Validate all output pointers (defensive despite _Nonnull) */
	if (original_code == NULL || options_len == NULL ||
	    payload_len == NULL || request_piv == NULL ||
	    request_piv_len == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}
	request_piv_capacity = *request_piv_len;

	/* Get OSCORE option */
	ret = coap_oscore_get_option(request, oscore_opt, &oscore_opt_len);
	if (ret != 0) {
		return ret;
	}

	/* Parse OSCORE option to extract PIV */
	ret = oscore_option_parse(oscore_opt, oscore_opt_len, &opt);
	if (ret != OSCORE_OK) {
		return ret;
	}

	/* Validate correlation output capacity, but publish only after auth. */
	if (!opt.has_piv || opt.piv_len == 0) {
		return OSCORE_ERR_INVALID_PARAM;
	}
	if (request_piv_capacity < opt.piv_len) {
		return OSCORE_ERR_BUFFER_TOO_SMALL;
	}

	/* Get encrypted payload */
	ciphertext = coap_packet_get_payload(request, &ciphertext_len);
	if (ciphertext == NULL || ciphertext_len == 0) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Unprotect */
	if (peer != NULL) {
		ret = oscore_unprotect_request_by_peer(peer, oscore_opt, oscore_opt_len,
			ciphertext, ciphertext_len, original_code, options, options_len,
			payload, payload_len, ref);
	} else {
		ret = oscore_unprotect_request(ctx,
				       oscore_opt, oscore_opt_len,
				       ciphertext, ciphertext_len,
				       original_code,
				       options, options_len,
				       payload, payload_len);
	}
	if (ret != OSCORE_OK) {
		LOG_WRN("OSCORE unprotect failed: %d", ret);
		return ret;
	}

	memcpy(request_piv, opt.piv, opt.piv_len);
	*request_piv_len = opt.piv_len;

	LOG_DBG("Unprotected OSCORE request: code=0x%02x, payload=%zu",
		*original_code, *payload_len);
	return OSCORE_OK;
}

int coap_oscore_unprotect_request(struct oscore_ctx *ctx,
	const struct coap_packet *request, uint8_t *original_code,
	uint8_t *options, size_t *options_len, uint8_t *payload, size_t *payload_len,
	uint8_t *request_piv, size_t *request_piv_len)
{
	return unprotect_request(ctx, NULL, NULL, request, original_code,
		options, options_len, payload, payload_len, request_piv, request_piv_len);
}

static int protect_response(struct oscore_ctx *ctx, const struct oscore_ctx_ref *ref,
				 const uint8_t *request_piv, size_t request_piv_len,
				 const struct coap_packet *original_request,
				 uint8_t response_code,
				 const uint8_t *options, size_t options_len,
				 const uint8_t *payload, size_t payload_len,
				 struct coap_packet *response,
				 uint8_t *resp_buf, size_t resp_buf_len)
{
	uint8_t *ciphertext = coap_response_ciphertext;
	size_t ciphertext_len = sizeof(coap_response_ciphertext);
	uint8_t oscore_opt[16];
	size_t oscore_opt_len = sizeof(oscore_opt);
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl;
	uint8_t type;
	int ret;
	if (resp_buf_len > UINT16_MAX) return -EINVAL;

	/* Protect the response */
	if (ref != NULL) {
		ret = oscore_protect_response_ref(ref, request_piv, request_piv_len,
			response_code, options, options_len, payload, payload_len,
			ciphertext, &ciphertext_len, oscore_opt, &oscore_opt_len);
	} else {
		ret = oscore_protect_response(ctx,
				      request_piv, request_piv_len,
				      response_code,
				      options, options_len,
				      payload, payload_len,
				      ciphertext, &ciphertext_len,
				      oscore_opt, &oscore_opt_len);
	}
	if (ret != OSCORE_OK) {
		LOG_ERR("OSCORE protect_response failed: %d", ret);
		return ret;
	}

	/* Build CoAP response packet */
	tkl = coap_header_get_token(original_request, token);
	type = (coap_header_get_type(original_request) == COAP_TYPE_CON)
	       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;

	ret = coap_packet_init(response, resp_buf, (uint16_t)resp_buf_len,
			       COAP_VERSION_1, type, tkl, token,
			       COAP_RESPONSE_CODE_CHANGED, /* Outer code for OSCORE */
			       coap_header_get_id(original_request));
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	/* Add OSCORE option */
	ret = coap_packet_append_option(response, COAP_OPTION_OSCORE,
					oscore_opt, oscore_opt_len);
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	/* Add payload marker and ciphertext */
	ret = coap_packet_append_payload_marker(response);
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	ret = coap_packet_append_payload(response, ciphertext, (uint16_t)ciphertext_len);
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	LOG_DBG("Protected OSCORE response: ct_len=%zu", ciphertext_len);
	return 0;
}

int coap_oscore_protect_response_ref(struct oscore_ctx_ref ref,
	const uint8_t *piv, size_t piv_len, const struct coap_packet *request,
	uint8_t code, const uint8_t *options, size_t options_len,
	const uint8_t *payload, size_t payload_len, struct coap_packet *response,
	uint8_t *buf, size_t buf_len)
{
	return protect_response(NULL, &ref, piv, piv_len, request, code,
		options, options_len, payload, payload_len, response, buf, buf_len);
}

int coap_oscore_protect_response(struct oscore_ctx *ctx,
	const uint8_t *piv, size_t piv_len, const struct coap_packet *request,
	uint8_t code, const uint8_t *options, size_t options_len,
	const uint8_t *payload, size_t payload_len, struct coap_packet *response,
	uint8_t *buf, size_t buf_len)
{
	return protect_response(ctx, NULL, piv, piv_len, request, code,
		options, options_len, payload, payload_len, response, buf, buf_len);
}

int lichen_coap_oscore_respond(struct coap_resource *resource,
			       const struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len,
			       struct oscore_ctx *ctx,
			       const uint8_t *piv, size_t piv_len,
			       uint8_t code)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	int ret = coap_oscore_protect_response(ctx, piv, piv_len, request, code,
					       NULL, 0, NULL, 0,
					       &resp, buf, sizeof(buf));
	if (ret < 0) {
		/*
		 * Protect failed. Never fall back to cleartext on a protected
		 * exchange. Retry once with an empty 5.00 through the same
		 * context; if that also fails, drop the response silently —
		 * the client's retransmission/timeout handles the loss.
		 * OSCORE_ERR_CONTEXT_STALE (-EAGAIN) avoids the CoAP server
		 * framework's -EPERM/-ENOENT cleartext translations.
		 */
		LOG_ERR("OSCORE protect_response failed (%d), retrying empty 5.00", ret);
		ret = coap_oscore_protect_response(ctx, piv, piv_len, request,
						   COAP_RESPONSE_CODE_INTERNAL_ERROR,
						   NULL, 0, NULL, 0,
						   &resp, buf, sizeof(buf));
		if (ret < 0) {
			LOG_ERR("OSCORE empty 5.00 protect failed (%d), dropping response", ret);
			return OSCORE_ERR_CONTEXT_STALE;
		}
	}
	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

int coap_oscore_send_protected(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len,
			       struct oscore_ctx_ref ctx,
			       const uint8_t *piv, size_t piv_len,
			       uint8_t code)
{
	/* Static per the project response-buffer pattern (zg2d, 2m4y): the
	 * CoAP server dispatch serializes resource handlers. */
	static uint8_t buf[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX + OSCORE_TAG_LEN];
	struct coap_packet resp;
	int ret;

	if (ctx.ctx == NULL && ctx.generation == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   code, 0, NULL, 0);
	}
	ret = coap_oscore_protect_response_ref(ctx, piv, piv_len, request, code,
					   NULL, 0, NULL, 0, &resp, buf, sizeof(buf));
	if (ret < 0) {
		/* A protected request must never receive a cleartext reply
		 * (project invariant, coap_oscore.c:104-113).  Retry once
		 * with a protected empty 5.00 through the same context and
		 * drop silently if that also fails, mirroring
		 * coap_oscore_respond_resource's protect-failure path. */
		ret = coap_oscore_protect_response_ref(ctx, piv, piv_len, request,
						   COAP_RESPONSE_CODE_INTERNAL_ERROR,
						   NULL, 0, NULL, 0, &resp, buf,
						   sizeof(buf));
		if (ret < 0) {
			LOG_ERR("OSCORE empty 5.00 protect failed (%d), dropping response", ret);
			return OSCORE_ERR_CONTEXT_STALE;
		}
	}
	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

int coap_oscore_authorize_mutating_with_origin(struct coap_resource *resource,
				   struct coap_packet *request,
				   struct sockaddr *addr, socklen_t addr_len,
				   uint8_t expected_method,
				   uint8_t *plain_buf, size_t plain_buf_len,
				   const uint8_t **payload_out,
				   uint16_t *payload_len_out,
				   struct oscore_ctx **ctx_out,
				   uint8_t *piv_out, size_t *piv_len_out,
				   bool *is_protected,
				   struct coap_oscore_origin *origin_out)
{
	if (origin_out != NULL) {
		memset(origin_out, 0, sizeof(*origin_out));
	}

	*payload_out = NULL;
	*payload_len_out = 0;
	*ctx_out = NULL;
	*piv_len_out = 0;
	*is_protected = false;

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	*is_protected = coap_oscore_is_protected(request);
	if (*is_protected) {
		uint8_t peer[8];
		struct coap_oscore_origin origin = {0};
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		size_t pbuf_len = plain_buf_len;
		size_t ppiv_len = OSCORE_PIV_MAX_LEN;
		uint8_t *plain_dst = plain_buf;
		uint8_t scratch;
		int r;

		if (plain_dst == NULL || pbuf_len == 0) {
			/* fmee: unprotect always writes plaintext; callers
			 * that pass no buffer (no payload expected) get a
			 * fail-closed scratch so a payload-carrying request
			 * fails the capacity check instead of smashing NULL.
			 */
			plain_dst = &scratch;
			pbuf_len = sizeof(scratch);
		}
		if (origin_context(addr, addr_len, &origin, peer) != 0) {
			/* The dispatcher sends the returned code; never
			 * double-send here, and never return the send
			 * status (0) or the caller would treat the
			 * unknown peer as authorized. */
			return COAP_RESPONSE_CODE_UNAUTHORIZED;
		}
		r = unprotect_request(NULL, peer, &origin.response_ctx, request, &orig_code,
						  opts, &opt_len,
						  plain_dst, &pbuf_len,
						  piv_out, &ppiv_len);
		if (r != 0) {
			return COAP_RESPONSE_CODE_UNAUTHORIZED;
		}
		if (orig_code != expected_method) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		if (plain_buf == NULL && pbuf_len > 0) {
			/* No-payload caller: a decrypted payload cannot be
			 * published (the scratch is function-local). */
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
		*ctx_out = origin.response_ctx.ctx;
		*piv_len_out = ppiv_len;
		/* The fail-closed scratch never escapes: callers that passed
		 * no buffer get a NULL payload (len 0) on success. */
		*payload_out = (plain_dst != &scratch) ? plain_dst : NULL;
		*payload_len_out = (uint16_t)pbuf_len;
		if (origin_out != NULL) {
			origin.authenticated = true;
			*origin_out = origin;
		}
		return 0;
	}
#endif
#ifdef CONFIG_LICHEN_COAP_KEYS
	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		return COAP_RESPONSE_CODE_UNAUTHORIZED;
	}
	*payload_out = coap_packet_get_payload(request, payload_len_out);
	return 0;
#else
	/* The local-admin provider belongs to the optional key-store module. */
	return COAP_RESPONSE_CODE_UNAUTHORIZED;
#endif
}

int coap_oscore_authorize_mutating(struct coap_resource *resource,
	struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len,
	uint8_t expected_method, uint8_t *plain_buf, size_t plain_buf_len,
	const uint8_t **payload_out, uint16_t *payload_len_out,
	struct oscore_ctx_ref *ctx_out, uint8_t *piv_out, size_t *piv_len_out,
	bool *is_protected)
{
	struct coap_oscore_origin origin;
	struct oscore_ctx *ctx;
	int ret = coap_oscore_authorize_mutating_with_origin(resource, request, addr,
		addr_len, expected_method, plain_buf, plain_buf_len, payload_out,
		payload_len_out, &ctx, piv_out, piv_len_out, is_protected, &origin);
	*ctx_out = origin.response_ctx;
	return ret;
}

int coap_oscore_send_unauthorized(struct coap_resource *resource,
				  struct coap_packet *request,
				  struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t buf[64];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int ret;

	ret = coap_packet_init(&resp, buf, (uint16_t)sizeof(buf),
			       COAP_VERSION_1, type, tkl, token,
			       COAP_RESPONSE_CODE_UNAUTHORIZED,
			       coap_header_get_id(request));
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	ret = coap_resource_send(resource, &resp, addr, addr_len, NULL);
	return coap_err_to_oscore(ret);
}
