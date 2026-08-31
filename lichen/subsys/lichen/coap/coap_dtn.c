/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zcbor_decode.h>
#include <zephyr/net/net_ip.h>
#include <lichen/coap_server.h>
#include <lichen/coap_client.h>
#include <lichen/coap_dtn.h>
#include <lichen/coap_oscore.h>
#include <lichen/link.h>
#include <lichen/oscore.h>
#include <lichen/routing/dtn.h>
#include <lichen/senml.h>
#include <lichen/l2/ipv6_addr.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DEADDROP_LOG_LEVEL);

static struct lichen_deaddrop_provider *s_provider;
static struct lichen_dtn_buffer s_dtn_buf;
static K_MUTEX_DEFINE(s_dtn_buf_mutex);
static struct k_work_delayable s_dtn_expire_work;
static uint32_t s_last_deaddrop[256] = {0};
static uint32_t s_last_confession[256] = {0};
static K_MUTEX_DEFINE(s_rate_mutex);
static K_MUTEX_DEFINE(s_senml_pack_mutex);

static bool parse_recipient(const uint8_t *payload, size_t len,
			    uint8_t dest_iid[8])
{
	if (!payload || len == 0) return false;
	ZCBOR_STATE_D(zsd, 8, payload, len, 1, 0);
	if (!zcbor_map_start_decode(zsd)) return false;
	while (!zcbor_map_end_decode(zsd)) {
		struct zcbor_string key;
		if (zcbor_tstr_decode(zsd, &key) && key.len == 1 &&
		    key.value[0] == 'r') {
			struct zcbor_string val;
			if (zcbor_bstr_decode(zsd, &val) && val.len >= 8) {
				memcpy(dest_iid, val.value, 8);
				return true;
			}
		} else if (!zcbor_any_skip(zsd, NULL)) break;
	}
	zcbor_list_map_end_force_decode(zsd);
	return false;
}

/* DTN expiry decisions use the wall clock only (spec 05-routing.md
 * R-05-080: a node without valid wall-clock time MUST NOT drop messages
 * based on expiry timestamp alone; docs/firmware-time-provider.md:
 * never synthesize Unix time from uptime). When the clock is invalid,
 * expiry sweeps are skipped and the store path uses DTN_NO_EXPIRY so
 * the message is held for downstream nodes with valid time to enforce
 * expiry. */
#define DTN_NO_EXPIRY UINT32_MAX

static bool dtn_wall_clock(uint32_t *unix_time)
{
#ifdef CONFIG_LICHEN_CCP_TIME_SYNC
	if (!lichen_wall_clock_valid()) {
		return false;
	}
	*unix_time = lichen_wall_clock_get();
	return true;
#else
	/* No time-sync provider compiled in: the node is clockless for
	 * DTN purposes (R-05-080 fail open). */
	ARG_UNUSED(unix_time);
	return false;
#endif
}

static void dtn_expire_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	uint32_t now;

	if (dtn_wall_clock(&now)) {
		k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
		lichen_dtn_expire_old(&s_dtn_buf, now);
		k_mutex_unlock(&s_dtn_buf_mutex);
	}
	/* Clock invalid: fail open, nothing expires on our watch. */
	k_work_reschedule(&s_dtn_expire_work, K_SECONDS(30));
}

int lichen_coap_deaddrop_register(
	struct lichen_deaddrop_provider *provider)
{
	if (provider == NULL) return -EINVAL;
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	if (s_provider != NULL) {
		k_mutex_unlock(&s_dtn_buf_mutex);
		return -EALREADY;
	}
	int r = lichen_coap_dtn_init();
	if (r < 0) {
		k_mutex_unlock(&s_dtn_buf_mutex);
		return r;
	}
	r = lichen_dtn_init(&s_dtn_buf);
	if (r < 0) {
		k_mutex_unlock(&s_dtn_buf_mutex);
		return r;
	}
	s_provider = provider;
	s_provider->dtn_buf = &s_dtn_buf;
	k_work_init_delayable(&s_dtn_expire_work, dtn_expire_work_handler);
	uint32_t now;
	if (dtn_wall_clock(&now)) {
		lichen_dtn_expire_old(&s_dtn_buf, now);
	}
	k_work_schedule(&s_dtn_expire_work, K_SECONDS(30));
	k_mutex_unlock(&s_dtn_buf_mutex);
	return 0;
}

static int deaddrop_post(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	if (s_provider == NULL || s_provider->store == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}
	uint8_t dest_iid[8] = {0};
	uint8_t peer_eui64[8] = {0};
	if (addr_len >= sizeof(struct sockaddr_in6) &&
	    addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)addr;
		memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
		lichen_eui64_to_iid(peer_eui64, peer_eui64);
	}
	struct coap_oscore_unprotect_result oscore;
	int ret = coap_oscore_unprotect_resource_request(resource, request,
							 addr, addr_len,
							 COAP_METHOD_POST,
							 &oscore);
	if (ret != 0) return ret;
	if (!oscore.is_protected &&
	    !lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0);
	}
	const uint8_t *payload = oscore.payload;
	uint16_t payload_len = oscore.payload_len;
	if (!payload || payload_len == 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}
	parse_recipient(payload, payload_len, dest_iid);
	uint32_t now_ms = k_uptime_get_32();
	uint8_t iid7 = peer_eui64[7];
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	if (s_last_deaddrop[iid7] &&
	    (now_ms - s_last_deaddrop[iid7] <
	     CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS)) {
		k_mutex_unlock(&s_rate_mutex);
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_TOO_MANY_REQUESTS,
						    0, NULL, 0);
	}
	s_last_deaddrop[iid7] = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	if (s_provider && s_provider->store) {
		int r = s_provider->store(payload, payload_len);
		if (r < 0) {
			k_mutex_unlock(&s_dtn_buf_mutex);
			return coap_oscore_respond_resource(resource, request,
							    addr, addr_len,
							    &oscore,
							    COAP_RESPONSE_CODE_INTERNAL_ERROR,
							    0, NULL, 0);
		}
	}
	uint32_t now = 0U;
	uint32_t expiry = DTN_NO_EXPIRY;

	/* Clockless node (R-05-080): no valid wall clock means no local
	 * expiry decision - store with the no-expiry sentinel and let
	 * downstream nodes with valid time enforce. now stays 0 (the
	 * honest "no time"), which the buffer accepts because
	 * DTN_NO_EXPIRY > 0. */
	if (dtn_wall_clock(&now)) {
		/* Saturate to the sentinel on wrap (clock near UINT32_MAX
		 * or garbage-but-valid time): fail open, never store an
		 * already-expired or accidentally never-expiring value. */
		expiry = (now > UINT32_MAX - LICHEN_DTN_DEFAULT_TTL_SEC)
				 ? DTN_NO_EXPIRY
				 : now + LICHEN_DTN_DEFAULT_TTL_SEC;
	}
	bool ok = lichen_dtn_buffer_message(&s_dtn_buf, payload, payload_len,
					    dest_iid, expiry, now, now_ms);
	k_mutex_unlock(&s_dtn_buf_mutex);
	uint8_t resp_code = ok ? COAP_RESPONSE_CODE_CHANGED
			       : COAP_RESPONSE_CODE_BAD_REQUEST;
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, resp_code, 0, NULL, 0);
}

static int deaddrop_get(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	if (s_provider == NULL || s_provider->retrieve == NULL) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}
	const char *node = NULL;
	struct coap_option qopts[4];
	int qcnt = coap_find_options(request, COAP_OPTION_URI_QUERY, qopts, 4);
	for (int i = 0; i < qcnt; i++) {
		if (qopts[i].len > 5 &&
		    memcmp(qopts[i].value, "node=", 5) == 0) {
			node = (const char *)qopts[i].value + 5;
			break;
		}
	}
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	uint8_t buf[256];
	int len = s_provider->retrieve(buf, sizeof(buf), node);
	k_mutex_unlock(&s_dtn_buf_mutex);
	if (len < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL,
				    0);
	}
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT,
			    SENML_CBOR_CONTENT_FORMAT, buf, (size_t)len);
}

static int confessions_get(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t buf[64];
	struct senml_pack pack;
	uint32_t now = 0U;

	/* No valid wall clock -> base_time 0 omits bt instead of
	 * synthesizing a timestamp from uptime. */
	(void)dtn_wall_clock(&now);
	k_mutex_lock(&s_senml_pack_mutex, K_FOREVER);
	senml_pack_init(&pack, NULL, now);
	senml_add_float(&pack, SENML_KEY_CONFESSIONS, NULL, 0.0f);
	int len = senml_encode_cbor(&pack, buf, sizeof(buf));
	k_mutex_unlock(&s_senml_pack_mutex);
	if (len < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL,
				    0);
	}
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT,
			    SENML_CBOR_CONTENT_FORMAT, buf, (size_t)len);
}

static int confessions_post(struct coap_resource *resource,
			    struct coap_packet *request,
			    struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t peer_eui64[8] = {0};
	if (addr_len >= sizeof(struct sockaddr_in6) &&
	    addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)addr;
		memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
		lichen_eui64_to_iid(peer_eui64, peer_eui64);
	}
	struct coap_oscore_unprotect_result oscore;
	int ret = coap_oscore_unprotect_resource_request(resource, request,
							 addr, addr_len,
							 COAP_METHOD_POST,
							 &oscore);
	if (ret != 0) return ret;
	if (!oscore.is_protected &&
	    !lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0);
	}
	if (oscore.payload == NULL || oscore.payload_len == 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}
	uint32_t now_ms = k_uptime_get_32();
	uint8_t iid7 = peer_eui64[7];
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	if (s_last_confession[iid7] &&
	    (now_ms - s_last_confession[iid7] <
	     CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS)) {
		k_mutex_unlock(&s_rate_mutex);
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_TOO_MANY_REQUESTS,
						    0, NULL, 0);
	}
	s_last_confession[iid7] = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CHANGED,
					    0, NULL, 0);
}

int lichen_coap_dtn_init(void)
{
	int r = oscore_init();
	if (r < 0) return r;
	return lichen_coap_client_init();
}

uint16_t lichen_dtn_expire_periodic(void)
{
	uint32_t now;

	/* R-05-080: clockless node must not drop on expiry - fail open. */
	if (!dtn_wall_clock(&now)) {
		return 0U;
	}
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	uint16_t expired = lichen_dtn_expire_old(&s_dtn_buf, now);
	k_mutex_unlock(&s_dtn_buf_mutex);
	return expired;
}

static const char *const deaddrop_path[] = { "deaddrop", NULL };
COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap_server, {
	.get = deaddrop_get,
	.post = deaddrop_post,
	.path = deaddrop_path,
});

static const char *const confessions_path[] = { "confessions", NULL };
COAP_RESOURCE_DEFINE(lichen_confessions, lichen_coap_server, {
	.get = confessions_get,
	.post = confessions_post,
	.path = confessions_path,
});
