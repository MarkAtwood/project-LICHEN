/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zcbor_decode.h>
#include <zcbor_encode.h>
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
#include <lichen/link.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DEADDROP_LOG_LEVEL);

#define LICHEN_DEADDROP_ID_MAX 12U

static struct lichen_deaddrop_provider *s_provider;
static struct lichen_dtn_buffer s_dtn_buf;
static K_MUTEX_DEFINE(s_dtn_buf_mutex);
static struct k_work_delayable s_dtn_expire_work;
static uint32_t s_last_deaddrop[256] = {0};
static uint32_t s_last_confession[256] = {0};
/* Spec 18.9: 6 POSTs per source per hour (rolling fixed window). */
static uint8_t s_hourly_count[256] = {0};
static uint32_t s_hourly_window_start[256] = {0};
static K_MUTEX_DEFINE(s_rate_mutex);
/* Spec 18.9: total stored-bytes budget (8 KB leaf, 32 KB BR). */
static size_t s_dtn_bytes;
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
 * expiry sweeps are skipped and the store path uses the expiry==0
 * fail-open sentinel ("no validated deadline", see routing/dtn.h) so
 * the message is held for downstream nodes with valid time to enforce
 * expiry. Guarded because time_sync.c only links with
 * CONFIG_LICHEN_CCP_TIME_SYNC. */
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
	struct coap_oscore_unprotect_result oscore = {0};
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = 0;
	struct oscore_ctx *oscore_ctx = NULL;
	const uint8_t *payload = NULL;
	uint16_t payload_len = 0;
	bool is_protected = false;
	/* The embedded plainbuf is required: authorize_mutating() rejects
	 * payload-carrying requests when called with a NULL buffer, and
	 * coap_oscore_respond_resource() (used for the payload-carrying
	 * 4.13/5.03 bodies) consumes this result struct. */
	int ret = coap_oscore_authorize_mutating(resource, request, addr,
						 addr_len, COAP_METHOD_POST,
						 oscore.plainbuf,
						 sizeof(oscore.plainbuf), &payload,
						 &payload_len, &oscore_ctx,
						 piv, &piv_len,
						 &is_protected);
	if (ret != 0) return ret;
	oscore.ctx = oscore_ctx;
	oscore.piv_len = piv_len;
	oscore.is_protected = is_protected;
	memcpy(oscore.piv, piv, piv_len);
	if (!payload || payload_len == 0) {
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_BAD_REQUEST);
	}
	parse_recipient(payload, payload_len, dest_iid);
	/* Spec 18.9: max drop size 1536 B — oversize is rejected statelessly
	 * before rate limiting and storage (4.13 Request Entity Too Large). */
	if (payload_len > CONFIG_LICHEN_DTN_MAX_PACKET_SIZE) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_MAKE_RESPONSE_CODE(4, 13),
						    0, NULL, 0);
	}
	uint32_t now_ms = k_uptime_get_32();
	uint8_t iid7 = peer_eui64[7];
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	if (s_last_deaddrop[iid7] &&
	    (now_ms - s_last_deaddrop[iid7] <
	     CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS)) {
		k_mutex_unlock(&s_rate_mutex);
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_TOO_MANY_REQUESTS);
	}
	/* Spec 18.9 hourly cap: 6 POSTs per source per hour. */
	if (now_ms - s_hourly_window_start[iid7] >= 3600000U) {
		s_hourly_window_start[iid7] = now_ms;
		s_hourly_count[iid7] = 0U;
	}
	if (s_hourly_count[iid7] >=
	    CONFIG_LICHEN_COAP_DEADDROP_HOURLY_LIMIT) {
		k_mutex_unlock(&s_rate_mutex);
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_TOO_MANY_REQUESTS);
	}
	s_hourly_count[iid7]++;
	s_last_deaddrop[iid7] = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	if (s_provider && s_provider->store) {
		int r = s_provider->store(payload, payload_len);
		if (r < 0) {
			k_mutex_unlock(&s_dtn_buf_mutex);
			return coap_oscore_send_protected(resource, request,
							  addr, addr_len,
							  oscore_ctx, piv,
							  piv_len,
							  COAP_RESPONSE_CODE_INTERNAL_ERROR);
		}
	}
	uint32_t now = 0U;
	uint32_t expiry = 0U;

	/* Clockless node (R-05-080): no valid wall clock means no local
	 * expiry decision - store with the expiry==0 fail-open sentinel
	 * ("no validated deadline", dtn.h) and let downstream nodes with
	 * valid time enforce. now stays 0 (the honest "no time"); the
	 * buffer admits the record because the sentinel bypasses the
	 * expiry check. */
	if (dtn_wall_clock(&now)) {
		/* Saturate to the sentinel on wrap (clock near UINT32_MAX
		 * or garbage-but-valid time): fail open, never store a
		 * wrapped already-expired value. */
		expiry = (now > UINT32_MAX - LICHEN_DTN_DEFAULT_TTL_SEC)
				 ? 0U
				 : now + LICHEN_DTN_DEFAULT_TTL_SEC;
	}
	if (s_dtn_bytes + payload_len > CONFIG_LICHEN_DTN_MAX_BYTES) {
		/* Spec 18.9: storage full -> 5.03 (structured CBOR body
		 * {reason: storage_full, ...} requires an
		 * coap_oscore_send_protected payload parameter — tracked
		 * separately, the API is oscore-bar). */
		k_mutex_unlock(&s_dtn_buf_mutex);
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);
	}
	bool ok = lichen_dtn_buffer_message(&s_dtn_buf, payload, payload_len,
					    dest_iid, expiry, now, now_ms);
	/* Merge resolution (HEAD + beads-worker-7): keep HEAD's stored-bytes
	 * budget accounting on success, and beads-worker-7's structured 5.03
	 * storage_full CBOR diagnostic on rejection (spec 18.9); storage
	 * failures are 5.03, not HEAD's 4.00. */
	if (ok) {
		s_dtn_bytes += payload_len;
	}
	uint8_t body[40];
	size_t body_len = 0;
	if (!ok) {
		/* Spec 18.9: storage exhausted -> 5.03 Service Unavailable
		 * with the storage_full CBOR diagnostic. Field set matches the
		 * deaddrop.json storage_full_rejection vector exactly
		 * ({reason, retry_after}); slot-based capacity is the real
		 * constraint (MAX_MESSAGES), so byte-based available_kb would
		 * be misleading and is deliberately omitted. Encoded size:
		 * map hdr 1 + "reason" 7 + "storage_full" 13 + "retry_after"
		 * 12 + 3600 as 0x19 xx xx 3 = 36 bytes. */
		ZCBOR_STATE_E(zs, 1, body, sizeof(body), 0);
		if (!zcbor_map_start_encode(zs, 2) ||
		    !zcbor_tstr_put_lit(zs, "reason") ||
		    !zcbor_tstr_put_lit(zs, "storage_full") ||
		    !zcbor_tstr_put_lit(zs, "retry_after") ||
		    !zcbor_uint32_put(zs, 3600U)) {
			body_len = 0;
		} else {
			body_len = (size_t)(zs->payload - body);
		}
	}
	k_mutex_unlock(&s_dtn_buf_mutex);
	if (!ok) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE,
						    COAP_CONTENT_FORMAT_APP_CBOR,
						    body, body_len);
	}
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CHANGED,
					    0, NULL, 0);
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

/* Spec 18.10: confessions are RAM-only (no-log guarantee), FIFO evicted,
 * 768 B max each, 2 KB leaf budget. */
#define CONFESSIONS_MAX_SIZE 768U
#define CONFESSIONS_SLOTS 2U
#define CONFESSIONS_RATE_WINDOW_MS 30000U
#define CONFESSIONS_HOURLY_WINDOW_MS 3600000U
#define CONFESSIONS_HOURLY_LIMIT 12U

static K_MUTEX_DEFINE(s_confessions_mutex);
static uint8_t s_confessions[CONFESSIONS_SLOTS][CONFESSIONS_MAX_SIZE];
static size_t s_confessions_len[CONFESSIONS_SLOTS];
static uint32_t s_confessions_at[CONFESSIONS_SLOTS];
static size_t s_confessions_head;
static size_t s_confessions_count;
static uint8_t s_conf_hourly_count[256] = {0};
static uint32_t s_conf_hourly_start[256] = {0};

static int confessions_get(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t buf[2048]; /* 2KB leaf budget (18.10.3) + SenML overhead */
	struct senml_pack out;
	uint32_t now = 0U;
	size_t count;
	size_t start;
	int64_t since = -1;
	size_t skipped = 0U;

	/* ?count=N and ?since=T query params (18.10.7). */
	struct coap_option qopts[2];
	int qcnt = coap_find_options(request, COAP_OPTION_URI_QUERY, qopts, 2);
	for (int i = 0; i < qcnt; i++) {
		if (qopts[i].len > 6 &&
		    memcmp(qopts[i].value, "count=", 6) == 0) {
			count = 0U;
			for (size_t d = 6; d < qopts[i].len; d++) {
				if (qopts[i].value[d] < '0' ||
				    qopts[i].value[d] > '9') {
					return lichen_coap_respond(
					    resource, request, addr, addr_len,
					    COAP_RESPONSE_CODE_BAD_REQUEST, 0,
					    NULL, 0);
				}
				count = count * 10U +
					(size_t)(qopts[i].value[d] - '0');
			}
		} else if (qopts[i].len > 6 &&
			   memcmp(qopts[i].value, "since=", 6) == 0) {
			int64_t parsed = 0;
			for (size_t d = 6; d < qopts[i].len; d++) {
				if (qopts[i].value[d] < '0' ||
				    qopts[i].value[d] > '9') {
					return lichen_coap_respond(
					    resource, request, addr, addr_len,
					    COAP_RESPONSE_CODE_BAD_REQUEST, 0,
					    NULL, 0);
				}
				parsed =
					parsed * 10 +
					(int64_t)(qopts[i].value[d] - '0');
			}
			since = parsed;
		}
	}

	/* No valid wall clock -> base_time 0 omits bt instead of
	 * synthesizing a timestamp from uptime. */
	(void)dtn_wall_clock(&now);
	k_mutex_lock(&s_confessions_mutex, K_FOREVER);
	if (s_confessions_count > 0U) {
		/* ?since=T: skip records with time <= T (uptime-based;
		 * meaningful only for clock-valid nodes). */
		while (skipped < s_confessions_count &&
		       since >= 0 &&
		       (int64_t)s_confessions_at[
			   (s_confessions_head + skipped) %
			   CONFESSIONS_SLOTS] <= since) {
			skipped++;
		}
	}
	start = (s_confessions_head + skipped) % CONFESSIONS_SLOTS;
	count = MIN(CONFESSIONS_SLOTS, s_confessions_count - skipped);
	k_mutex_lock(&s_senml_pack_mutex, K_FOREVER);
	senml_pack_init(&out, NULL, now);
	for (size_t i = 0U; i < count; i++) {
		size_t idx = (start + i) % CONFESSIONS_SLOTS;
		/* vd field: the ring buffer itself is the stable storage for
		 * the record lifetime (SenML data cap 1536 >= 768). */
		int r = senml_add_data(&out, SENML_KEY_CONFESSIONS,
				       s_confessions[idx],
				       s_confessions_len[idx]);
		if (r < 0) {
			k_mutex_unlock(&s_senml_pack_mutex);
			k_mutex_unlock(&s_confessions_mutex);
			return lichen_coap_respond(resource, request, addr,
						   addr_len,
						   COAP_RESPONSE_CODE_INTERNAL_ERROR,
						   0, NULL, 0);
		}
	}
	int len = senml_encode_cbor(&out, buf, sizeof(buf));
	k_mutex_unlock(&s_senml_pack_mutex);
	k_mutex_unlock(&s_confessions_mutex);
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
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = 0;
	struct oscore_ctx *oscore_ctx = NULL;
	const uint8_t *payload = NULL;
	uint16_t payload_len = 0;
	bool is_protected = false;
	/* Spec 18.10.5: OSCORE is OPTIONAL for confessions (anonymous
	 * postings) — provide a plain buffer so unprotected POSTs carrying
	 * a payload are accepted. */
	uint8_t confessions_plain_buf[CONFESSIONS_MAX_SIZE];
	int ret = coap_oscore_authorize_mutating(resource, request, addr,
						 addr_len, COAP_METHOD_POST,
						 confessions_plain_buf,
						 sizeof(confessions_plain_buf),
						 &payload, &payload_len,
						 &oscore_ctx, piv, &piv_len,
						 &is_protected);
	if (ret != 0) return ret;
	if (payload == NULL || payload_len == 0) {
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_BAD_REQUEST);
	}
	if (payload_len > CONFESSIONS_MAX_SIZE) {
		/* Spec 18.10.3: max confession size 768 B. */
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_REQUEST_TOO_LARGE);
	}
	uint32_t now_ms = k_uptime_get_32();
	uint8_t iid7 = peer_eui64[7];
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	/* 18.10.3: 1 POST per node per 30 s (uptime-based). */
	if (s_last_confession[iid7] &&
	    (now_ms - s_last_confession[iid7] <
	     CONFESSIONS_RATE_WINDOW_MS)) {
		k_mutex_unlock(&s_rate_mutex);
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_TOO_MANY_REQUESTS);
	}
	/* 18.10.3: 12 POSTs per node per hour. */
	if (now_ms - s_conf_hourly_start[iid7] >=
	    CONFESSIONS_HOURLY_WINDOW_MS) {
		s_conf_hourly_start[iid7] = now_ms;
		s_conf_hourly_count[iid7] = 0U;
	}
	if (s_conf_hourly_count[iid7] >= CONFESSIONS_HOURLY_LIMIT) {
		k_mutex_unlock(&s_rate_mutex);
		return coap_oscore_send_protected(resource, request, addr,
						  addr_len, oscore_ctx, piv,
						  piv_len,
						  COAP_RESPONSE_CODE_TOO_MANY_REQUESTS);
	}
	s_conf_hourly_count[iid7]++;
	s_last_confession[iid7] = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	/* 18.10.3/18.10.4: FIFO eviction into the RAM-only ring. */
	k_mutex_lock(&s_confessions_mutex, K_FOREVER);
	size_t slot = s_confessions_count < CONFESSIONS_SLOTS
			  ? (s_confessions_head + s_confessions_count) %
				CONFESSIONS_SLOTS
			  : s_confessions_head;
	if (s_confessions_count == CONFESSIONS_SLOTS) {
		s_confessions_head =
		    (s_confessions_head + 1U) % CONFESSIONS_SLOTS;
	} else {
		s_confessions_count++;
	}
	memcpy(s_confessions[slot], payload, payload_len);
	s_confessions_len[slot] = payload_len;
	s_confessions_at[slot] = now_ms;
	k_mutex_unlock(&s_confessions_mutex);
	return coap_oscore_send_protected(resource, request, addr, addr_len,
					  oscore_ctx, piv, piv_len,
					  COAP_RESPONSE_CODE_CHANGED);
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

/* Spec 18.9: GET /deaddrop/<id> retrieves one specific drop. The id is
 * matched against the SenML bn (base name) embedded in the stored payload. */
static int deaddrop_by_id_get(struct coap_resource *resource,
			      struct coap_packet *request,
			      struct sockaddr *addr, socklen_t addr_len)
{
	if (s_provider == NULL || s_provider->retrieve == NULL) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}
	char id[LICHEN_DEADDROP_ID_MAX + 1U] = {0};
	struct coap_option paths[4];
	int pcount = coap_find_options(request, COAP_OPTION_URI_PATH, paths, 4);
	for (int i = 0; i < pcount; i++) {
		if (paths[i].len > 0U && paths[i].len <= LICHEN_DEADDROP_ID_MAX &&
		    memcmp(paths[i].value, "deaddrop", 8U) != 0) {
			size_t copy = MIN(paths[i].len, LICHEN_DEADDROP_ID_MAX);
			memcpy(id, paths[i].value, copy);
			id[copy] = '\0';
			break;
		}
	}
	if (id[0] == '\0') {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	uint8_t buf[256];
	int len = s_provider->retrieve(buf, sizeof(buf), id);
	k_mutex_unlock(&s_dtn_buf_mutex);
	if (len <= 0) {
		/* Spec 18.9: 4.04 conceals existence for private drops. */
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT,
			    SENML_CBOR_CONTENT_FORMAT, buf, (size_t)len);
}

static const char *const deaddrop_path[] = { "deaddrop", NULL };
COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap_server, {
	.get = deaddrop_get,
	.post = deaddrop_post,
	.path = deaddrop_path,
});

/* Spec 18.9: GET /deaddrop/<id> for a specific drop. The id is the drop id
 * returned in the POST Location-Path. The '+' is a single-level URI
 * wildcard (CONFIG_COAP_URI_WILDCARD, selected by LICHEN_COAP_DEADDROP);
 * the handler extracts the concrete id from the request options. */
static const char *const deaddrop_by_id_path[] = { "deaddrop", "+", NULL };
COAP_RESOURCE_DEFINE(lichen_deaddrop_by_id, lichen_coap_server, {
	.get = deaddrop_by_id_get,
	.path = deaddrop_by_id_path,
});

static const char *const confessions_path[] = { "confessions", NULL };
COAP_RESOURCE_DEFINE(lichen_confessions, lichen_coap_server, {
	.get = confessions_get,
	.post = confessions_post,
	.path = confessions_path,
});
