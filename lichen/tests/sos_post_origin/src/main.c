/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: The contributors to the LICHEN project
 *
 * bead project-LICHEN-worker6-117r: vector-driven accept/reject pair for
 * the sos_post origin-address path (coap_server.c). The sibling
 * coap_config_put_auth suite stubs sos_origin_verify and the AddrForKey
 * derivation, so nothing C-side pinned the transcript-address migration
 * to upstream AddrForKey(pubkey).
 *
 * Fixtures are golden: the CBOR alert, the pinned pubkey, and both
 * Schnorr48 signatures were generated ONCE by the Python reference
 * (lichen.crypto.identity.yggdrasil_address + lichen.crypto.schnorr48.sign,
 * independent oracle per test-vector discipline), over
 *   SHA-512("LICHEN-SOS-ORIGIN-v1" || origin_ipv6 || seq_be || cbor).
 * ACCEPT signs with origin_ipv6 = AddrForKey(pubkey) and must reach 2.04
 * CHANGED; REJECT signs with the legacy synthesized 0x02||0*7||iid form
 * and must be silently dropped. A C regression to the legacy transcript
 * inverts both outcomes, so the pair catches it.
 *
 * Real modules are linked end to end (sos_origin.c, sos_alert.c,
 * sos_ratelimit.c, schnorr48.c, identity_addr.c, monocypher); only the
 * key store and the unrelated coap_server.c dependencies are stubbed.
 * Responses are captured at coap_resource_send (--wrap), same approach
 * as lichen/tests/coap_config_put_auth.
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

/* Resource under test (COAP_RESOURCE_DEFINE in coap_server.c). */
extern struct coap_resource lichen_sos;

/* ------------------------------------------------------------------ */
/* Golden fixtures (python oracle; see file header)                    */
/* ------------------------------------------------------------------ */

static const uint8_t fixture_pubkey[32] = {
	0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24,
	0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab, 0x6c,
	0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00,
	0x97, 0x96, 0x0e, 0x06, 0x98, 0x81, 0xdb, 0x12,
};

/* AddrForKey(fixture_pubkey) = 0202:f568:3973:2437:16dd:d66d:e8f5:068a
 * Alert CBOR: {"type":"sos","node":"0202:...:068a","ts":1716742800,"seq":1} */
static const uint8_t fixture_cbor[] = {
	0xa4, 0x64, 0x74, 0x79, 0x70, 0x65, 0x63, 0x73,
	0x6f, 0x73, 0x64, 0x6e, 0x6f, 0x64, 0x65, 0x78,
	0x27, 0x30, 0x32, 0x30, 0x32, 0x3a, 0x66, 0x35,
	0x36, 0x38, 0x3a, 0x33, 0x39, 0x37, 0x33, 0x3a,
	0x32, 0x34, 0x33, 0x37, 0x3a, 0x31, 0x36, 0x64,
	0x64, 0x3a, 0x64, 0x36, 0x36, 0x64, 0x3a, 0x65,
	0x38, 0x66, 0x35, 0x3a, 0x30, 0x36, 0x38, 0x61,
	0x62, 0x74, 0x73, 0x1a, 0x66, 0x53, 0x6a, 0x90,
	0x63, 0x73, 0x65, 0x71, 0x01,
};

#define FIXTURE_SEQ 1ULL

/* Signature over the AddrForKey transcript (must be accepted). */
static const uint8_t fixture_sig_accept[48] = {
	0x4c, 0x50, 0xe2, 0x08, 0x72, 0x4f, 0x73, 0xa4,
	0x30, 0x33, 0xa1, 0xd6, 0x5d, 0xfd, 0x78, 0xe7,
	0xf6, 0xdd, 0x89, 0xdd, 0x49, 0x9b, 0xcb, 0x52,
	0xf4, 0xa3, 0x52, 0xa2, 0x81, 0x44, 0x58, 0xed,
	0xa7, 0x8a, 0x46, 0x29, 0x4a, 0x66, 0x8a, 0x63,
	0x31, 0x15, 0xba, 0xd0, 0x44, 0xa5, 0x4e, 0x09,
};

/* Reject fixture: same alert shape with the inner seq bumped to 2, and a
 * trailer Origin Sequence of 2. The distinct trailer seq keeps the reject
 * arm load-bearing against the accept arm's committed gate state: with
 * last_seq=1 already committed for this origin, a frame carrying seq=2
 * passes the monotonic gate, so a verify-skipping regression in
 * coap_server.c would emit a response and fail this test instead of
 * being masked by the gate (security review pass 2, finding 1). */
#define FIXTURE_REJECT_SEQ 2ULL

static const uint8_t fixture_cbor_reject[] = {
	0xa4, 0x64, 0x74, 0x79, 0x70, 0x65, 0x63, 0x73,
	0x6f, 0x73, 0x64, 0x6e, 0x6f, 0x64, 0x65, 0x78,
	0x27, 0x30, 0x32, 0x30, 0x32, 0x3a, 0x66, 0x35,
	0x36, 0x38, 0x3a, 0x33, 0x39, 0x37, 0x33, 0x3a,
	0x32, 0x34, 0x33, 0x37, 0x3a, 0x31, 0x36, 0x64,
	0x64, 0x3a, 0x64, 0x36, 0x36, 0x64, 0x3a, 0x65,
	0x38, 0x66, 0x35, 0x3a, 0x30, 0x36, 0x38, 0x61,
	0x62, 0x74, 0x73, 0x1a, 0x66, 0x53, 0x6a, 0x90,
	0x63, 0x73, 0x65, 0x71, 0x02,
};

/* Same signer/alert but the transcript origin is the legacy synthesized
 * 0x02||0*7||iid address (must be rejected: silent drop). */
static const uint8_t fixture_sig_legacy[48] = {
	0x14, 0xc1, 0xe5, 0x72, 0xe9, 0x0a, 0xe9, 0xec,
	0x13, 0x7d, 0x72, 0xb7, 0x37, 0xac, 0x66, 0xf9,
	0xe8, 0xd0, 0x55, 0x36, 0xe7, 0x6a, 0xe9, 0x55,
	0x9a, 0x16, 0x49, 0x53, 0xed, 0x3c, 0xd1, 0x56,
	0x3e, 0xa9, 0x17, 0x5f, 0x05, 0xee, 0x78, 0x82,
	0x65, 0x3e, 0x29, 0x28, 0x4c, 0x4c, 0xef, 0x05,
};

/* ------------------------------------------------------------------ */
/* Captured responses                                                  */
/* ------------------------------------------------------------------ */

static struct {
	unsigned int calls;
	uint8_t code;
} captured;

int __wrap_coap_resource_send(
	const struct coap_resource *resource, const struct coap_packet *packet,
	const struct sockaddr *addr, socklen_t addr_len,
	const struct coap_transmission_parameters *params)
{
	ARG_UNUSED(resource);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	ARG_UNUSED(params);

	captured.calls++;
	captured.code = coap_header_get_code(packet);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Stubs for symbols coap_server.c references from unlinked modules    */
/* ------------------------------------------------------------------ */

/* One pinned key: the fixture identity. sos_post scans the store and
 * accepts the origin only when the alert's node string equals the pinned
 * key's own AddrForKey (real derivation in identity_addr.c is linked). */
size_t lichen_key_store_list(struct lichen_key_entry *entries,
			     size_t max_entries)
{
	if (max_entries < 1U) {
		return 0U;
	}
	memset(&entries[0], 0, sizeof(entries[0]));
	memcpy(entries[0].pubkey, fixture_pubkey, sizeof(fixture_pubkey));
	entries[0].trust = LICHEN_KEY_TRUST_TOFU;
	entries[0].valid = true;
	return 1U;
}

uint8_t lichen_tunnel_auth_coap_code(uint16_t coap_code)
{
	ARG_UNUSED(coap_code);
	return 0U;
}

bool lichen_coap_is_local_admin(const struct sockaddr *addr, socklen_t addr_len)
{
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	return false;
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
	ARG_UNUSED(code);
	return 0;
}

int coap_oscore_authorize_mutating(struct coap_resource *resource,
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
	*payload_out = coap_packet_get_payload(request, payload_len_out);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Request plumbing                                                    */
/* ------------------------------------------------------------------ */

static void init_sos_post(struct coap_packet *request, uint8_t *buf,
			  size_t buf_size, const uint8_t *cbor, size_t cbor_len,
			  uint64_t origin_seq, const uint8_t *sig)
{
	uint8_t seq_be[8];

	for (int i = 7; i >= 0; i--) {
		seq_be[7 - i] = (uint8_t)(origin_seq >> (8 * i));
	}

	zassert_ok(coap_packet_init(request, buf, (uint16_t)buf_size,
				    COAP_VERSION_1, COAP_TYPE_CON, 0U, NULL,
				    COAP_METHOD_POST, 0x1234U));
	zassert_ok(coap_packet_append_payload_marker(request));
	zassert_ok(coap_packet_append_payload(request, cbor,
					      (uint16_t)cbor_len));
	zassert_ok(coap_packet_append_payload(request, seq_be,
					      (uint16_t)sizeof(seq_be)));
	zassert_ok(coap_packet_append_payload(request, sig, 48U));
	/* Handlers receive parsed datagrams, whose max_len is the received
	 * length; coap_packet_init keeps the output buffer capacity. */
	request->max_len = request->offset;
}

static void init_global_addr(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_port = htons(5683U);
	addr->sin6_addr.s6_addr[0] = 0x20U;
	addr->sin6_addr.s6_addr[1] = 0x01U;
	addr->sin6_addr.s6_addr[2] = 0x0dU;
	addr->sin6_addr.s6_addr[3] = 0xb8U;
	addr->sin6_addr.s6_addr[15] = 0x01U;
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);

	memset(&captured, 0, sizeof(captured));
	/* No server handlers needed: sos_post consults only the key store,
	 * the origin table, and the rate limiter. */
	(void)lichen_coap_server_init(NULL);
}

ZTEST_SUITE(sos_post_origin, NULL, NULL, before, NULL, NULL);

/* ACCEPT: pinned key + signature over the AddrForKey(pubkey) transcript
 * must traverse the full path (CBOR parse, node-string resolution,
 * pinned-key AddrForKey scan, Schnorr48 verify, seq gate, rate limit) to
 * a 2.04 CHANGED; an identical replay must then hit the monotonic
 * Origin-Sequence gate and be silently dropped. */
ZTEST(sos_post_origin, test_addrforkey_transcript_accepted_then_replay_dropped)
{
	struct coap_packet request;
	struct sockaddr_in6 addr;
	uint8_t request_buf[512];
	int ret;

	init_sos_post(&request, request_buf, sizeof(request_buf),
		      fixture_cbor, sizeof(fixture_cbor), FIXTURE_SEQ,
		      fixture_sig_accept);
	init_global_addr(&addr);

	ret = lichen_sos.post(&lichen_sos, &request, (struct sockaddr *)&addr,
			      sizeof(addr));

	zassert_ok(ret, "valid SOS POST must be handled, got %d", ret);
	zassert_equal(captured.calls, 1U,
		      "accepted SOS must answer through coap_resource_send");
	zassert_equal(captured.code, COAP_RESPONSE_CODE_CHANGED,
		      "accepted SOS must get 2.04, got 0x%02x", captured.code);

	/* Same bytes again: replay must be dropped silently (no response). */
	init_sos_post(&request, request_buf, sizeof(request_buf),
		      fixture_cbor, sizeof(fixture_cbor), FIXTURE_SEQ,
		      fixture_sig_accept);
	ret = lichen_sos.post(&lichen_sos, &request, (struct sockaddr *)&addr,
			      sizeof(addr));

	zassert_equal(ret, -ENOENT, "replay must be dropped, got %d", ret);
	zassert_equal(captured.calls, 1U,
		      "silent drop must not emit a second response");
}

/* REJECT: identical frame, but the signature covers the legacy
 * synthesized 0x02||0*7||iid transcript address. The pinned key still
 * resolves (node string unchanged), so only the transcript address can
 * fail verification — the handler must silently drop. A C regression to
 * the legacy transcript would ACCEPT this frame, failing the test. */
ZTEST(sos_post_origin, test_legacy_transcript_signature_silently_dropped)
{
	struct coap_packet request;
	struct sockaddr_in6 addr;
	uint8_t request_buf[512];
	int ret;

	init_sos_post(&request, request_buf, sizeof(request_buf),
		      fixture_cbor_reject, sizeof(fixture_cbor_reject),
		      FIXTURE_REJECT_SEQ, fixture_sig_legacy);
	init_global_addr(&addr);

	ret = lichen_sos.post(&lichen_sos, &request, (struct sockaddr *)&addr,
			      sizeof(addr));

	zassert_equal(ret, -ENOENT,
		      "legacy-transcript signature must be dropped, got %d", ret);
	zassert_equal(captured.calls, 0U,
		      "silent drop must not emit any response");
}
