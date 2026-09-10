/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <string.h>
#include <zephyr/ztest.h>
#include <lichen/coap_server.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_keys.h>

extern struct coap_resource lichen_msg_inbox;
extern const struct coap_service lichen_coap_server;

/* This suite deliberately keeps the optional key store disabled. */
bool lichen_coap_is_local_admin(const struct sockaddr *addr, socklen_t addr_len)
{
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	return false;
}

int lichen_key_store_get(const uint8_t iid[LICHEN_KEY_IID_LEN],
	struct lichen_key_entry *entry)
{
	ARG_UNUSED(iid);
	ARG_UNUSED(entry);
	return -ENOENT;
}

int __real_coap_service_start(const struct coap_service *service);
int __wrap_coap_service_start(const struct coap_service *service);
int __wrap_coap_service_start(const struct coap_service *service)
{
	/* Register real application callbacks without starting a dispatch thread;
	 * the tests invoke the real resource's post function directly. */
	return service == &lichen_coap_server ? 0 : __real_coap_service_start(service);
}

static uint8_t sent_packet[CONFIG_COAP_SERVER_MESSAGE_SIZE];
static size_t sent_len;
static unsigned sends;
static unsigned callback_calls;
static bool invalidate_in_callback;
static struct oscore_ctx *ctx;

int __real_coap_resource_send(const struct coap_resource *resource,
	const struct coap_packet *packet, const struct sockaddr *addr,
	socklen_t addr_len, const struct coap_transmission_parameters *params);
int __wrap_coap_resource_send(const struct coap_resource *resource,
	const struct coap_packet *packet, const struct sockaddr *addr,
	socklen_t addr_len, const struct coap_transmission_parameters *params);
int __wrap_coap_resource_send(const struct coap_resource *resource,
	const struct coap_packet *packet, const struct sockaddr *addr,
	socklen_t addr_len, const struct coap_transmission_parameters *params)
{
	if (resource != &lichen_msg_inbox) {
		return __real_coap_resource_send(resource, packet, addr, addr_len, params);
	}
	sends++;
	sent_len = packet->offset;
	zassert_true(sent_len <= sizeof(sent_packet));
	memcpy(sent_packet, packet->data, sent_len);
	return 0;
}

static int deliver_message(const uint8_t *payload, size_t len, uint32_t *msg_id)
{
	static const char expected[] = "{\"message\":\"test\"}";
	callback_calls++;
	zassert_equal(len, sizeof(expected) - 1);
	zassert_mem_equal(payload, expected, len);
	*msg_id = 42;
	if (invalidate_in_callback) {
		oscore_ctx_free(ctx);
		ctx = NULL;
	}
	return 0;
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	/* Independent Python/Rust fixture: oscore_cross_exchange.json,
	 * roundtrip_request_with_payload, sender aa, recipient bb, sequence 42. */
	const uint8_t secret[16] = {
		0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
		0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	};
	const uint8_t salt[8] = {0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
	const uint8_t peer[8] = {2, 0, 0, 0, 0, 0, 0, 1};
	const struct lichen_coap_server_handlers handlers = {.msg_post = deliver_message};
	sends = 0;
	sent_len = 0;
	callback_calls = 0;
	invalidate_in_callback = false;
	zassert_ok(oscore_init());
	zassert_ok(oscore_ctx_create_with_eui64(secret, salt, sizeof(salt),
		(uint8_t[]){0xbb}, 1, (uint8_t[]){0xaa}, 1, peer, &ctx));
	zassert_ok(lichen_coap_server_init(&handlers));
}

static void after(void *fixture)
{
	ARG_UNUSED(fixture);
	oscore_ctx_free(ctx);
	ctx = NULL;
	zassert_ok(lichen_coap_server_init(NULL));
}

static int post(void)
{
	const uint8_t ciphertext[] = {
		0xf9, 0xad, 0xeb, 0x44, 0x45, 0x10, 0x48, 0xd5,
		0x3a, 0xed, 0x05, 0x6c, 0x45, 0x40, 0x8e, 0xc3,
		0xa9, 0x1c, 0xf3, 0x89, 0xdf, 0xf9, 0x26, 0x92,
		0xe8, 0xc8, 0xe2, 0xec,
	};
	uint8_t wire[64];
	struct coap_packet request;
	struct coap_option options[4];
	struct sockaddr_in6 source = {.sin6_family = AF_INET6};
	source.sin6_addr.s6_addr[0] = 0xfe;
	source.sin6_addr.s6_addr[1] = 0x80;
	source.sin6_addr.s6_addr[15] = 1;
	zassert_ok(coap_packet_init(&request, wire, sizeof(wire), 1,
		COAP_TYPE_CON, 1, (uint8_t[]){0x31}, COAP_METHOD_POST, 123));
	zassert_ok(coap_packet_append_option(&request, COAP_OPTION_OSCORE,
		(uint8_t[]){9, 42, 0xaa}, 3));
	zassert_ok(coap_packet_append_payload_marker(&request));
	zassert_ok(coap_packet_append_payload(&request, ciphertext, sizeof(ciphertext)));
	zassert_ok(coap_packet_parse(&request, wire, request.offset, options, ARRAY_SIZE(options)));
	return lichen_msg_inbox.post(&lichen_msg_inbox, &request,
		(struct sockaddr *)&source, sizeof(source));
}

ZTEST_SUITE(inbox_lifetime, NULL, NULL, before, after, NULL);

ZTEST(inbox_lifetime, test_callback_invalidation_never_sends_plaintext)
{
	invalidate_in_callback = true;
	int ret = post();
	zassert_equal(ret, OSCORE_ERR_CONTEXT_STALE, "ret=%d sends=%u", ret, sends);
	zassert_equal(callback_calls, 1);
	zassert_equal(sends, 0, "stale context must not emit even an error response");
}

ZTEST(inbox_lifetime, test_normal_callback_sends_protected_created)
{
	/* Independently computed with pyca/cryptography HKDF-SHA256/AESCCM,
	 * tag_length=8. Same context as the cross-implementation request above:
	 * key info=8541bbf60a634b657910, IV info=8540f60a6249560d,
	 * AAD=8368456e63727970743040498501810a41aa412a40, plaintext=41.
	 * The independent calculation also reproduced the request fixture exactly. */
	const uint8_t expected[] = {0x86, 0x25, 0xb1, 0xb4, 0x4d, 0xea, 0x4e, 0xca, 0x4a};
	struct coap_packet response;
	struct coap_option options[8], oscore;
	uint16_t payload_len;
	zassert_ok(post());
	zassert_equal(callback_calls, 1);
	zassert_equal(sends, 1, "sends=%u", sends);
	zassert_ok(coap_packet_parse(&response, sent_packet, sent_len, options, ARRAY_SIZE(options)));
	zassert_equal(coap_find_options(&response, COAP_OPTION_OSCORE, &oscore, 1), 1);
	const uint8_t *payload = coap_packet_get_payload(&response, &payload_len);
	zassert_equal(payload_len, sizeof(expected));
	zassert_mem_equal(payload, expected, sizeof(expected));
	struct coap_option location[3];
	zassert_equal(coap_find_options(&response, COAP_OPTION_LOCATION_PATH, location, 3), 3);
	zassert_equal(location[2].len, 2);
	zassert_mem_equal(location[2].value, "42", 2);
}
