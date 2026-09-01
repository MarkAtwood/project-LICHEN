/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_diag.c
 * @brief Hardware diagnostics event ring (spec 18.x LCI diagnostics).
 *
 * Ring buffer of diagnostic events callable from any subsystem. Events are
 * printed human-readable over the console on report and served as a CBOR
 * array on GET /diag.
 */

#include <lichen/diag.h>

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/sys/printk.h>
#include <zephyr/init.h>
#include <zcbor_encode.h>

#define DIAG_CAPACITY CONFIG_LICHEN_DIAG_CAPACITY

static struct lichen_diag_event s_ring[DIAG_CAPACITY];
static size_t s_head;   /* next write index */
static size_t s_count;  /* events retained (<= DIAG_CAPACITY) */
static bool s_initialized;

static const char *const subsystem_names[LICHEN_DIAG_SUB_COUNT] = {
	"radio", "gps", "display", "power", "link", "coap", "sched", "other",
};

void lichen_diag_init(void)
{
	s_head = 0;
	s_count = 0;
	s_initialized = true;
}

void lichen_diag_report(enum lichen_diag_subsystem subsystem,
			uint16_t event_code, uint32_t detail,
			const char *message)
{
	if (!s_initialized || subsystem >= LICHEN_DIAG_SUB_COUNT) {
		return;
	}

	struct lichen_diag_event *slot = &s_ring[s_head];
	slot->timestamp_ms = k_uptime_get();
	slot->subsystem = (uint8_t)subsystem;
	slot->event_code = event_code;
	slot->detail = detail;
	if (message != NULL) {
		strncpy(slot->message, message, sizeof(slot->message) - 1U);
		slot->message[sizeof(slot->message) - 1U] = '\0';
	} else {
		slot->message[0] = '\0';
	}

	printk("DIAG [%s] code=%u detail=%u: %s\n",
	       subsystem_names[subsystem], event_code, detail,
	       slot->message);

	s_head = (s_head + 1U) % DIAG_CAPACITY;
	if (s_count < DIAG_CAPACITY) {
		s_count++;
	}
}

size_t lichen_diag_count(void)
{
	return s_count;
}

bool lichen_diag_get(size_t index, struct lichen_diag_event *out)
{
	if (!s_initialized || out == NULL || index >= s_count) {
		return false;
	}
	/* Oldest retained event lives at s_head - s_count (mod capacity). */
	size_t base = (s_head + DIAG_CAPACITY - s_count) % DIAG_CAPACITY;
	*out = s_ring[(base + index) % DIAG_CAPACITY];
	return true;
}

/* Wire init at boot: without this, s_initialized stays false and every
 * report no-ops (found by ldzz.3 review). */
SYS_INIT(lichen_diag_init, APPLICATION, 0);

/* CoAP GET /diag: CBOR array of recent events as maps. */
static int diag_get(struct coap_resource *resource,
		    struct coap_packet *request,
		    struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t body[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	size_t events = lichen_diag_count();
	bool ok;

	ZCBOR_STATE_E(zs, 2, body, sizeof(body), 0);
	ok = zcbor_list_start_encode(zs, events);
	for (size_t i = 0; ok && i < events; i++) {
		struct lichen_diag_event ev;
		if (!lichen_diag_get(i, &ev)) {
			ok = false;
			break;
		}
		ok = zcbor_map_start_encode(zs, 4) &&
		     zcbor_tstr_put_lit(zs, "ts") &&
		     zcbor_uint64_put(zs, ev.timestamp_ms) &&
		     zcbor_tstr_put_lit(zs, "sub") &&
		     zcbor_uint32_put(zs, ev.subsystem) &&
		     zcbor_tstr_put_lit(zs, "code") &&
		     zcbor_uint32_put(zs, ev.event_code) &&
	     zcbor_tstr_put_lit(zs, "detail") &&
	     zcbor_uint32_put(zs, ev.detail) &&
	     /* Exactly 4 pairs are encoded (ts/sub/code/detail); a count of
	      * 5 broke at end-encode. If "msg" is added, bump both to 5. */
	     zcbor_map_end_encode(zs, 4);
	}
	if (ok) {
		ok = zcbor_list_end_encode(zs, events);
	}
	if (!ok) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0,
					   NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   COAP_CONTENT_FORMAT_APP_CBOR, body,
				   (size_t)(zs->payload - body));
}

static const char *const diag_path[] = { "diag", NULL };
COAP_RESOURCE_DEFINE(lichen_diag, lichen_coap_server, {
	.get = diag_get,
	.path = diag_path,
});
