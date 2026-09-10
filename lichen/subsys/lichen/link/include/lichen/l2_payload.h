/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file l2_payload.h
 * @brief Authenticated L2 inner-payload dispatch constants.
 */

#ifndef LICHEN_L2_PAYLOAD_H_
#define LICHEN_L2_PAYLOAD_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_L2_DISPATCH_SCHC 0x14U
#define LICHEN_L2_DISPATCH_ROUTING 0x15U
/* SOS emergency alert (spec 02-physical-link.md §4.1, 12-apps.md §18.4.3):
 * carries the §18.4.2 CBOR alert map, NOT SCHC-compressed. Relays classify
 * SOS for the separate 3/hour SOS budget solely by this byte. */
#define LICHEN_L2_DISPATCH_SOS 0x16U
#define LICHEN_L2_ROUTING_TYPE_ANNOUNCE 0x01U

enum lichen_l2_payload_kind {
	LICHEN_L2_PAYLOAD_UNKNOWN = 0,
	LICHEN_L2_PAYLOAD_SCHC = 1,
	LICHEN_L2_PAYLOAD_ROUTING = 2,
	LICHEN_L2_PAYLOAD_SOS = 3,
};

static inline enum lichen_l2_payload_kind
lichen_l2_payload_classify(const uint8_t *_Nullable payload, size_t len)
{
	/* A defined dispatch always has at least one namespace body byte. */
	if (payload == NULL || len < 2U) {
		return LICHEN_L2_PAYLOAD_UNKNOWN;
	}
	if (payload[0] == LICHEN_L2_DISPATCH_SCHC) {
		return LICHEN_L2_PAYLOAD_SCHC;
	}
	if (payload[0] == LICHEN_L2_DISPATCH_ROUTING) {
		return LICHEN_L2_PAYLOAD_ROUTING;
	}
	if (payload[0] == LICHEN_L2_DISPATCH_SOS) {
		return LICHEN_L2_PAYLOAD_SOS;
	}
	return LICHEN_L2_PAYLOAD_UNKNOWN;
}

/**
 * Wrap a canonical SOS CBOR alert in its authenticated L2 namespace.
 *
 * Authentication and transmission are performed by the L2 sender; this
 * helper only constructs the dispatch-prefixed inner payload.
 */
static inline int
lichen_l2_wrap_sos_payload(const uint8_t *_Nullable cbor, size_t cbor_len,
			   uint8_t *_Nullable out, size_t out_len,
			   size_t *_Nullable written)
{
	if (written == NULL || out == NULL || cbor_len == 0U ||
	    (cbor == NULL && cbor_len != 0U) ||
	    cbor_len == SIZE_MAX || out_len < cbor_len + 1U) {
		return -1;
	}
	out[0] = LICHEN_L2_DISPATCH_SOS;
	if (cbor_len != 0U) {
		memcpy(&out[1], cbor, cbor_len);
	}
	*written = cbor_len + 1U;
	return 0;
}

static inline const uint8_t *_Nullable
lichen_l2_payload_body(const uint8_t *_Nullable payload, size_t len,
		       size_t *_Nullable body_len)
{
	if (body_len != NULL) {
		*body_len = (payload != NULL && len > 0U) ? len - 1U : 0U;
	}
	return (payload != NULL && len > 0U) ? &payload[1] : NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_L2_PAYLOAD_H_ */
