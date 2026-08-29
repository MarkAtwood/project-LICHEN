/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Host-test stub: opaque CoAP types for LICHEN header prototypes. The
 * resource handlers themselves are compiled out (no CONFIG_
 * LICHEN_COAP_SLOT_COORD_RESOURCE). */
#ifndef ZEPHYR_HOST_TEST_SLOT_CLAIM_COAP_H_
#define ZEPHYR_HOST_TEST_SLOT_CLAIM_COAP_H_

#include <stdint.h>

/* -std=c23 is strict-ANSI: macOS sys/types.h hides socklen_t */
typedef uint32_t socklen_t;

struct coap_resource;
struct coap_packet;
struct coap_core_metadata;

#endif
