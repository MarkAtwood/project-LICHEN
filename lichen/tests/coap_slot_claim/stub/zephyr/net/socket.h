/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Host-test stub: socklen_t for LICHEN header prototypes (see net/coap.h
 * stub: strict-ANSI C hides the platform typedef). */
#ifndef ZEPHYR_HOST_TEST_SLOT_CLAIM_SOCKET_H_
#define ZEPHYR_HOST_TEST_SLOT_CLAIM_SOCKET_H_

#include <stdint.h>

typedef uint32_t socklen_t;

#endif
