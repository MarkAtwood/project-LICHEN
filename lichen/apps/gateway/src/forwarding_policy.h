/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_FORWARDING_POLICY_H_
#define LICHEN_GATEWAY_FORWARDING_POLICY_H_

#include <stdbool.h>
#include <stdint.h>

bool lichen_forwarding_ipv6_policy_allows(const uint8_t header[40]);

#endif
