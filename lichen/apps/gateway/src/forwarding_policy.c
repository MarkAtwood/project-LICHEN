/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "forwarding_policy.h"

#include <string.h>

static bool ipv6_endpoint_is_unspecified(const uint8_t addr[16])
{
	static const uint8_t unspecified[16];

	return memcmp(addr, unspecified, sizeof(unspecified)) == 0;
}

static bool ipv6_endpoint_is_loopback(const uint8_t addr[16])
{
	static const uint8_t loopback[16] = { [15] = 1 };

	return memcmp(addr, loopback, sizeof(loopback)) == 0;
}

static bool ipv6_endpoint_is_ipv4_mapped(const uint8_t addr[16])
{
	static const uint8_t prefix[12] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
	};

	return memcmp(addr, prefix, sizeof(prefix)) == 0;
}

bool lichen_forwarding_ipv6_policy_allows(const uint8_t header[40])
{
	const uint8_t *src = &header[8];
	const uint8_t *dst = &header[24];

	if (ipv6_endpoint_is_unspecified(src) || ipv6_endpoint_is_loopback(src) ||
	    src[0] == 0xff || ipv6_endpoint_is_ipv4_mapped(src)) {
		return false;
	}

	if (ipv6_endpoint_is_unspecified(dst) || ipv6_endpoint_is_loopback(dst) ||
	    ipv6_endpoint_is_ipv4_mapped(dst)) {
		return false;
	}

	if (dst[0] == 0xff && ((dst[1] & 0x0fU) < 2U ||
				       (dst[1] & 0x0fU) > 14U)) {
		return false;
	}

	return true;
}
