/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file zephyr/sys/byteorder.h
 * @brief Minimal host-test stub for <zephyr/sys/byteorder.h>
 *
 * Provides the big-endian accessors used by the RPL message codec on the
 * host. Guarded so it can only leak into LICHEN_RPL_TEST builds.
 */

#ifndef ZEPHYR_HOST_TEST_BYTEORDER_H_
#define ZEPHYR_HOST_TEST_BYTEORDER_H_

#include <stdint.h>

#ifndef LICHEN_RPL_TEST
#error "Host-test byteorder stub is only for LICHEN_RPL_TEST builds"
#endif

static inline uint16_t sys_get_be16(const uint8_t src[2])
{
	return (uint16_t)((uint16_t)src[0] << 8 | src[1]);
}

static inline void sys_put_be16(uint16_t val, uint8_t dst[2])
{
	dst[0] = (uint8_t)(val >> 8);
	dst[1] = (uint8_t)val;
}

static inline uint32_t sys_get_be32(const uint8_t src[4])
{
	return (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 |
	       (uint32_t)src[2] << 8 | src[3];
}

static inline void sys_put_be32(uint32_t val, uint8_t dst[4])
{
	dst[0] = (uint8_t)(val >> 24);
	dst[1] = (uint8_t)(val >> 16);
	dst[2] = (uint8_t)(val >> 8);
	dst[3] = (uint8_t)val;
}

#endif /* ZEPHYR_HOST_TEST_BYTEORDER_H_ */
