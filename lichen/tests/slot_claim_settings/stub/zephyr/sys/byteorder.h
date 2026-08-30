/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TEST_ZEPHYR_BYTEORDER_H_
#define TEST_ZEPHYR_BYTEORDER_H_

#include <stdint.h>

static inline uint32_t sys_get_le32(const uint8_t src[4])
{
	return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static inline void sys_put_le32(uint32_t v, uint8_t dst[4])
{
	dst[0] = (uint8_t)(v & 0xFFU);
	dst[1] = (uint8_t)((v >> 8) & 0xFFU);
	dst[2] = (uint8_t)((v >> 16) & 0xFFU);
	dst[3] = (uint8_t)((v >> 24) & 0xFFU);
}

#endif
