/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file zephyr/kernel.h
 * @brief Host-test stub for coap_slot_coord builds
 *
 * Provides just enough of the Zephyr kernel API for coap_slot_coord.c:
 * the coord mutex, the __weak linkage macro, and the wall-clock hook the
 * resource handler uses. Never linked against Zephyr objects.
 */

#ifndef ZEPHYR_HOST_TEST_SLOT_CLAIM_KERNEL_H_
#define ZEPHYR_HOST_TEST_SLOT_CLAIM_KERNEL_H_

#include <stdint.h>

#ifndef LICHEN_SLOT_CLAIM_TEST
#error "Host-test zephyr/kernel.h stub is only for LICHEN_SLOT_CLAIM_TEST builds"
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#define K_FOREVER (-1)

struct k_mutex {
	uint32_t lock_word;
};

#define K_MUTEX_DEFINE(name) struct k_mutex name

static inline int k_mutex_lock(struct k_mutex *mutex, int timeout)
{
	(void)mutex;
	(void)timeout;
	return 0;
}

static inline int k_mutex_unlock(struct k_mutex *mutex)
{
	(void)mutex;
	return 0;
}

#endif /* ZEPHYR_HOST_TEST_SLOT_CLAIM_KERNEL_H_ */
