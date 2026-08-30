/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TEST_ZEPHYR_KERNEL_H_
#define TEST_ZEPHYR_KERNEL_H_

/* Host tests are single-threaded: mutexes are no-ops. This also makes the
 * module's recursive lock path (cache_load_locked holds s_lock while the
 * settings handler re-locks, mirroring Zephyr's recursive k_mutex)
 * deadlock-free under the stub. */

struct k_mutex {
	int unused;
};

#define K_FOREVER 0
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

#endif
