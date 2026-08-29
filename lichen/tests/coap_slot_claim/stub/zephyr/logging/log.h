/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file zephyr/logging/log.h
 * @brief Host-test stub: logging macros compile out
 */

#ifndef ZEPHYR_HOST_TEST_SLOT_CLAIM_LOG_H_
#define ZEPHYR_HOST_TEST_SLOT_CLAIM_LOG_H_

#define LOG_LEVEL 0

#define LOG_MODULE_REGISTER(...)
#define LOG_DBG(...)      do { } while (0)
#define LOG_INF(...)      do { } while (0)
#define LOG_WRN(...)      do { } while (0)
#define LOG_ERR(...)      do { } while (0)

#endif /* ZEPHYR_HOST_TEST_SLOT_CLAIM_LOG_H_ */
