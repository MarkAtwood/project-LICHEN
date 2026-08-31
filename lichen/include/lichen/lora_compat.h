/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_LORA_COMPAT_H_
#define LICHEN_LORA_COMPAT_H_

/*
 * Zephyr 4.0 renamed the async LoRa receive contract: lora_recv_cb gained a
 * trailing `void *user_data` and lora_recv_async() a third parameter
 * (v3.7.0: 5-param cb / 2-arg call; v4.0+: 6-param cb / 3-arg call).  Both
 * generations are in fleet use - v3.7.0 is the documented CI pin, v4.1.0 is
 * what lichen/west.yml materializes - so drivers and the L2 RX path go
 * through these macros instead of spelling either form.
 *
 * Usage in a driver or callback owner:
 *   - callback definition:  append LORA_RECV_CB_EXTRA_ARGS to the parameter
 *     list and LORA_RECV_CB_UNUSED inside the body;
 *   - callback invocation:  append LORA_RECV_CB_PASS(user_data_var);
 *   - arming/disarming:     LORA_RECV_ASYNC(dev, cb) (or LORA_RECV_ASYNC_1
 *     for a NULL-callback disarm).
 */

#include <zephyr/version.h>

#if defined(ZEPHYR_VERSION_CODE) && ZEPHYR_VERSION_CODE >= ZEPHYR_VERSION(4, 0, 0)

#define LORA_RECV_CB_EXTRA_ARGS , void *user_data
#define LORA_RECV_CB_UNUSED ARG_UNUSED(user_data)
#define LORA_RECV_CB_PASS(user_data) , (user_data)
#define LORA_RECV_ASYNC(dev, cb) lora_recv_async((dev), (cb), NULL)
#define LORA_RECV_ASYNC_1(dev) lora_recv_async((dev), NULL, NULL)

#else

#define LORA_RECV_CB_EXTRA_ARGS
#define LORA_RECV_CB_UNUSED
#define LORA_RECV_CB_PASS(user_data)
#define LORA_RECV_ASYNC(dev, cb) lora_recv_async((dev), (cb))
#define LORA_RECV_ASYNC_1(dev) lora_recv_async((dev), NULL)

#endif

#endif /* LICHEN_LORA_COMPAT_H_ */
