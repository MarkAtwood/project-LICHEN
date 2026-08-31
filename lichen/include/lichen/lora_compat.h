/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_LORA_COMPAT_H
#define LICHEN_LORA_COMPAT_H

#include <zephyr/version.h>
#include <zephyr/drivers/lora.h>

/*
 * Zephyr 4.1.0 changed the LoRa async-receive contract: lora_recv_async()
 * gained a trailing void *user_data parameter and the lora_recv_cb typedef
 * gained a trailing void *user_data argument (v3.7.0: 2-arg call, 5-param
 * callback; v4.1.0: 3-arg call, 6-param callback).  The repository pins
 * Zephyr v3.7.0, while the shared native_sim workspace builds 4.1.0; these
 * macros keep both compilable (same pattern as the coap_client v3.7/v4.1
 * lock fix).
 */

#if KERNEL_VERSION_NUMBER >= 0x040100

/* Arm or disarm (cb == NULL) asynchronous reception. */
#define LORA_RECV_ASYNC(dev, cb) lora_recv_async((dev), (cb), NULL)

/* Trailing callback-parameter fragments: definition, invocation, and the
 * unused-argument guard for implementations that ignore user_data. */
#define LORA_RECV_CB_EXTRA_ARGS , void *user_data
#define LORA_RECV_CB_PASS , user_data
#define LORA_RECV_CB_UNUSED ARG_UNUSED(user_data)

/* Invoke a stored callback, forwarding a user_data value that is only
 * available on 4.1.0 (e.g. the pointer a driver-side recv_async stored). */
#define LORA_RECV_CB_PASS_VALUE(ptr) , (ptr)

/* The user_data value received by a driver-side recv_async implementation. */
#define LORA_RECV_CB_USER_DATA_ARG user_data

#else

#define LORA_RECV_ASYNC(dev, cb) lora_recv_async((dev), (cb))

#define LORA_RECV_CB_EXTRA_ARGS
#define LORA_RECV_CB_PASS
#define LORA_RECV_CB_UNUSED

#define LORA_RECV_CB_PASS_VALUE(ptr)
#define LORA_RECV_CB_USER_DATA_ARG NULL

#endif

#endif /* LICHEN_LORA_COMPAT_H */
