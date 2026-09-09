/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_LORA_CAD_H_
#define LICHEN_LORA_CAD_H_

#include <stdbool.h>

#ifdef __ZEPHYR__
#include <zephyr/device.h>
#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

/** CAD completion delivered from the driver's own context (work/IRQ):
 * busy reflects the CadDetected verdict; status is 0 or a negative errno
 * (e.g. -ETIMEDOUT when CAD never completed, fail-closed). The callback
 * runs under the CAD registry mutex (thread/work context only) and must
 * never block — record the verdict and signal/return. */
typedef void (*lichen_lora_cad_done_fn)(const struct device *dev, bool busy,
					int status, void *user_data);

/** Driver-side async CAD start: arm the radio, return immediately. The
 * completion must be delivered exactly once via lichen_lora_cad_done(). */
typedef int (*lichen_lora_cad_start_fn)(const struct device *dev,
					k_timeout_t timeout);

/** Register a device for CAD, optionally with a driver-side async CAD
 * start (lr1110-class hardware). A NULL start selects the emulated
 * clear-channel completion (sim/renode/loopback have no hardware CAD). */
int lichen_lora_cad_start_register(const struct device *dev,
				   lichen_lora_cad_start_fn start);

/** Begin CAD without blocking; the verdict arrives via done() from the
 * driver's completion context. Fails closed (-EBUSY in flight, -ENOTSUP
 * without a registered device, -EINVAL on bad args). */
int lichen_lora_cad_start(const struct device *dev, k_timeout_t timeout,
			  lichen_lora_cad_done_fn done, void *user_data);

/** Driver completion entry point: deliver the CAD verdict exactly once
 * (no-op if no CAD is in flight for this device). The consumer callback
 * is invoked under the CAD registry mutex; call from thread/work context
 * only. */
void lichen_lora_cad_done(const struct device *dev, bool busy, int status);

#ifdef __cplusplus
}
#endif
#endif /* __ZEPHYR__ */

#endif /* LICHEN_LORA_CAD_H_ */
