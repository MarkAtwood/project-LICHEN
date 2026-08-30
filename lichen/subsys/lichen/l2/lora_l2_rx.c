/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2_rx.c
 * @brief LICHEN LoRa L2 interrupt-driven receive path
 *
 * Reception uses the driver's asynchronous API (lora_recv_async): the radio
 * is armed once and the driver invokes the ISR callback on RX_DONE. The ISR
 * callback only copies (data, len, rssi, snr) into a staging buffer owned by
 * this module and submits a work item; all packet processing (the callback
 * chain into lichen_link_rx) and re-arming happens in the system workqueue.
 *
 * Buffer ownership: rx_stage is owned by L2. The registered RX callback
 * receives a pointer that is valid ONLY for the duration of the callback
 * invocation (same contract the old RX thread provided with its stack
 * buffer). While a packet is staged, the ISR drops any further delivery, so
 * a callback that outlives its invocation never observes mutated data.
 *
 * Radio-liveness hook. Apps that gate a watchdog feed on radio progress
 * (puck main.c) provide a strong definition; standalone builds fall back to
 * this no-op. Same pattern as lichen/lib/native/native.c. The hook is now
 * bumped from work executions (packet delivery and re-arm attempts) instead
 * of an RX thread loop; consumers must not rely on it being bumped while the
 * radio sits idle and armed.
 */
#include "lora_l2_internal.h"
#include "crash_info.h"

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/drivers/lora.h>

LOG_MODULE_DECLARE(lichen_lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);

/** Delay between re-arm attempts while the modem is owned by TX. */
#define RX_REARM_RETRY_MS 10

__attribute__((weak)) void lichen_radio_progress(void)
{
}

/*
 * Staging buffer for received packets. Sized to LICHEN_LORA_MAX_PAYLOAD
 * (255 bytes) - the maximum a driver may deliver. The ISR callback copies
 * driver-owned data here before handing off to the workqueue.
 */
static uint8_t rx_stage[LICHEN_LORA_MAX_PHY_PAYLOAD];
BUILD_ASSERT(sizeof(rx_stage) == LICHEN_LORA_MAX_PHY_PAYLOAD,
             "rx_stage size must equal LICHEN_LORA_MAX_PHY_PAYLOAD for "
             "callback buffer sizing guarantees");
static uint16_t rx_stage_len;
static int16_t rx_stage_rssi;
static int8_t rx_stage_snr;

/*
 * rx_enabled: RX is supposed to be active (RUNNING and not stopping).
 * Written from thread context (start/stop), read from the ISR callback.
 * Cleared BEFORE the driver is disarmed so late deliveries are dropped.
 *
 * rx_pending: a packet is staged and awaiting processing. Set by the ISR
 * (test-and-set), cleared by the work handler after the RX callback returns,
 * which makes the staging buffer immutable for the whole callback duration.
 */
static atomic_t rx_enabled;
static atomic_t rx_pending;

/*
 * Single work item: delivers the staged packet (if any), then re-arms the
 * driver. Delayable so a re-arm blocked by TX ownership can retry shortly
 * without a dedicated thread or busy sleep.
 */
static void rx_work_fn(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(rx_work, rx_work_fn);

static void lora_l2_rx_isr_cb(const struct device *dev, uint8_t *data,
			      uint16_t size, int16_t rssi, int8_t snr);

/**
 * @brief Arm the driver for the next asynchronous reception
 *
 * Must be called with the module in LORA_RUNNING. Arms under modem_mutex
 * (non-blocking) so driver access stays serialized with TX; if the modem is
 * busy or the arm call fails transiently, a short delayable retry keeps the
 * re-arm alive without blocking the system workqueue.
 *
 * A driver that reports -ENOTSUP cannot receive at all: fail closed by
 * forcing the module into ABORTED so callers see needs_reinit() instead of a
 * silently deaf radio.
 */
static void lora_l2_rx_arm(void)
{
	int ret;

	if (atomic_get(&tx_pending) > 0) {
		/* TX owns or is about to own the modem; retry shortly. */
		goto retry;
	}

	if (k_mutex_lock(&modem_mutex, K_NO_WAIT) != 0) {
		/* TX holds the modem; retry when it is released. */
		goto retry;
	}

	/*
	 * Re-check under the modem lock: stop() may have transitioned the
	 * module to STOPPED while this handler was waiting; arming a stopped
	 * module would leave the driver armed across stop() and fail the
	 * next start() with -EBUSY on drivers that reject double-arming.
	 */
	if (lora_get_state() != LORA_RUNNING) {
		k_mutex_unlock(&modem_mutex);
		return;
	}

	ret = lora_recv_async(lora_data.lora_dev, lora_l2_rx_isr_cb);
	k_mutex_unlock(&modem_mutex);

	if (ret == 0) {
		return;
	}

	if (ret == -ENOTSUP) {
		LOG_ERR("lora_l2: driver lacks recv_async; RX impossible");
		atomic_set(&current_state, LORA_ABORTED);
		return;
	}

	LOG_ERR("lora_l2: recv_async arm failed (%d)", ret);

retry:
	k_work_schedule(&rx_work, K_MSEC(RX_REARM_RETRY_MS));
}

/**
 * @brief ISR callback invoked by the driver on RX_DONE
 *
 * Runs in driver interrupt context: only copy into the staging buffer and
 * submit the work item. The driver's data buffer is valid only during this
 * callback (Zephyr lora_recv_async contract).
 *
 * A payload larger than the staging buffer is a driver-contract violation
 * that would overflow rx_stage. The old RX thread treated this as
 * unrecoverable corruption; do the same here (crash_info is designed to be
 * callable from error paths including ISRs) and leave the radio unarmed.
 */
static void lora_l2_rx_isr_cb(const struct device *dev, uint8_t *data,
			      uint16_t size, int16_t rssi, int8_t snr)
{
	ARG_UNUSED(dev);

	if ((size_t)size > sizeof(rx_stage)) {
		LOG_ERR("lora_l2: recv overflow (%u > %u)", size,
			(unsigned int)sizeof(rx_stage));
		crash_info_store(CRASH_DRIVER_OVERFLOW, __LINE__, (uint32_t)size);
		atomic_set(&current_state, LORA_ABORTED);
		return;
	}

	if (!atomic_get(&rx_enabled)) {
		/* Stop raced the delivery; the packet is dropped, which is
		 * what the radio would have lost anyway when disarming. */
		return;
	}

	if (atomic_cas(&rx_pending, 0, 1)) {
		/* Claimed the staging buffer. Single outstanding RX means a
		 * concurrent claim cannot happen (we re-arm only after
		 * processing); defensive against drivers that auto-re-arm. */
	} else {
		LOG_DBG("lora_l2: RX staging busy, packet dropped");
		return;
	}

	memcpy(rx_stage, data, size);
	rx_stage_len = size;
	rx_stage_rssi = rssi;
	rx_stage_snr = snr;

	/* rx_work is delayable (the re-arm retry uses the delay slot); submit
	 * it immediately with a zero delay. */
	k_work_schedule(&rx_work, K_NO_WAIT);
}

/**
 * @brief Work handler: deliver staged packet, then re-arm the driver
 */
static void rx_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	/*
	 * Radio-liveness heartbeat: apps gate their watchdog feed on this
	 * (see puck main.c). Each execution proves the RX path is not wedged.
	 */
	lichen_radio_progress();

	if (atomic_get(&rx_pending)) {
		uint16_t len = rx_stage_len;
		int16_t rssi = rx_stage_rssi;
		int8_t snr = rx_stage_snr;

		/*
		 * Snapshot the callback pair under lock for consistency
		 * (preserves the old RX thread invariant: stop() clears the
		 * callback before any later work execution observes it).
		 *
		 * LOCK ORDER INVARIANT (project-LICHEN-i1gk.45): lora_mutex is
		 * released BEFORE the callback is invoked, and the callback
		 * never calls back into functions that need lora_mutex, so no
		 * lock ordering between lora_mutex and rx_mutex exists.
		 */
		k_mutex_lock(&lora_mutex, K_FOREVER);
		lichen_lora_rx_cb_t cb = lora_data.rx_callback;
		void *cb_user_data = lora_data.rx_callback_user_data;
		k_mutex_unlock(&lora_mutex);

		if (cb != NULL && len > 0) {
			/*
			 * Buffer ownership: rx_stage stays immutable for the
			 * whole callback (rx_pending is still set, so the ISR
			 * drops any concurrent delivery). The pointer is valid
			 * ONLY for the duration of this invocation.
			 */
			cb(rx_stage, len, rssi, snr, cb_user_data);
		}

		atomic_clear(&rx_pending);
	}

	if (lora_get_state() == LORA_RUNNING) {
		lora_l2_rx_arm();
	}
}

/**
 * @brief Arm the first asynchronous reception (called from start())
 *
 * The modem cannot be contended here: the module just transitioned
 * STOPPED -> RUNNING and no TX can be in flight yet.
 *
 * @return 0 on success, negative errno from the driver on failure
 */
int lora_l2_rx_start(void)
{
	int ret;

	atomic_clear(&rx_pending);
	atomic_set(&rx_enabled, 1);

	k_mutex_lock(&modem_mutex, K_FOREVER);
	ret = lora_recv_async(lora_data.lora_dev, lora_l2_rx_isr_cb);
	k_mutex_unlock(&modem_mutex);

	if (ret < 0) {
		atomic_set(&rx_enabled, 0);
		return ret;
	}

	return 0;
}

/**
 * @brief Disarm the driver and drain the RX work item (called from stop())
 *
 * Order matters:
 * 1. Clear rx_enabled: ISR deliveries are dropped from here on (stop() has
 *    already transitioned to STOPPED before calling this).
 * 2. Cancel a scheduled re-arm retry, then flush: when this returns, the
 *    work item is neither queued nor running, and - because the handler
 *    re-checks the state inside its arm critical section - nothing will
 *    arm the driver afterwards.
 * 3. Disarm under modem_mutex (non-blocking): if TX owns the modem the
 *    enabled gate already drops stragglers, and TX cannot deliver a packet
 *    to this module.
 *
 * The net effect equals the old RX thread join: no RX callback can start
 * after stop() completes, without any join/abort failure modes.
 */
void lora_l2_rx_stop(void)
{
	const struct device *dev = lora_data.lora_dev;
	int ret;

	atomic_set(&rx_enabled, 0);

	k_work_cancel_delayable(&rx_work);
	{
		/* Thread context requires a sync token for the flush. */
		struct k_work_sync rx_sync;

		k_work_flush_delayable(&rx_work, &rx_sync);
	}

	if (dev != NULL && k_mutex_lock(&modem_mutex, K_NO_WAIT) == 0) {
		ret = lora_recv_async(dev, NULL);
		k_mutex_unlock(&modem_mutex);
		if (ret < 0) {
			LOG_WRN("lora_l2: recv_async disarm failed (%d)", ret);
		}
	} else {
		LOG_DBG("lora_l2: modem busy during RX disarm");
	}
}

int lichen_lora_l2_set_rx_callback(lichen_lora_rx_cb_t cb, void *user_data)
{
	enum lora_state state = lora_get_state();

	if (state == LORA_UNINIT) {
		LOG_WRN("lora_l2: cannot set RX callback, not initialized");
		return -ENODEV;
	}
	if (state == LORA_DEINITING) {
		LOG_WRN("lora_l2: cannot set RX callback during deinit");
		return -EBUSY;
	}
	if (state == LORA_ABORTED || lichen_lora_l2_needs_reinit()) {
		LOG_WRN("lora_l2: cannot set RX callback until reinit after abort");
		return -ECANCELED;
	}

	/*
	 * Use mutex to ensure atomic update of callback + user_data pair.
	 * The work handler reads both fields, so they must be updated together
	 * to avoid invoking a callback with mismatched user_data.
	 *
	 * Order matters: user_data MUST be set before callback. If the callback
	 * pointer is read non-NULL, user_data must already be valid. This order
	 * is safe even for lock-free reads (though we use mutex here).
	 *
	 * Ownership: caller retains ownership of user_data. This module stores
	 * the pointer and passes it back on invocation, but never frees it.
	 * Callers should clean up their user_data before calling stop() or
	 * deinit() if the memory would otherwise be orphaned.
	 */
	k_mutex_lock(&lora_mutex, K_FOREVER);
	lora_data.rx_callback_user_data = user_data;
	lora_data.rx_callback = cb;
	k_mutex_unlock(&lora_mutex);

	return 0;
}
