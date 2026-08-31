/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: The contributors to the LICHEN project
 *
 * LoRa loopback driver for native_sim.
 *
 * Simple test driver that loops transmitted packets back to the receiver.
 * No external simulator or hardware required. Uses k_msgq for the internal
 * packet queue.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/logging/log.h>

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
#include <lichen/lora_cad.h>
#endif
#include <zephyr/sys/atomic.h>
#include <string.h>

#include "lora_loopback_test.h"

LOG_MODULE_REGISTER(lora_loopback, CONFIG_LORA_LOG_LEVEL);

#define DT_DRV_COMPAT lichen_lora_loopback

/* Maximum LoRa payload size */
#define LORA_MAX_PAYLOAD 255

/* Queue depth for loopback packets */
#define LOOPBACK_QUEUE_DEPTH CONFIG_LORA_LOOPBACK_QUEUE_DEPTH

/* Packet structure for the message queue */
struct loopback_packet {
	uint8_t data[LORA_MAX_PAYLOAD];
	uint8_t len;
};

struct lora_loopback_data {
	struct k_msgq rx_queue;
	char __aligned(4) rx_queue_buf[LOOPBACK_QUEUE_DEPTH * sizeof(struct loopback_packet)];
	struct lora_modem_config config;
	bool configured;
	/* Async RX (lora_recv_async): a registered callback is fed queued
	 * packets from the system workqueue. recv_cb != NULL means armed;
	 * rx_lock guards the callback pointer. The delivery buffer lives in
	 * per-instance data rather than the workqueue stack. */
	const struct device *dev;
	struct k_work rx_work;
	struct k_spinlock rx_lock;
	lora_recv_cb recv_cb;
	void *recv_cb_user_data;
	struct loopback_packet rx_pkt;
#ifdef CONFIG_LORA_LOOPBACK_TEST_HOOKS
	atomic_t sent_packets;
	atomic_t received_packets;
#endif
};

#ifdef CONFIG_LORA_LOOPBACK_TEST_HOOKS
void lora_loopback_test_reset(const struct device *dev)
{
	struct lora_loopback_data *data = dev->data;
	struct loopback_packet pkt;

	while (k_msgq_get(&data->rx_queue, &pkt, K_NO_WAIT) == 0) {
	}

	atomic_set(&data->sent_packets, 0);
	atomic_set(&data->received_packets, 0);
}

void lora_loopback_test_get_stats(const struct device *dev,
				  struct lora_loopback_test_stats *stats)
{
	struct lora_loopback_data *data = dev->data;

	if (stats == NULL) {
		return;
	}

	stats->sent_packets = (uint32_t)atomic_get(&data->sent_packets);
	stats->received_packets = (uint32_t)atomic_get(&data->received_packets);
}
#endif

static int lora_loopback_config(const struct device *dev,
				struct lora_modem_config *config)
{
	struct lora_loopback_data *data = dev->data;

	if (config == NULL) {
		return -EINVAL;
	}

	memcpy(&data->config, config, sizeof(*config));
	data->configured = true;

	LOG_DBG("configured: freq=%u, sf=%d, bw=%d, tx=%d",
		config->frequency, config->datarate, config->bandwidth, config->tx);

	return 0;
}

static int lora_loopback_send(const struct device *dev,
			      uint8_t *payload, uint32_t payload_len)
{
	struct lora_loopback_data *data = dev->data;
	struct loopback_packet pkt;
	int ret;

	if (payload == NULL || payload_len == 0) {
		return -EINVAL;
	}

	if (payload_len > CONFIG_LORA_LOOPBACK_MTU) {
		LOG_ERR("payload exceeds MTU: %u > %u", payload_len, CONFIG_LORA_LOOPBACK_MTU);
		return -EMSGSIZE;
	}

	memcpy(pkt.data, payload, payload_len);
	pkt.len = (uint8_t)payload_len;

	ret = k_msgq_put(&data->rx_queue, &pkt, K_NO_WAIT);
	if (ret != 0) {
		LOG_WRN("loopback queue full, packet dropped");
		return -ENOBUFS;
	}

#ifdef CONFIG_LORA_LOOPBACK_TEST_HOOKS
	atomic_inc(&data->sent_packets);
#endif
	/* Feed a registered async receiver (work-item context). Sending while
	 * async RX is armed is deliberately allowed — loopback tests must be
	 * able to transmit into their own armed receiver. */
	k_work_submit(&data->rx_work);

	LOG_DBG("sent %u bytes (looped back to rx queue)", payload_len);
	return 0;
}

static int lora_loopback_recv(const struct device *dev,
			      uint8_t *payload, uint8_t size,
			      k_timeout_t timeout,
			      int16_t *rssi, int8_t *snr)
{
	struct lora_loopback_data *data = dev->data;
	struct loopback_packet pkt;
	int ret;

	if (payload == NULL || size == 0) {
		return -EINVAL;
	}

	k_spinlock_key_t key = k_spin_lock(&data->rx_lock);
	bool armed = data->recv_cb != NULL;

	k_spin_unlock(&data->rx_lock, key);
	if (armed) {
		/* One receiver at a time: an armed async RX owns the queue
		 * (upstream sx12xx semantics). */
		return -EBUSY;
	}

	ret = k_msgq_get(&data->rx_queue, &pkt, timeout);
	if (ret == -EAGAIN || ret == -ENOMSG) {
		return -EAGAIN;
	}
	if (ret != 0) {
		return ret;
	}

	if (pkt.len > size) {
		LOG_ERR("recv: packet too large for buffer: %u > %u", pkt.len, size);
		return -EMSGSIZE;
	}

	memcpy(payload, pkt.data, pkt.len);

	/* Provide simulated RSSI and SNR values */
	if (rssi != NULL) {
		*rssi = CONFIG_LORA_LOOPBACK_RSSI;
	}
	if (snr != NULL) {
		*snr = CONFIG_LORA_LOOPBACK_SNR;
	}

#ifdef CONFIG_LORA_LOOPBACK_TEST_HOOKS
	atomic_inc(&data->received_packets);
#endif
	LOG_DBG("received %u bytes (from loopback queue)", pkt.len);
	return pkt.len;
}

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
static int lora_loopback_cad(const struct device *dev, k_timeout_t timeout,
			     bool *busy)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(timeout);
	if (busy == NULL) {
		return -EINVAL;
	}
	*busy = false;
	return 0;
}
#endif

/* Deliver queued packets to the registered async callback. Runs in system
 * workqueue context; the callback may cancel (recv_async(NULL)) — cancel-then
 * re-arm also works — both handled by re-reading recv_cb each packet. The
 * drain is capped per run so a send flood cannot monopolize the workqueue;
 * excess packets are picked up by the re-submitted work item. */
static void lora_loopback_rx_work(struct k_work *work)
{
	struct lora_loopback_data *data =
		CONTAINER_OF(work, struct lora_loopback_data, rx_work);
	const struct device *dev = data->dev;
	int drained = 0;

	while (drained++ < LOOPBACK_QUEUE_DEPTH) {
		k_spinlock_key_t key = k_spin_lock(&data->rx_lock);
		lora_recv_cb cb = data->recv_cb;
		void *cb_user_data = data->recv_cb_user_data;

		k_spin_unlock(&data->rx_lock, key);

		if (cb == NULL) {
			return;
		}

		if (k_msgq_get(&data->rx_queue, &data->rx_pkt, K_NO_WAIT) != 0) {
			return;
		}

#ifdef CONFIG_LORA_LOOPBACK_TEST_HOOKS
		atomic_inc(&data->received_packets);
#endif
		cb(dev, data->rx_pkt.data, data->rx_pkt.len,
		   CONFIG_LORA_LOOPBACK_RSSI, CONFIG_LORA_LOOPBACK_SNR,
		   cb_user_data);
	}

	/* Queue still has work: re-queue ourselves (Zephyr re-submission of a
	 * running item is legal and ordered after this run). */
	k_work_submit(&data->rx_work);
}

static int lora_loopback_recv_async(const struct device *dev,
				    lora_recv_cb cb, void *user_data)
{
	struct lora_loopback_data *data = dev->data;

	if (cb == NULL) {
		k_spinlock_key_t key = k_spin_lock(&data->rx_lock);
		bool was_armed = data->recv_cb != NULL;

		data->recv_cb = NULL;
		data->recv_cb_user_data = NULL;
		k_spin_unlock(&data->rx_lock, key);
		return was_armed ? 0 : -EINVAL;
	}

	k_spinlock_key_t key = k_spin_lock(&data->rx_lock);

	if (data->recv_cb != NULL) {
		k_spin_unlock(&data->rx_lock, key);
		return -EBUSY;
	}
	data->recv_cb = cb;
	data->recv_cb_user_data = user_data;
	k_spin_unlock(&data->rx_lock, key);

	/* Deliver anything already queued (sent before arming). */
	k_work_submit(&data->rx_work);
	return 0;
}

static int lora_loopback_init(const struct device *dev)
{
	struct lora_loopback_data *data = dev->data;

	k_msgq_init(&data->rx_queue, data->rx_queue_buf,
		    sizeof(struct loopback_packet), LOOPBACK_QUEUE_DEPTH);

	data->configured = false;
	data->dev = dev;
	data->recv_cb = NULL;
	k_work_init(&data->rx_work, lora_loopback_rx_work);

	LOG_INF("LoRa loopback driver initialized (queue depth=%d)",
		LOOPBACK_QUEUE_DEPTH);

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
	return lichen_lora_cad_register(dev, lora_loopback_cad);
#endif
	return 0;
}

static int lora_loopback_send_async(const struct device *dev, uint8_t *data,
				    uint32_t data_len,
				    struct k_poll_signal *async)
{
	int ret = lora_loopback_send(dev, data, data_len);

	if (async != NULL) {
		/* The underlying send is synchronous: completion fires before
		 * this call returns (poll-safe, no deferred context). */
		k_poll_signal_raise(async, ret);
	}
	return ret;
}

static const struct lora_driver_api lora_loopback_api = {
	.config     = lora_loopback_config,
	.send       = lora_loopback_send,
	.send_async = lora_loopback_send_async,
	.recv       = lora_loopback_recv,
	.recv_async = lora_loopback_recv_async,
};

#define LORA_LOOPBACK_DEFINE(inst)					\
	static struct lora_loopback_data lora_loopback_data_##inst;	\
	DEVICE_DT_INST_DEFINE(inst, lora_loopback_init, NULL,		\
			      &lora_loopback_data_##inst, NULL,		\
			      POST_KERNEL, CONFIG_LORA_INIT_PRIORITY,	\
			      &lora_loopback_api);

DT_INST_FOREACH_STATUS_OKAY(LORA_LOOPBACK_DEFINE)
