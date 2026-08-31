/*
 * LICHEN LoRa driver for Renode LichenSubGHz peripheral.
 *
 * Memory-mapped interface to the C# peripheral which bridges to lichen-sim.
 * For use in Renode simulation of STM32WL firmware.
 *
 * Polling Design Note:
 *   TX uses fixed 1ms polling intervals, RX uses 10ms intervals. These are
 *   simple and sufficient for simulation where timing is not critical.
 *   A production driver on real hardware could use interrupts or k_poll(),
 *   but the Renode peripheral doesn't support GPIO interrupts, so polling
 *   is the appropriate model for this simulation environment.
 *
 * Memory map (base from devicetree, typically 0x58010000):
 *   0x000: TX_LEN (write) - payload length
 *   0x004: TX_TRIGGER (write) - any write triggers TX
 *   0x008: TX_STATUS (read) - 0=idle, 1=busy, 2=done, 3=fail
 *   0x00C: TX_AIRTIME (read) - last TX airtime in us
 *   0x010: RX_STATUS (read) - 0=empty, 1=packet available
 *   0x014: RX_LEN (read) - received payload length
 *   0x018: RX_RSSI (read) - RSSI in dBm (int16)
 *   0x01C: RX_SNR (read) - SNR * 10 (int16)
 *   0x020: RX_CONSUME (write) - consume RX packet
 *   0x024: CONNECT (write) - trigger socket connect to lichen-sim
 *   0x100-0x1FF: TX_BUFFER (256 bytes)
 *   0x200-0x2FF: RX_BUFFER (256 bytes)
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
#include <lichen/lora_cad.h>
#endif

LOG_MODULE_REGISTER(lora_renode, CONFIG_LORA_LOG_LEVEL);

#define DT_DRV_COMPAT lichen_lora_renode

/* Register offsets */
#define REG_TX_LEN      0x000
#define REG_TX_TRIGGER  0x004
#define REG_TX_STATUS   0x008
#define REG_TX_AIRTIME  0x00C
#define REG_RX_STATUS   0x010
#define REG_RX_LEN      0x014
#define REG_RX_RSSI     0x018
#define REG_RX_SNR      0x01C
#define REG_RX_CONSUME  0x020
#define REG_CONNECT     0x024
#define REG_TX_BUFFER   0x100
#define REG_RX_BUFFER   0x200

/* TX_STATUS values */
#define TX_IDLE  0
#define TX_BUSY  1
#define TX_DONE  2
#define TX_FAIL  3

/* RX_STATUS values */
#define RX_EMPTY    0
#define RX_AVAILABLE 1

/* Async RX poll interval. The Renode peripheral has no GPIO interrupts, so
 * recv_async polls RX_STATUS from a self-rescheduling work item — the same
 * 10 ms model as the synchronous recv() poll loop. */
#define RENODE_RX_POLL_MS 10

struct lora_renode_config {
	volatile uint32_t *base;
};

struct lora_renode_data {
	bool connected;
	/* Async RX (lora_recv_async). recv_cb != NULL means armed. The armed
	 * state holds the modem lock (modem_usage), so sync send/recv return
	 * -EBUSY while an async receive is pending — upstream sx12xx
	 * semantics. The poller reschedules itself until disarmed. */
	struct k_work_delayable rx_poll;
	struct k_spinlock rx_lock;
	lora_recv_cb recv_cb;
	void *recv_cb_user_data;
	const struct device *dev;
	atomic_t modem_usage;
	/* Delivery buffer: lives in per-instance data rather than the system
	 * workqueue stack (256 B would be tight on constrained targets). */
	uint8_t rx_buf[256];
};

/* Upstream sx12xx-style single-operation lock: acquire succeeds only when
 * the modem was idle. An armed async RX holds the lock until cancelled.
 * CAS so a losing contender leaves the counter untouched. */
static bool renode_modem_acquire(struct lora_renode_data *drv)
{
	return atomic_cas(&drv->modem_usage, 0, 1);
}

static void renode_modem_release(struct lora_renode_data *drv)
{
	atomic_dec(&drv->modem_usage);
}

static void lora_renode_rx_poll(struct k_work *work);

static inline uint32_t reg_read(const struct lora_renode_config *cfg, uint32_t off)
{
	return cfg->base[off / 4];
}

static inline void reg_write(const struct lora_renode_config *cfg, uint32_t off, uint32_t val)
{
	cfg->base[off / 4] = val;
}

static inline void buf_write(const struct lora_renode_config *cfg,
			     uint32_t off, const uint8_t *data, uint32_t len)
{
	volatile uint8_t *dst = (volatile uint8_t *)cfg->base + off;

	for (uint32_t i = 0; i < len; i++) {
		dst[i] = data[i];
	}
}

static inline void buf_read(const struct lora_renode_config *cfg,
			    uint32_t off, uint8_t *data, uint32_t len)
{
	volatile uint8_t *src = (volatile uint8_t *)cfg->base + off;

	for (uint32_t i = 0; i < len; i++) {
		data[i] = src[i];
	}
}

/* --- LoRa API callbacks ------------------------------------------------- */

static int lora_renode_config(const struct device *dev,
			      struct lora_modem_config *config)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(config);
	/* Simulator ignores RF config; the medium model controls propagation. */
	return 0;
}

static int lora_renode_send(const struct device *dev,
			    uint8_t *data, uint32_t data_len)
{
	if (dev == NULL || data == NULL) {
		return -EINVAL;
	}
	const struct lora_renode_config *cfg = dev->config;
	struct lora_renode_data *drv = dev->data;
	if (!drv->connected) {
		LOG_WRN("not connected to lichen-sim");
		return -ENOTCONN;
	}
	if (data_len > 255) {
		return -EMSGSIZE;
	}
	if (!renode_modem_acquire(drv)) {
		/* An armed async RX holds the modem. */
		return -EBUSY;
	}

	/* Write payload to TX buffer */
	buf_write(cfg, REG_TX_BUFFER, data, data_len);

	/* Set TX length */
	reg_write(cfg, REG_TX_LEN, data_len);

	/* Trigger TX */
	reg_write(cfg, REG_TX_TRIGGER, 1);

	/* Poll for completion.
	 * TX_TIMEOUT_MS covers the longest LoRa airtime: SF12/125kHz with 255B
	 * payload takes ~1.3s. 2 seconds provides margin for simulation overhead.
	 * Timeout indicates a stuck radio.
	 */
	#define TX_TIMEOUT_MS 2000
	uint32_t status;
	int retries = TX_TIMEOUT_MS;
	int ret = -ETIMEDOUT;

	do {
		status = reg_read(cfg, REG_TX_STATUS);
		if (status == TX_DONE) {
			LOG_DBG("TX done, airtime=%u us, len=%u", reg_read(cfg, REG_TX_AIRTIME), data_len);
			ret = 0;
			goto out;
		}
		if (status == TX_FAIL) {
			LOG_ERR("TX failed, len=%u", data_len);
			ret = -EIO;
			goto out;
		}
		k_sleep(K_MSEC(1));
	} while (--retries > 0);

	LOG_ERR("TX timeout");
out:
	renode_modem_release(drv);
	return ret;
}

static int lora_renode_recv(const struct device *dev,
			    uint8_t *data, uint8_t size,
			    k_timeout_t timeout,
			    int16_t *rssi, int8_t *snr)
{
	const struct lora_renode_config *cfg = dev->config;
	struct lora_renode_data *drv = dev->data;

	if (!drv->connected) {
		return -ENOTCONN;
	}
	if (!renode_modem_acquire(drv)) {
		/* An armed async RX holds the modem. */
		return -EBUSY;
	}

	bool forever = K_TIMEOUT_EQ(timeout, K_FOREVER);
	uint32_t timeout_ms = forever ? 0 : k_ticks_to_ms_floor32(timeout.ticks);
	uint32_t elapsed = 0;
	int ret = -EAGAIN;

	/* Poll RX_STATUS until packet or timeout */
	while (forever || elapsed < timeout_ms) {
		uint32_t status = reg_read(cfg, REG_RX_STATUS);

		if (status == RX_AVAILABLE) {
			uint16_t rx_len = (uint16_t)reg_read(cfg, REG_RX_LEN);

			if (rx_len > size) {
				/* Consume the packet to prevent infinite loop,
				 * then return error */
				reg_write(cfg, REG_RX_CONSUME, 1);
				LOG_ERR("recv: packet too large for buffer: %u > %u",
					rx_len, size);
				ret = -EMSGSIZE;
				goto out;
			}

			buf_read(cfg, REG_RX_BUFFER, data, rx_len);

			if (rssi) {
				*rssi = (int16_t)reg_read(cfg, REG_RX_RSSI);
			}
			if (snr) {
				/* SNR stored as *10, convert to int8 */
				int16_t snr_x10 = (int16_t)reg_read(cfg, REG_RX_SNR);
				*snr = (int8_t)(snr_x10 / 10);
			}

			/* Consume the packet */
			reg_write(cfg, REG_RX_CONSUME, 1);

			LOG_DBG("RX: %u bytes, RSSI=%d, SNR=%d", rx_len,
				rssi ? *rssi : 0, snr ? *snr : 0);
			ret = rx_len;
			goto out;
		}

		k_sleep(K_MSEC(10));
		elapsed += 10;
	}

out:
	renode_modem_release(drv);
	return ret;
}

/* --- device init -------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
static int lora_renode_cad(const struct device *dev, k_timeout_t timeout,
			    bool *busy);
#endif

static int lora_renode_init(const struct device *dev)
{
	const struct lora_renode_config *cfg = dev->config;
	struct lora_renode_data *data = dev->data;

	data->dev = dev;
	data->recv_cb = NULL;
	data->recv_cb_user_data = NULL;
	data->modem_usage = 0;
	k_work_init_delayable(&data->rx_poll, lora_renode_rx_poll);

	/* Trigger connection to lichen-sim */
	reg_write(cfg, REG_CONNECT, 1);

	/* Brief delay for connection */
	k_sleep(K_MSEC(100));

	/* Check if we can read TX_STATUS (any value means peripheral is alive) */
	uint32_t status = reg_read(cfg, REG_TX_STATUS);

	data->connected = true;
	if (status <= TX_FAIL) {
		LOG_INF("initialized, connected to lichen-sim");
	} else {
		LOG_WRN("peripheral not responding, continuing anyway");
	}
#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
	return lichen_lora_cad_register(dev, lora_renode_cad);
#endif
	return 0;
}

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
static int lora_renode_cad(const struct device *dev, k_timeout_t timeout,
			    bool *busy)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(timeout);
	if (busy == NULL) {
		return -EINVAL;
	}
	*busy = false; /* renode sim assumes clear */
	return 0;
}
#endif

static int lora_renode_send_async(const struct device *dev, uint8_t *data,
				  uint32_t data_len, struct k_poll_signal *async)
{
	ARG_UNUSED(async);
	return lora_renode_send(dev, data, data_len);
}

/* Async RX poller: self-rescheduling work item. Exits (without rescheduling)
 * as soon as the callback is disarmed, so a cancel is honored even if the
 * poller is mid-run. */
static void lora_renode_rx_poll(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct lora_renode_data *drv =
		CONTAINER_OF(dwork, struct lora_renode_data, rx_poll);
	const struct device *dev = drv->dev;
	const struct lora_renode_config *cfg = dev->config;

	k_spinlock_key_t key = k_spin_lock(&drv->rx_lock);
	lora_recv_cb cb = drv->recv_cb;
	void *cb_user_data = drv->recv_cb_user_data;

	k_spin_unlock(&drv->rx_lock, key);
	if (cb == NULL) {
		return;
	}

	if (reg_read(cfg, REG_RX_STATUS) == RX_AVAILABLE) {
		uint16_t rx_len = (uint16_t)reg_read(cfg, REG_RX_LEN);
		int16_t rssi = 0;
		int8_t snr = 0;

		if (rx_len > sizeof(drv->rx_buf)) {
			/* Oversized frame: consume and drop, keep polling. */
			reg_write(cfg, REG_RX_CONSUME, 1);
			LOG_ERR("async rx: packet too large: %u", rx_len);
		} else {
			buf_read(cfg, REG_RX_BUFFER, drv->rx_buf, rx_len);
			rssi = (int16_t)reg_read(cfg, REG_RX_RSSI);
			snr = (int8_t)((int16_t)reg_read(cfg, REG_RX_SNR) / 10);
			reg_write(cfg, REG_RX_CONSUME, 1);

			LOG_DBG("async RX: %u bytes, RSSI=%d, SNR=%d",
				rx_len, rssi, snr);
			cb(dev, drv->rx_buf, rx_len, rssi, snr, cb_user_data);
		}
	}

	/* Re-arm unless cancelled during delivery (rx_lock snapshot now shows
	 * a disarmed callback). */
	key = k_spin_lock(&drv->rx_lock);
	bool armed = drv->recv_cb != NULL;

	k_spin_unlock(&drv->rx_lock, key);
	if (armed) {
		k_work_reschedule(&drv->rx_poll, K_MSEC(RENODE_RX_POLL_MS));
	}
}

static int lora_renode_recv_async(const struct device *dev,
				  lora_recv_cb cb, void *user_data)
{
	struct lora_renode_data *drv = dev->data;

	if (cb == NULL) {
		k_spinlock_key_t key = k_spin_lock(&drv->rx_lock);
		bool was_armed = drv->recv_cb != NULL;

		drv->recv_cb = NULL;
		drv->recv_cb_user_data = NULL;
		k_spin_unlock(&drv->rx_lock, key);

		if (!was_armed) {
			return -EINVAL;
		}
		/* Quiesce the poller before releasing the modem so a sync
		 * recv that follows cannot race a mid-run poll. Waiting is
		 * forbidden from the sysworkq itself (self-cancel from the
		 * callback): there the poller's own re-checks honor the
		 * disarm and its tail stops rescheduling. */
		if (k_current_get() == &k_sys_work_q.thread) {
			k_work_cancel_delayable(&drv->rx_poll);
		} else {
			struct k_work_sync ws;

			k_work_cancel_delayable_sync(&drv->rx_poll, &ws);
		}
		renode_modem_release(drv);
		return 0;
	}

	if (!renode_modem_acquire(drv)) {
		return -EBUSY;
	}

	k_spinlock_key_t key = k_spin_lock(&drv->rx_lock);

	drv->recv_cb = cb;
	drv->recv_cb_user_data = user_data;
	k_spin_unlock(&drv->rx_lock, key);

	k_work_reschedule(&drv->rx_poll, K_NO_WAIT);
	return 0;
}

static const struct lora_driver_api lora_renode_api = {
	.config     = lora_renode_config,
	.send       = lora_renode_send,
	.send_async = lora_renode_send_async,
	.recv       = lora_renode_recv,
	.recv_async = lora_renode_recv_async,
	.test_cw    = NULL,
};

#define LORA_RENODE_DEFINE(inst)					\
	static const struct lora_renode_config lora_renode_config_##inst = { \
		.base = (volatile uint32_t *)DT_INST_REG_ADDR(inst),	\
	};								\
	static struct lora_renode_data lora_renode_data_##inst;		\
	DEVICE_DT_INST_DEFINE(inst, lora_renode_init, NULL,		\
			      &lora_renode_data_##inst,			\
			      &lora_renode_config_##inst,		\
			      POST_KERNEL, CONFIG_LORA_INIT_PRIORITY,	\
			      &lora_renode_api);

DT_INST_FOREACH_STATUS_OKAY(LORA_RENODE_DEFINE)

int sx1302_read_register(uint16_t address, uint8_t *buffer, uint16_t size) {
	return 0;
}
int sx1302_write_register(uint16_t address, const uint8_t *buffer, uint16_t size) {
	return 0;
}
