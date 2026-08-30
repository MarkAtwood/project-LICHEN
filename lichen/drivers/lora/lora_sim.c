/*
 * LICHEN simulator LoRa driver for Zephyr native_sim.
 *
 * Connects to the Python/Rust lichen-sim server over TCP and implements the
 * Zephyr LoRa API on top of the simulator wire protocol.
 *
 * Wire protocol (all integers little-endian, 4-byte length-prefixed frames):
 *   REGISTER 0x01: [1B sim_id_len][sim_id][1B node_id_len][node_id][24B xyz]
 *   OK       0x00
 *   TX       0x10: [2B payload_len][payload]
 *   TX_DONE  0x11: [4B airtime_us]
 *   TX_FAIL  0x12
 *   RX       0x20: [4B timeout_ms]
 *   RX_OK    0x21: [2B payload_len][payload][2B rssi_s16][2B snr_s16]
 *   RX_TIMEOUT 0x22
 *   RX_ENTER 0x24: [4B timeout_us][1B channel] — arm one push RX window
 *   RX_EXIT  0x26: end push RX mode (unused here; windows self-expire)
 *   RX_PACKET 0x27: [2B payload_len][payload][2B rssi_s16][2B snr_s16]
 *   RX_TIMEOUT_PUSH 0x28
 *   ERR      0xFF: [1B code][1B msg_len][msg]
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
#include <lichen/lora_cad.h>
#endif

LOG_MODULE_REGISTER(lora_sim, CONFIG_LORA_LOG_LEVEL);

#define DT_DRV_COMPAT lichen_lora_sim

/* Message type bytes */
#define MSG_OK         0x00
#define MSG_REGISTER   0x01
#define MSG_TX         0x10
#define MSG_TX_DONE    0x11
#define MSG_TX_FAIL    0x12
#define MSG_RX         0x20
#define MSG_RX_OK      0x21
#define MSG_RX_TIMEOUT 0x22
#define MSG_RX_ENTER   0x24
#define MSG_RX_PACKET  0x27
#define MSG_RX_TIMEOUT_PUSH 0x28
#define MSG_ERR        0xFF

/* Maximum receive buffer for a single frame (256-byte LoRa payload + headers) */
#define RX_BUF_MAX 320

/* Socket timeout in milliseconds - prevents indefinite blocking on disconnected simulator */
#define SOCKET_TIMEOUT_MS 5000

/* Push-protocol RX window per exchange. The server replies with exactly one
 * frame (RX_PACKET or RX_TIMEOUT_PUSH) per RX_ENTER, so a window bounds both
 * the re-arm gap and the cancel latency. */
#define SIM_RX_WINDOW_MS 200

/* Async RX thread: runs push-protocol RX windows and delivers frames to the
 * registered callback. Spawned on first arm, parked on rx_go when disarmed. */
#define SIM_RX_STACK_SIZE CONFIG_LORA_LICHEN_SIM_RX_THREAD_STACK_SIZE

struct lora_sim_data {
	int fd;
	struct k_sem rx_go;
	struct k_spinlock rx_lock;
	lora_recv_cb recv_cb;
	const struct device *dev;
	bool rx_thread_started;
	struct k_thread rx_thread;
	atomic_t modem_usage;
	K_KERNEL_STACK_MEMBER(rx_stack, SIM_RX_STACK_SIZE);
};

/* Upstream sx12xx-style single-operation lock: acquire succeeds only when the
 * modem was idle. An armed async RX holds the lock until cancelled, so sync
 * send/recv (which share the request/response TCP framing) return -EBUSY
 * while armed — no interleaved exchanges on the socket. CAS so a losing
 * contender leaves the counter untouched. */
static bool sim_modem_acquire(struct lora_sim_data *drv)
{
	return atomic_cas(&drv->modem_usage, 0, 1);
}

static void sim_modem_release(struct lora_sim_data *drv)
{
	atomic_dec(&drv->modem_usage);
}

/* EAGAIN and EWOULDBLOCK are the same value on native_sim (Linux); guard the
 * comparison so -Wlogical-op stays quiet where they are equal. */
static inline bool sock_would_block(void)
{
#if EAGAIN == EWOULDBLOCK
	return errno == EAGAIN;
#else
	return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

/* --- framing ------------------------------------------------------------ */

static int send_exact(int fd, const uint8_t *buf, int len)
{
	while (len > 0) {
		int n = zsock_send(fd, buf, len, 0);

		if (n < 0) {
			if (sock_would_block()) {
				LOG_ERR("send timeout - simulator may be disconnected");
				return -ETIMEDOUT;
			}
			LOG_ERR("send error: %d", errno);
			return -EIO;
		}
		if (n == 0) {
			LOG_ERR("send: connection closed by simulator");
			return -ECONNRESET;
		}
		buf += n;
		len -= n;
	}
	return 0;
}

static int recv_exact(int fd, uint8_t *buf, int len)
{
	while (len > 0) {
		int n = zsock_recv(fd, buf, len, MSG_WAITALL);

		if (n < 0) {
			if (sock_would_block()) {
				LOG_ERR("recv timeout - simulator may be disconnected");
				return -ETIMEDOUT;
			}
			LOG_ERR("recv error: %d", errno);
			return -EIO;
		}
		if (n == 0) {
			LOG_ERR("recv: connection closed by simulator");
			return -ECONNRESET;
		}
		buf += n;
		len -= n;
	}
	return 0;
}

static int drain_exact(int fd, uint32_t len)
{
	uint8_t discard[64];

	while (len > 0) {
		int chunk = (int)len;

		if (chunk > (int)sizeof(discard)) {
			chunk = (int)sizeof(discard);
		}

		if (recv_exact(fd, discard, chunk) < 0) {
			return -EIO;
		}
		len -= (uint32_t)chunk;
	}
	return 0;
}

static int write_frame(int fd, const uint8_t *payload, uint32_t len)
{
	uint8_t hdr[4];

	sys_put_le32(len, hdr);
	if (send_exact(fd, hdr, 4) < 0) {
		return -EIO;
	}
	return send_exact(fd, payload, len);
}

/* Read length-prefix, return number of bytes placed into buf. */
static int read_frame(int fd, uint8_t *buf, uint32_t buf_size)
{
	uint8_t hdr[4];

	if (recv_exact(fd, hdr, 4) < 0) {
		return -EIO;
	}
	uint32_t len = sys_get_le32(hdr);

	if (len > buf_size) {
		LOG_ERR("frame too large: %u > %u", len, buf_size);
		if (drain_exact(fd, len) < 0) {
			LOG_ERR("failed to drain oversized frame");
			return -EIO;
		}
		return -ENOMEM;
	}
	if (recv_exact(fd, buf, len) < 0) {
		return -EIO;
	}
	return (int)len;
}

/* --- init: connect + REGISTER ------------------------------------------ */

static int lora_sim_connect(struct lora_sim_data *data)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port   = htons(CONFIG_LORA_LICHEN_SIM_PORT),
	};
	struct zsock_timeval tv = {
		.tv_sec  = SOCKET_TIMEOUT_MS / 1000,
		.tv_usec = (SOCKET_TIMEOUT_MS % 1000) * 1000,
	};

	zsock_inet_pton(AF_INET, CONFIG_LORA_LICHEN_SIM_HOST, &addr.sin_addr);

	data->fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (data->fd < 0) {
		LOG_ERR("socket() failed: %d", errno);
		return -errno;
	}

	/* Set socket timeouts to prevent indefinite blocking on disconnected simulator.
	 * This is critical for Zephyr cooperative threads where blocking forever
	 * freezes the entire system.
	 */
	if (zsock_setsockopt(data->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		LOG_WRN("setsockopt(SO_RCVTIMEO) failed: %d", errno);
	}
	if (zsock_setsockopt(data->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
		LOG_WRN("setsockopt(SO_SNDTIMEO) failed: %d", errno);
	}

	if (zsock_connect(data->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOG_ERR("connect() to %s:%d failed: %d",
			CONFIG_LORA_LICHEN_SIM_HOST,
			CONFIG_LORA_LICHEN_SIM_PORT, errno);
		zsock_close(data->fd);
		data->fd = -1;
		return -errno;
	}
	LOG_INF("connected to simulator at %s:%d",
		CONFIG_LORA_LICHEN_SIM_HOST, CONFIG_LORA_LICHEN_SIM_PORT);
	return 0;
}

static int lora_sim_register(struct lora_sim_data *data)
{
	static const char sim_id[]  = CONFIG_LORA_LICHEN_SIM_SIM_ID;
	static const char node_id[] = CONFIG_LORA_LICHEN_SIM_NODE_ID;
	uint8_t buf[256];
	int off = 0;
	size_t sim_id_len = strlen(sim_id);
	size_t node_id_len = strlen(node_id);

	/* Validate string lengths fit in uint8_t and total message fits in buffer.
	 * Message format: 1B type + 1B sim_id_len + sim_id + 1B node_id_len + node_id + 24B xyz
	 * Maximum usable space for strings: 256 - 1 - 1 - 1 - 24 = 229 bytes
	 */
	if (sim_id_len > 255 || node_id_len > 255) {
		LOG_ERR("sim_id or node_id exceeds 255 bytes");
		return -EINVAL;
	}
	if (1 + 1 + sim_id_len + 1 + node_id_len + 24 > sizeof(buf)) {
		LOG_ERR("REGISTER message too large: sim_id=%zu + node_id=%zu exceeds buffer",
			sim_id_len, node_id_len);
		return -EMSGSIZE;
	}

	buf[off++] = MSG_REGISTER;
	buf[off++] = (uint8_t)sim_id_len;
	memcpy(buf + off, sim_id, sim_id_len);
	off += sim_id_len;
	buf[off++] = (uint8_t)node_id_len;
	memcpy(buf + off, node_id, node_id_len);
	off += node_id_len;
	/* Position: (0.0, 0.0, 0.0) as three IEEE 754 doubles, little-endian */
	memset(buf + off, 0, 24);
	off += 24;

	if (write_frame(data->fd, buf, off) < 0) {
		return -EIO;
	}

	uint8_t resp[64];
	int n = read_frame(data->fd, resp, sizeof(resp));

	if (n < 1) {
		return -EIO;
	}
	if (resp[0] != MSG_OK) {
		LOG_ERR("REGISTER rejected (type=0x%02x)", resp[0]);
		return -EPROTO;
	}
	LOG_INF("registered as node_id=\"%s\"", node_id);
	return 0;
}

/* --- LoRa API callbacks ------------------------------------------------- */

static int lora_sim_config(const struct device *dev,
			   struct lora_modem_config *config)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(config);
	/* Simulator ignores RF config; the medium model controls propagation. */
	return 0;
}

static int lora_sim_send(const struct device *dev,
			 uint8_t *data, uint32_t data_len)
{
	if (dev == NULL || data == NULL) {
		return -EINVAL;
	}
	struct lora_sim_data *drv = dev->data;

	if (drv->fd < 0) {
		LOG_ERR("send: not connected to simulator");
		return -ENOTCONN;
	}
	if (!sim_modem_acquire(drv)) {
		/* An armed async RX holds the modem. */
		return -EBUSY;
	}
	uint8_t buf[256 + 3];
	int off = 0;
	int ret;

	if (data_len > 255) {
		sim_modem_release(drv);
		return -EMSGSIZE;
	}
	buf[off++] = MSG_TX;
	sys_put_le16((uint16_t)data_len, buf + off);
	off += 2;
	memcpy(buf + off, data, data_len);
	off += data_len;

	ret = -EIO;
	if (write_frame(drv->fd, buf, off) < 0) {
		goto out;
	}

	uint8_t resp[8];
	int n = read_frame(drv->fd, resp, sizeof(resp));

	if (n < 1) {
		goto out;
	}
	if (resp[0] == MSG_TX_DONE) {
		LOG_DBG("TX successful: %u bytes", data_len);
		ret = 0;
		goto out;
	}
	if (resp[0] == MSG_TX_FAIL) {
		LOG_ERR("TX failed: %u bytes", data_len);
		ret = -EIO;
		goto out;
	}
	LOG_ERR("unexpected TX response: 0x%02x", resp[0]);
	ret = -EPROTO;
out:
	sim_modem_release(drv);
	return ret;
}

static int lora_sim_recv(const struct device *dev,
			 uint8_t *data, uint8_t size,
			 k_timeout_t timeout,
			 int16_t *rssi, int8_t *snr)
{
	if (dev == NULL || data == NULL || size == 0) {
		return -EINVAL;
	}

	struct lora_sim_data *drv = dev->data;

	if (drv->fd < 0) {
		LOG_ERR("recv: not connected to simulator");
		return -ENOTCONN;
	}
	if (!sim_modem_acquire(drv)) {
		/* An armed async RX holds the modem. */
		return -EBUSY;
	}

	/* K_FOREVER sends 0xFFFFFFFF as the explicit "wait forever" marker.
	 * The server interprets this as infinite timeout.
	 */
	bool forever = K_TIMEOUT_EQ(timeout, K_FOREVER);
	uint32_t timeout_ms = forever ? UINT32_MAX : k_ticks_to_ms_floor32(timeout.ticks);
	uint8_t req[5];
	int ret;

	req[0] = MSG_RX;
	sys_put_le32(timeout_ms, req + 1);

	ret = -EIO;
	if (write_frame(drv->fd, req, sizeof(req)) < 0) {
		goto out;
	}

	uint8_t buf[RX_BUF_MAX];
	int n = read_frame(drv->fd, buf, sizeof(buf));

	if (n < 1) {
		goto out;
	}
	if (buf[0] == MSG_RX_TIMEOUT) {
		LOG_DBG("RX timeout");
		ret = -EAGAIN;
		goto out;
	}
	if (buf[0] != MSG_RX_OK) {
		LOG_ERR("unexpected RX response: 0x%02x", buf[0]);
		ret = -EPROTO;
		goto out;
	}
	if (n < 5) {
		ret = -EPROTO;
		goto out;
	}
	uint16_t payload_len = sys_get_le16(buf + 1);

	if (n < (int)(3 + payload_len + 4)) {
		ret = -EPROTO;
		goto out;
	}
	if (payload_len > size) {
		LOG_ERR("recv: packet too large for buffer: %u > %u", payload_len, size);
		ret = -EMSGSIZE;
		goto out;
	}

	memcpy(data, buf + 3, payload_len);

	if (rssi) {
		*rssi = (int16_t)sys_get_le16(buf + 3 + payload_len);
	}
	if (snr) {
		*snr = (int8_t)((int16_t)sys_get_le16(buf + 3 + payload_len + 2) / 10);
	}
	LOG_DBG("RX successful: %u bytes, rssi=%d, snr=%d", payload_len,
		rssi ? *rssi : 0, snr ? *snr : 0);
	ret = payload_len;
out:
	sim_modem_release(drv);
	return ret;
}

/* --- device init -------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
static int lora_sim_cad(const struct device *dev, k_timeout_t timeout,
			 bool *busy);
#endif

static int lora_sim_init(const struct device *dev)
{
	struct lora_sim_data *data = dev->data;
	int rc;

	data->fd = -1;
	data->dev = dev;
	data->recv_cb = NULL;
	data->rx_thread_started = false;
	data->modem_usage = 0;
	k_sem_init(&data->rx_go, 0, 1);

	rc = lora_sim_connect(data);
	if (rc < 0) {
		return rc;
	}
	rc = lora_sim_register(data);
	if (rc < 0) {
		zsock_close(data->fd);
		data->fd = -1;
		return rc;
	}
#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
	rc = lichen_lora_cad_register(dev, lora_sim_cad);
	if (rc < 0) {
		zsock_close(data->fd);
		data->fd = -1;
		return rc;
	}
#endif
	return 0;
}

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
static int lora_sim_cad(const struct device *dev, k_timeout_t timeout,
			 bool *busy)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(timeout);
	if (busy == NULL) {
		return -EINVAL;
	}
	*busy = false; /* simulator assumes clear for testing */
	return 0;
}
#endif

static int lora_sim_send_async(const struct device *dev, uint8_t *data,
			       uint32_t data_len, struct k_poll_signal *async)
{
	ARG_UNUSED(async);
	return lora_sim_send(dev, data, data_len);
}

/* Consecutive failed exchanges before the RX thread disarms itself. The
 * modem is released so sync paths recover; the next recv_async() arm
 * retries the connection path. */
#define SIM_RX_MAX_EXCHANGE_FAILURES 10

/* Async RX thread body. Each armed cycle runs bounded push-protocol RX
 * windows (RX_ENTER → one of RX_PACKET / RX_TIMEOUT_PUSH) until disarmed.
 * The modem lock is held for the whole armed period — acquired by the
 * arming call and released by this thread when it parks — so sync
 * send/recv can never interleave exchanges on the shared socket, and a
 * cancel that returns 0 is fully quiesced once the lock frees. */
static void lora_sim_rx_thread_fn(void *p1, void *p2, void *p3)
{
	const struct device *dev = p1;
	struct lora_sim_data *drv = dev->data;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (k_sem_take(&drv->rx_go, K_FOREVER) == 0) {
		int failures = 0;

		while (true) {
			k_spinlock_key_t key = k_spin_lock(&drv->rx_lock);
			lora_recv_cb cb = drv->recv_cb;

			k_spin_unlock(&drv->rx_lock, key);
			if (cb == NULL) {
				break;
			}

			uint8_t req[6];

			req[0] = MSG_RX_ENTER;
			sys_put_le32(SIM_RX_WINDOW_MS * 1000U, req + 1);
			req[5] = 0; /* channel */

			int rc = write_frame(drv->fd, req, sizeof(req));
			uint8_t buf[RX_BUF_MAX];
			int n = (rc == 0) ? read_frame(drv->fd, buf, sizeof(buf)) : -EIO;

			if (n < 1) {
				failures++;
				if (failures >= SIM_RX_MAX_EXCHANGE_FAILURES) {
					LOG_ERR("async rx: %d consecutive "
						"exchange failures, disarming",
						failures);
					break;
				}
				LOG_WRN("async rx: exchange failed (%d), retrying", n);
				k_sleep(K_MSEC(100));
				continue;
			}
			failures = 0;

			if (buf[0] == MSG_RX_TIMEOUT_PUSH) {
				continue;
			}
			if (buf[0] != MSG_RX_PACKET) {
				LOG_ERR("async rx: unexpected response 0x%02x", buf[0]);
				k_sleep(K_MSEC(100));
				continue;
			}
			if (n < 3) {
				LOG_ERR("async rx: short RX_PACKET");
				continue;
			}
			uint16_t payload_len = sys_get_le16(buf + 1);

			if (n < (int)(3 + payload_len + 4)) {
				LOG_ERR("async rx: truncated RX_PACKET");
				continue;
			}
			int16_t rssi = (int16_t)sys_get_le16(buf + 3 + payload_len);
			int16_t snr_x10 = (int16_t)sys_get_le16(buf + 3 + payload_len + 2);

			/* Re-check under the lock: a cancel that landed while
			 * this window was in flight must not deliver. */
			key = k_spin_lock(&drv->rx_lock);
			cb = drv->recv_cb;
			k_spin_unlock(&drv->rx_lock, key);
			if (cb == NULL) {
				break;
			}

			LOG_DBG("async RX: %u bytes, rssi=%d, snr=%d",
				payload_len, rssi, snr_x10 / 10);
			cb(dev, buf + 3, payload_len, rssi,
			   (int8_t)(snr_x10 / 10));
		}

		/* Disarm (including self-disarm on dead link) and free the
		 * modem so sync paths recover. */
		k_spinlock_key_t key = k_spin_lock(&drv->rx_lock);

		drv->recv_cb = NULL;
		k_spin_unlock(&drv->rx_lock, key);
		sim_modem_release(drv);
	}
}

static int lora_sim_recv_async(const struct device *dev, lora_recv_cb cb)
{
	if (dev == NULL) {
		return -EINVAL;
	}
	struct lora_sim_data *drv = dev->data;

	if (cb == NULL) {
		k_spinlock_key_t key = k_spin_lock(&drv->rx_lock);
		bool was_armed = drv->recv_cb != NULL;

		drv->recv_cb = NULL;
		k_spin_unlock(&drv->rx_lock, key);

		if (!was_armed) {
			return -EINVAL;
		}
		/* Do NOT release the modem here: the RX thread may still be
		 * inside a window exchange on the shared socket. It releases
		 * the lock itself when it parks, so sync paths stay excluded
		 * until the socket is genuinely idle (bounded by
		 * SIM_RX_WINDOW_MS under a live server). The server closes
		 * the window itself after the pending RX_ENTER completes, so
		 * no RX_EXIT is written (it would race the thread's writes). */
		return 0;
	}

	if (drv->fd < 0) {
		return -ENOTCONN;
	}
	if (!sim_modem_acquire(drv)) {
		return -EBUSY;
	}

	/* Spawn the RX thread once. The modem lock serializes arming, so
	 * this needs no separate guard against a concurrent spawner; keep
	 * k_thread_create outside any spinlock (it does allocations and
	 * ready-queue work). */
	if (!drv->rx_thread_started) {
		k_thread_create(&drv->rx_thread, drv->rx_stack,
				K_THREAD_STACK_SIZEOF(drv->rx_stack),
				lora_sim_rx_thread_fn, (void *)dev, NULL, NULL,
				CONFIG_LORA_LICHEN_SIM_RX_THREAD_PRIORITY, 0,
				K_NO_WAIT);
		k_thread_name_set(&drv->rx_thread, "lora_sim_rx");
		drv->rx_thread_started = true;
	}

	k_spinlock_key_t key = k_spin_lock(&drv->rx_lock);

	drv->recv_cb = cb;
	k_spin_unlock(&drv->rx_lock, key);

	k_sem_give(&drv->rx_go);
	return 0;
}

static const struct lora_driver_api lora_sim_api = {
	.config     = lora_sim_config,
	.send       = lora_sim_send,
	.send_async = lora_sim_send_async,
	.recv       = lora_sim_recv,
	.recv_async = lora_sim_recv_async,
	.test_cw    = NULL,
};

#define LORA_SIM_DEFINE(inst)						\
	static struct lora_sim_data lora_sim_data_##inst;		\
	DEVICE_DT_INST_DEFINE(inst, lora_sim_init, NULL,		\
			      &lora_sim_data_##inst, NULL,		\
			      POST_KERNEL, CONFIG_LORA_INIT_PRIORITY,	\
			      &lora_sim_api);

DT_INST_FOREACH_STATUS_OKAY(LORA_SIM_DEFINE)
