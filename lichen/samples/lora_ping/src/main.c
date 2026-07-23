/*
 * Simple LoRa ping test - transmits a packet and waits for response.
 * Used to verify LoRa driver works in Renode + lichen-sim.
 *
 * Emits lichen.telemetry.v1 JSONL for cross-implementation fleet analysis.
 * Hash format: first 16 bytes of SHA-256 as 32-char hex (matches Python/Rust).
 *
 * Note: This sample calls lora_config() on each TX/RX switch for clarity.
 * Production code would use lora_set_mode() which is lighter weight, but
 * the full config call is preferred here because:
 * 1. It exercises the complete driver configuration path
 * 2. It's more explicit about what's being changed
 * 3. Performance is not critical for this test sample
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <string.h>
#include <tinycrypt/sha256.h>

LOG_MODULE_REGISTER(lora_ping, LOG_LEVEL_DBG);

BUILD_ASSERT(DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_lora), okay),
	     "lora_ping requires an enabled devicetree chosen zephyr,lora");

/* 32-char hex = first 16 bytes of SHA-256 */
#define HASH_HEX_LEN 32

/*
 * Node ID derivation:
 * In Renode fleet tests, each nRF52840 instance gets a unique DEVICEID[0]
 * value set via sysbus Tag (0x1CE00000 + NID). On real hardware DEVICEID
 * is a factory-programmed unique identifier. We extract NID from the low
 * bits and fall back to a default on platforms without FICR.
 *
 * DEVICEID[0] base address in nRF52840 FICR is 0x10000060.
 * Renode sets: DEVICEID[0] = 0x1CE00000 + NID  (NID starts at 3000)
 */
#define NRF_FICR_DEVICEID0  (*(volatile uint32_t *)0x10000060)
#define RENODE_DEVICEID_BASE  0x1CE00000UL
#define DEFAULT_NODE_ID       3000

/* Derive node identifier from hardware or fallback */
static uint32_t get_node_id(void)
{
	uint32_t devid = NRF_FICR_DEVICEID0;
	if (devid >= RENODE_DEVICEID_BASE &&
	    devid < RENODE_DEVICEID_BASE + 10000) {
		return devid - RENODE_DEVICEID_BASE;
	}
	return DEFAULT_NODE_ID;
}

/* Packet telemetry metrics */
static struct {
	uint32_t tx_count;
	uint32_t rx_count;
	uint32_t tx_bytes;
	uint32_t rx_bytes;
	uint32_t errors;
	uint32_t unique_hashes_seen;
	uint32_t unique_hashes_dropped;
	/* Simple hash set (fixed size for embedded) */
	char seen_hashes[64][HASH_HEX_LEN + 1];
	uint8_t seen_hash_count;
} metrics;

/* Compute packet hash: first 16 bytes of SHA-256 as 32-char hex */
static void packet_hash(const uint8_t *data, size_t len,
			char out[HASH_HEX_LEN + 1])
{
	uint8_t raw[TC_SHA256_DIGEST_SIZE];
	struct tc_sha256_state_struct state;
	tc_sha256_init(&state);
	if (len > 0) {
		tc_sha256_update(&state, data, len);
	}
	tc_sha256_final(raw, &state);
	for (int i = 0; i < 16; i++) {
		sprintf(&out[i * 2], "%02x", raw[i]);
	}
	out[HASH_HEX_LEN] = '\0';
}

/* Emit lichen.telemetry.v1 JSONL line */
static void emit_telemetry(const char *node_id, const char *direction,
			   const char *hash, int64_t ts_us,
			   size_t payload_len, int16_t rssi, int8_t snr,
			   const char *status)
{
	printk("TELEMETRY "
	       "{\"schema\":\"lichen.telemetry.v1\","
	       "\"event\":\"%s\","
	       "\"ts_us\":%lld,"
	       "\"node_id\":\"%s\","
	       "\"impl\":\"zephyr\","
	       "\"tx_id\":\"%s\","
	       "\"packet_hash\":\"%s\","
	       "\"direction\":\"%s\","
	       "\"payload_len\":%zu,"
	       "\"rssi_dbm\":%d,"
	       "\"snr_db\":%d,"
	       "\"status\":\"%s\""
	       "}\n",
	       direction, (long long)ts_us,
	       node_id, hash, hash,
	       direction,
	       payload_len, rssi, snr,
	       status);
}

/* Track unique packets by hash string */
static void track_hash(const char *hash)
{
	for (int i = 0; i < metrics.seen_hash_count; i++) {
		if (strcmp(metrics.seen_hashes[i], hash) == 0) {
			return;
		}
	}
	if (metrics.seen_hash_count < ARRAY_SIZE(metrics.seen_hashes)) {
		strncpy(metrics.seen_hashes[metrics.seen_hash_count], hash,
			HASH_HEX_LEN);
		metrics.seen_hashes[metrics.seen_hash_count][HASH_HEX_LEN] = '\0';
		metrics.seen_hash_count++;
		metrics.unique_hashes_seen++;
	} else {
		metrics.unique_hashes_dropped++;
	}
}

/* Log metrics summary */
static void log_metrics(void)
{
	LOG_INF("METRICS: tx=%u rx=%u tx_bytes=%u rx_bytes=%u errors=%u unique=%u dropped=%u",
		metrics.tx_count, metrics.rx_count,
		metrics.tx_bytes, metrics.rx_bytes,
		metrics.errors, metrics.unique_hashes_seen, metrics.unique_hashes_dropped);
}

/* Parse announce packet to extract peer IID */
static void parse_announce(const uint8_t *data, size_t len)
{
	/* Announce format: dispatch=0x15, type=0x01, iid at offset 5 */
	if (len >= 13 && data[0] == 0x15 && data[1] == 0x01) {
		const uint8_t *peer_iid = &data[5];
		LOG_INF("[RX] announce from %02x%02x%02x%02x%02x%02x%02x%02x",
			peer_iid[0], peer_iid[1], peer_iid[2], peer_iid[3],
			peer_iid[4], peer_iid[5], peer_iid[6], peer_iid[7]);
	}
}

int main(void)
{
	const struct device *lora = DEVICE_DT_GET(DT_CHOSEN(zephyr_lora));
	struct lora_modem_config config = {
		.frequency = 915000000,
		.bandwidth = BW_125_KHZ,
		.datarate = SF_10,
		.coding_rate = CR_4_5,
		.preamble_len = 8,
		.tx_power = 14,
		.tx = true,
	};
	int ret;

	if (!device_is_ready(lora)) {
		LOG_ERR("LoRa device not ready");
		return -1;
	}

	ret = lora_config(lora, &config);
	if (ret < 0) {
		LOG_ERR("lora_config failed: %d", ret);
		return ret;
	}

	LOG_INF("LoRa configured, starting ping loop");

	uint8_t tx_buf[] = "PING";
	uint8_t rx_buf[64];
	int16_t rssi;
	int8_t snr;
	int count = 0;
	char hash_hex[HASH_HEX_LEN + 1];
	char node_id[32];
	int64_t ts_us;

	snprintk(node_id, sizeof(node_id), "zephyr-%u", get_node_id());

	while (1) {
		/* TX path with telemetry */
		count++;
		ts_us = k_cyc_to_us_floor32(k_cycle_get_32());
		packet_hash(tx_buf, sizeof(tx_buf) - 1, hash_hex);
		emit_telemetry(node_id, "tx", hash_hex, ts_us,
			       sizeof(tx_buf) - 1, 0, 0, "ok");
		LOG_INF("[TX] len=%zu hash=%s PING #%d",
			sizeof(tx_buf) - 1, hash_hex, count);
		LOG_HEXDUMP_DBG(tx_buf, sizeof(tx_buf) - 1, "TX payload");

		ret = lora_send(lora, tx_buf, sizeof(tx_buf) - 1);
		if (ret < 0) {
			LOG_ERR("lora_send failed: %d", ret);
			metrics.errors++;
			emit_telemetry(node_id, "tx", hash_hex, ts_us,
				       sizeof(tx_buf) - 1, 0, 0, "fail");
		} else {
			LOG_INF("TX done");
			metrics.tx_count++;
			metrics.tx_bytes += sizeof(tx_buf) - 1;
			track_hash(hash_hex);
		}

		/* Wait for response */
		config.tx = false;
		ret = lora_config(lora, &config);
		if (ret < 0) {
			LOG_ERR("lora_config (RX) failed: %d", ret);
			metrics.errors++;
			continue;
		}

		ret = lora_recv(lora, rx_buf, sizeof(rx_buf),
				K_SECONDS(5), &rssi, &snr);
		if (ret > 0) {
			/* RX path with telemetry */
			ts_us = k_cyc_to_us_floor32(k_cycle_get_32());
			packet_hash(rx_buf, ret, hash_hex);
			emit_telemetry(node_id, "rx", hash_hex, ts_us,
				       (size_t)ret, rssi, snr, "ok");
			LOG_INF("[RX] len=%d rssi=%d snr=%d hash=%s",
				ret, rssi, snr, hash_hex);
			LOG_HEXDUMP_DBG(rx_buf, ret, "RX payload");

			metrics.rx_count++;
			metrics.rx_bytes += ret;
			track_hash(hash_hex);

			/* Parse announce packets for peer IID */
			parse_announce(rx_buf, ret);
		} else if (ret == -EAGAIN) {
			LOG_INF("RX timeout");
		} else {
			LOG_ERR("lora_recv failed: %d", ret);
			metrics.errors++;
		}

		config.tx = true;
		ret = lora_config(lora, &config);
		if (ret < 0) {
			LOG_ERR("lora_config (TX) failed: %d", ret);
			metrics.errors++;
			continue;
		}

		/* Log metrics every 5 iterations */
		if (count % 5 == 0) {
			log_metrics();
		}

		k_sleep(K_SECONDS(2));
	}

	return 0;
}
