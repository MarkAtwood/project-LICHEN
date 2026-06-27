/*
 * LICHEN LoRa Bridge - Zephyr version
 * IPv6 mesh networking over LoRa.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>

#if defined(CONFIG_USB_DEVICE_STACK)
#include <zephyr/usb/usb_device.h>
#endif

#if defined(CONFIG_LICHEN_LORA_L2)
#include "lora_l2.h"
#endif

#if defined(CONFIG_LICHEN_IPV6)
#include "ipv6_addr.h"
#endif

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

/* LED (optional - not all boards have one) */
#if DT_NODE_EXISTS(DT_ALIAS(led0))
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
#define HAS_LED 1
#endif

#if defined(CONFIG_LICHEN_LORA_L2)
/**
 * @brief Handle received LoRa packets
 */
static void lora_rx_handler(const uint8_t *data, size_t len,
                            int16_t rssi, int8_t snr, void *user_data)
{
    ARG_UNUSED(user_data);

    LOG_INF("RX: %zu bytes, RSSI=%d dBm, SNR=%d dB", len, rssi, snr);

    /*
     * Future: Parse LICHEN frame, verify signature, check replay,
     * decompress SCHC, inject into IPv6 stack.
     */
}
#endif

int main(void)
{
    int ret;

    LOG_INF("LICHEN bridge (Zephyr) starting...");

#if defined(HAS_LED)
    if (gpio_is_ready_dt(&led)) {
        gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
        gpio_pin_set_dt(&led, 1);
    }
#endif

#if defined(CONFIG_USB_DEVICE_STACK)
    ret = usb_enable(NULL);
    if (ret != 0) {
        LOG_ERR("USB enable failed: %d", ret);
    }
    k_sleep(K_MSEC(1000));
    LOG_INF("USB CDC ready");
#else
    LOG_INF("UART console ready");
#endif

#if defined(CONFIG_LICHEN_LORA_L2)
    /* Initialize LoRa L2 layer */
    ret = lichen_lora_l2_init();
    if (ret < 0) {
        LOG_ERR("LoRa L2 init failed: %d", ret);
        goto main_loop;
    }

    /* Set up RX callback */
    lichen_lora_l2_set_rx_callback(lora_rx_handler, NULL);

    /* Start LoRa L2 */
    ret = lichen_lora_l2_start();
    if (ret < 0) {
        LOG_ERR("LoRa L2 start failed: %d", ret);
        goto main_loop;
    }

    /* Log our link-layer address */
    const uint8_t *eui64 = lichen_lora_l2_get_eui64();
    LOG_INF("EUI-64: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            eui64[0], eui64[1], eui64[2], eui64[3],
            eui64[4], eui64[5], eui64[6], eui64[7]);

#if defined(CONFIG_LICHEN_IPV6)
    /* Derive and log link-local address */
    uint8_t iid[8];
    struct in6_addr ll_addr;
    char addr_str[LICHEN_IPV6_ADDR_STR_LEN];
    lichen_eui64_to_iid(eui64, iid);
    lichen_make_link_local(iid, &ll_addr);
    lichen_ipv6_addr_to_str(&ll_addr, addr_str, sizeof(addr_str));
    LOG_INF("Link-local: %s", addr_str);
#endif

    LOG_INF("LoRa L2 active: SF10, BW125, 915MHz");
#endif /* CONFIG_LICHEN_LORA_L2 */

#if defined(HAS_LED)
    if (gpio_is_ready_dt(&led)) {
        gpio_pin_set_dt(&led, 0);
    }
#endif

main_loop:
    LOG_INF("Ready - LICHEN IPv6/LoRa mesh");

    while (1) {
        k_sleep(K_SECONDS(60));
        LOG_DBG("tick");
    }

    return 0;
}
