/*
 * LICHEN LoRa Bridge - Zephyr version
 * Minimal "hello world" that initializes serial console and SX1262 radio.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>

#if defined(CONFIG_USB_DEVICE_STACK)
#include <zephyr/usb/usb_device.h>
#endif

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

/* LED (optional - not all boards have one) */
#if DT_NODE_EXISTS(DT_ALIAS(led0))
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
#define HAS_LED 1
#endif

/* LoRa device */
#define LORA_DEV DEVICE_DT_GET(DT_ALIAS(lora0))

/* LICHEN default config: SF10, BW125, 915MHz */
static struct lora_modem_config lora_cfg = {
    .frequency = 915000000,
    .bandwidth = BW_125_KHZ,
    .datarate = SF_10,
    .coding_rate = CR_4_5,
    .preamble_len = 8,
    .tx_power = 22,
    .tx = true,
};

int main(void)
{
    int ret;

    LOG_INF("LICHEN bridge (Zephyr) starting...");

#if defined(HAS_LED)
    /* LED init */
    if (gpio_is_ready_dt(&led)) {
        gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
        gpio_pin_set_dt(&led, 1);
    }
#endif

#if defined(CONFIG_USB_DEVICE_STACK)
    /* USB CDC init (nRF52 and similar) */
    ret = usb_enable(NULL);
    if (ret != 0) {
        LOG_ERR("USB enable failed: %d", ret);
        /* Continue anyway - might work without explicit enable */
    }
    /* Wait for USB enumeration */
    k_sleep(K_MSEC(1000));
    LOG_INF("USB CDC ready");
#else
    /* UART console (ESP32 and similar) */
    LOG_INF("UART console ready");
#endif

    /* LoRa init */
    const struct device *lora_dev = LORA_DEV;

    if (!device_is_ready(lora_dev)) {
        LOG_ERR("LoRa device not ready");
        goto main_loop;
    }

    ret = lora_config(lora_dev, &lora_cfg);
    if (ret < 0) {
        LOG_ERR("LoRa config failed: %d", ret);
        goto main_loop;
    }

    LOG_INF("SX1262 configured: SF=10 BW=125kHz FREQ=915MHz");

#if defined(HAS_LED)
    /* Turn off LED to indicate success */
    if (gpio_is_ready_dt(&led)) {
        gpio_pin_set_dt(&led, 0);
    }
#endif

main_loop:
    LOG_INF("Ready");

    /* ponytail: minimal loop, just proves it runs */
    while (1) {
        k_sleep(K_SECONDS(5));
        LOG_INF("tick");
    }

    return 0;
}
