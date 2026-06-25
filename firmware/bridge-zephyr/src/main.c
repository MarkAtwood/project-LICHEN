/*
 * LICHEN LoRa Bridge - Zephyr version
 * Minimal "hello world" that initializes USB serial and SX1262 radio.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

/* LED */
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);

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

    /* LED init */
    if (gpio_is_ready_dt(&led)) {
        gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
        gpio_pin_set_dt(&led, 1);
    }

    /* USB CDC init */
    ret = usb_enable(NULL);
    if (ret != 0) {
        LOG_ERR("USB enable failed: %d", ret);
        /* Continue anyway - might work without explicit enable */
    }

    /* Wait for USB enumeration */
    k_sleep(K_MSEC(1000));

    LOG_INF("USB CDC ready");

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

    /* Turn off LED to indicate success */
    if (gpio_is_ready_dt(&led)) {
        gpio_pin_set_dt(&led, 0);
    }

main_loop:
    LOG_INF("Ready");

    /* ponytail: minimal loop, just proves it runs */
    while (1) {
        k_sleep(K_SECONDS(5));
        LOG_INF("tick");
    }

    return 0;
}
