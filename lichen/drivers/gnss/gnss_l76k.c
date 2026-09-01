/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 The contributors to the LICHEN project
 *
 * Zephyr GNSS driver for the Quectel L76K series (T-Echo).
 *
 * Streams NMEA-0183 at 9600 baud with no mandatory host-side init.
 * PMTK configuration commands (output message set, update rate) are a
 * follow-up: an unconfigured L76K streams the full NMEA set at 9600 and
 * the generic NMEA0183 parser handles wildcard talker IDs.
 *
 * Standby/backup power (spec 09: duty-cycled tracking): PM_DEVICE
 * suspend pulls V_BACKUP low when the backup GPIO is provided and
 * closes the UART pipe; resume releases V_BACKUP and re-opens. Backup
 * loses ephemeris — the next wake is a cold start, acceptable for a
 * duty-cycled tracker per spec 09.
 */

#include <zephyr/drivers/gnss.h>
#include <zephyr/drivers/gnss/gnss_publish.h>
#include <zephyr/modem/chat.h>
#include <zephyr/modem/backend/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/pm/device.h>
#include <string.h>

#include "gnss_nmea0183.h"
#include "gnss_nmea0183_match.h"
#include "gnss_parse.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(gnss_l76k, CONFIG_GNSS_LOG_LEVEL);

#define DT_DRV_COMPAT quectel_l76k

#define UART_RX_BUF_SZ   (256 + IS_ENABLED(CONFIG_GNSS_SATELLITES) * 512)
#define UART_TX_BUF_SZ   64

struct gnss_l76k_config {
	const struct device    *uart;
	struct gpio_dt_spec     backup_gpio;
};

struct gnss_l76k_data {
	/* match_data MUST be first — modem_chat passes it as user_data */
	struct gnss_nmea0183_match_data match_data;
#if CONFIG_GNSS_SATELLITES
	struct gnss_satellite satellites[CONFIG_GNSS_L76K_SATELLITES_COUNT];
#endif

	struct modem_pipe        *uart_pipe;
	struct modem_backend_uart uart_backend;
	uint8_t uart_backend_receive_buf[UART_RX_BUF_SZ];
	uint8_t uart_backend_transmit_buf[UART_TX_BUF_SZ];
};

MODEM_CHAT_MATCHES_DEFINE(unsol_matches,
	MODEM_CHAT_MATCH_WILDCARD("$??GGA,", ",*", gnss_nmea0183_match_gga_callback),
	MODEM_CHAT_MATCH_WILDCARD("$??RMC,", ",*", gnss_nmea0183_match_rmc_callback),
#if CONFIG_GNSS_SATELLITES
	MODEM_CHAT_MATCH_WILDCARD("$??GSV,", ",*", gnss_nmea0183_match_gsv_callback),
#endif
);

/* Passive-only (mirrors the AG3335 driver): the L76K streams NMEA at
 * 9600 baud unconfigured; PMTK configuration (output message set,
 * update rate, GNSS search mode) is a follow-up bead. All
 * gnss_driver_api callbacks stay NULL so callers get -ENOSYS. */
static const struct gnss_driver_api gnss_l76k_api = {
	/* Passive-only — no runtime configuration supported */
};

static int gnss_l76k_init_match(const struct device *dev)
{
	struct gnss_l76k_data *data = dev->data;

	const struct gnss_nmea0183_match_config match_config = {
		.gnss = dev,
#if CONFIG_GNSS_SATELLITES
		.satellites      = data->satellites,
		.satellites_size = ARRAY_SIZE(data->satellites),
#endif
	};

	return gnss_nmea0183_match_init(&data->match_data, &match_config);
}

static void gnss_l76k_init_pipe(const struct device *dev)
{
	const struct gnss_l76k_config *cfg = dev->config;
	struct gnss_l76k_data *data = dev->data;

	const struct modem_backend_uart_config uart_backend_config = {
		.uart              = cfg->uart,
		.receive_buf       = data->uart_backend_receive_buf,
		.receive_buf_size  = sizeof(data->uart_backend_receive_buf),
		.transmit_buf      = data->uart_backend_transmit_buf,
		.transmit_buf_size = sizeof(data->uart_backend_transmit_buf),
	};

	data->uart_pipe = modem_backend_uart_init(&data->uart_backend,
						  &uart_backend_config);
}

static uint8_t gnss_l76k_char_delimiter[] = {'\r', '\n'};

static int gnss_l76k_init_chat(const struct device *dev)
{
	struct gnss_l76k_data *data = dev->data;

	const struct modem_chat_config chat_config = {
		.user_data          = data,
		.receive_buf        = data->chat_receive_buf,
		.receive_buf_size   = sizeof(data->chat_receive_buf),
		.delimiter          = gnss_l76k_char_delimiter,
		.delimiter_size     = ARRAY_SIZE(gnss_l76k_char_delimiter),
		.filter             = NULL,
		.filter_size        = 0,
		.argv               = data->chat_argv,
		.argv_size          = ARRAY_SIZE(data->chat_argv),
		.unsol_matches      = unsol_matches,
		.unsol_matches_size = ARRAY_SIZE(unsol_matches),
	};

	return modem_chat_init(&data->chat, &chat_config);
}

static int gnss_l76k_resume(const struct device *dev)
{
	const struct gnss_l76k_config *cfg = dev->config;
	struct gnss_l76k_data *data = dev->data;
	int ret;

	if (cfg->backup_gpio.port != NULL) {
		ret = gpio_pin_configure_dt(&cfg->backup_gpio,
					    GPIO_OUTPUT_ACTIVE);
		if (ret < 0) {
			LOG_ERR("V_BACKUP configure: %d", ret);
			return ret;
		}
	}

	ret = modem_pipe_open(data->uart_pipe);
	if (ret < 0) {
		LOG_ERR("Failed to open UART pipe: %d", ret);
		return ret;
	}

	ret = modem_chat_attach(&data->chat, data->uart_pipe);
	if (ret < 0) {
		modem_pipe_close(data->uart_pipe);
		return ret;
	}

	LOG_INF("L76K GNSS ready on %s", cfg->uart->name);
	return 0;
}

static int gnss_l76k_init(const struct device *dev)
{
	const struct gnss_l76k_config *cfg = dev->config;
	int ret;

	if (!device_is_ready(cfg->uart)) {
		LOG_ERR("UART not ready");
		return -ENODEV;
	}
	if (cfg->backup_gpio.port != NULL &&
	    !gpio_is_ready_dt(&cfg->backup_gpio)) {
		LOG_ERR("V_BACKUP GPIO not ready");
		return -ENODEV;
	}

	ret = gnss_l76k_init_match(dev);
	if (ret < 0) {
		return ret;
	}

	gnss_l76k_init_pipe(dev);

	ret = gnss_l76k_init_chat(dev);
	if (ret < 0) {
		return ret;
	}

#if CONFIG_PM_DEVICE
	pm_device_init_suspended(dev);
	return 0;
#else
	return gnss_l76k_resume(dev);
#endif
}

#if CONFIG_PM_DEVICE
static int gnss_l76k_suspend(const struct device *dev)
{
	const struct gnss_l76k_config *cfg = dev->config;
	struct gnss_l76k_data *data = dev->data;
	int ret;

	/* Backup mode loses ephemeris (cold start on wake) — acceptable
	 * for duty-cycled tracking (spec 09). */
	if (cfg->backup_gpio.port != NULL) {
		gpio_pin_set_dt(&cfg->backup_gpio, 0);
	}
	modem_chat_release(&data->chat);
	ret = modem_pipe_close(data->uart_pipe);
	if (ret < 0) {
		LOG_WRN("UART pipe close: %d", ret);
	}
	return ret;
}

static int gnss_l76k_pm_action(const struct device *dev,
			       enum pm_device_action action)
{
	switch (action) {
	case PM_DEVICE_ACTION_RESUME:
		return gnss_l76k_resume(dev);
	case PM_DEVICE_ACTION_SUSPEND:
		return gnss_l76k_suspend(dev);
	default:
		return -ENOTSUP;
	}
}
#endif

#define GNSS_L76K_DEFINE(inst)                                                 \
	static struct gnss_l76k_data gnss_l76k_data_##inst;                    \
									       \
	static const struct gnss_l76k_config gnss_l76k_config_##inst = {       \
		.uart = DEVICE_DT_GET(DT_INST_BUS(inst)),                      \
		.backup_gpio = GPIO_DT_SPEC_INST_GET_OR(                       \
			inst, backup_gpios, {0}),                              \
	};                                                                     \
									       \
	IF_ENABLED(CONFIG_PM_DEVICE, (                                         \
		PM_DEVICE_DT_INST_DEFINE(inst, gnss_l76k_pm_action);           \
	))                                                                     \
									       \
	DEVICE_DT_INST_DEFINE(inst, gnss_l76k_init,                            \
			      PM_DEVICE_DT_INST_GET(inst),                     \
			      &gnss_l76k_data_##inst, &gnss_l76k_config_##inst, \
			      POST_KERNEL, CONFIG_GNSS_INIT_PRIORITY,          \
			      &gnss_l76k_api);

DT_INST_FOREACH_STATUS_OKAY(GNSS_L76K_DEFINE)