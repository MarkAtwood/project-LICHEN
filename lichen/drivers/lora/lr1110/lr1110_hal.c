/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 The contributors to the LICHEN project
 *
 * Zephyr HAL implementation for the Semtech LR1110.
 *
 * The LR1110 SPI protocol is two-phase for reads:
 *   Write:      CS↓ [opcode+params] [data] CS↑  → wait BUSY↓
 *   Read:       CS↓ [opcode+params]        CS↑  → wait BUSY↓
 *               CS↓ [NOP×(1+N)]            CS↑  → receive [stat, data×N]
 *               (no trailing BUSY wait — chip is ready before data phase)
 *   Sleep:      CS↓ [0x01 0x1B ...]       CS↑  → 1ms (no BUSY — chip sleeps immediately)
 *   Write+Read: CS↓ [cmd×N] simultaneous rx [resp×N] CS↑  (GetStatus only)
 */

#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "lr1110_hal.h"

LOG_MODULE_DECLARE(lr1110, CONFIG_LORA_LOG_LEVEL);

/* Provided by lr1110.c — single-instance statics */
extern const struct spi_dt_spec  lr1110_bus;
extern const struct gpio_dt_spec lr1110_gpio_busy;
extern const struct gpio_dt_spec lr1110_gpio_reset;

/*
 * Zero-filled NOP pad for the SPI read response phase.
 *
 * The LR1110's two-phase read protocol clocks out 1 status byte followed by
 * up to 256 data bytes. The radio buffer is 256 bytes (per LR1110 datasheet
 * section 5.2), so the maximum response is 1 + 256 = 257 bytes. We transmit
 * NOPs (0x00) to generate the SPI clock while receiving.
 */
#define LR1110_HAL_MAX_READ_DATA 256U
static const uint8_t nop_pad[1U + LR1110_HAL_MAX_READ_DATA];

static void wait_busy(void)
{
	int64_t deadline = k_uptime_get() + 500;

	while (gpio_pin_get_dt(&lr1110_gpio_busy) > 0) {
		if (k_uptime_get() > deadline) {
			LOG_ERR("LR1110 BUSY stuck — hard reset");
			lr1110_hal_reset(NULL);
			return;
		}
		k_sleep(K_MSEC(1));
	}
}

lr1110_hal_status_t lr1110_hal_write(const void *context,
				     const uint8_t *command,
				     const uint16_t command_length,
				     const uint8_t *data,
				     const uint16_t data_length)
{
	ARG_UNUSED(context);

	struct spi_buf tx_bufs[2] = {
		{ .buf = (void *)command, .len = command_length },
		{ .buf = (void *)data,    .len = data_length    },
	};
	const struct spi_buf_set tx = {
		.buffers = tx_bufs,
		.count   = data_length ? 2U : 1U,
	};

	if (spi_write_dt(&lr1110_bus, &tx)) {
		LOG_ERR("SPI write failed");
		return LR1110_HAL_STATUS_ERROR;
	}

	/* SetSleep (0x01 0x1B) puts the chip to sleep immediately — no BUSY transition */
	if (command_length >= 2 && command[0] == 0x01 && command[1] == 0x1B) {
		k_busy_wait(1000);
	} else {
		wait_busy();
	}
	return LR1110_HAL_STATUS_OK;
}

lr1110_hal_status_t lr1110_hal_read(const void *context,
				    const uint8_t *command,
				    const uint16_t command_length,
				    uint8_t *data,
				    const uint16_t data_length)
{
	ARG_UNUSED(context);

	if (data_length > LR1110_HAL_MAX_READ_DATA) {
		LOG_ERR("Read length %u exceeds max %u", data_length,
			LR1110_HAL_MAX_READ_DATA);
		return LR1110_HAL_STATUS_ERROR;
	}

	/* Phase 1: send command */
	struct spi_buf cmd_buf = { .buf = (void *)command, .len = command_length };
	const struct spi_buf_set cmd_tx = { .buffers = &cmd_buf, .count = 1 };

	if (spi_write_dt(&lr1110_bus, &cmd_tx)) {
		LOG_ERR("SPI cmd write failed");
		return LR1110_HAL_STATUS_ERROR;
	}
	wait_busy();

	/* Phase 2: send NOPs, receive [stat1 (discarded), data×N] */
	uint8_t stat_byte;
	struct spi_buf tx_buf  = { .buf = (void *)nop_pad, .len = 1U + data_length };
	struct spi_buf rx_bufs[2] = {
		{ .buf = &stat_byte, .len = 1          },
		{ .buf = data,       .len = data_length },
	};
	const struct spi_buf_set rx_tx = { .buffers = &tx_buf,  .count = 1 };
	const struct spi_buf_set rx_rx = { .buffers = rx_bufs,  .count = 2 };

	if (spi_transceive_dt(&lr1110_bus, &rx_tx, &rx_rx)) {
		LOG_ERR("SPI read failed");
		return LR1110_HAL_STATUS_ERROR;
	}
	return LR1110_HAL_STATUS_OK;
}

lr1110_hal_status_t lr1110_hal_write_read(const void *context,
					  const uint8_t *command,
					  uint8_t *data,
					  const uint16_t data_length)
{
	ARG_UNUSED(context);

	/* Full-duplex — used only by lr1110_system_get_status */
	struct spi_buf tx_buf = { .buf = (void *)command, .len = data_length };
	struct spi_buf rx_buf = { .buf = data,            .len = data_length };
	const struct spi_buf_set tx = { .buffers = &tx_buf, .count = 1 };
	const struct spi_buf_set rx = { .buffers = &rx_buf, .count = 1 };

	if (spi_transceive_dt(&lr1110_bus, &tx, &rx)) {
		LOG_ERR("SPI write_read failed");
		return LR1110_HAL_STATUS_ERROR;
	}
	return LR1110_HAL_STATUS_OK;
}

void lr1110_hal_reset(const void *context)
{
	ARG_UNUSED(context);
	gpio_pin_set_dt(&lr1110_gpio_reset, 1);
	k_busy_wait(1000);
	gpio_pin_set_dt(&lr1110_gpio_reset, 0);
	k_busy_wait(1000);
	k_sleep(K_MSEC(200)); /* wait for internal firmware to load */
}

lr1110_hal_status_t lr1110_hal_wakeup(const void *context)
{
	ARG_UNUSED(context);

	/* CS pulse (no SPI bytes) wakes the LR1110 from sleep.
	 * CS is active-low: assert LOW to wake, then release HIGH. */
	gpio_pin_set_dt(&lr1110_bus.config.cs.gpio, 0);
	k_busy_wait(100);
	gpio_pin_set_dt(&lr1110_bus.config.cs.gpio, 1);
	wait_busy();
	return LR1110_HAL_STATUS_OK;
}
