/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* STM32WL55JC memory layout (CM4 core) */
/* Reference: RM0453 STM32WL5x Reference Manual */

MEMORY
{
    /* Flash: 256KB total, starting at 0x0800_0000 */
    /* Reserve first 48KB for bootloader if needed in future */
    FLASH : ORIGIN = 0x08000000, LENGTH = 256K

    /* SRAM1: 32KB - main application RAM */
    RAM   : ORIGIN = 0x20000000, LENGTH = 32K

    /* SRAM2: 32KB - shared with radio, can be used for buffers */
    /* Note: Last 2KB reserved for IPCC if using dual-core */
    RAM2  : ORIGIN = 0x20008000, LENGTH = 32K
}

/* Entry point */
ENTRY(Reset);

/* Stack size - 4KB should be sufficient for Embassy */
_stack_size = 4K;

/* Ensure stack doesn't overflow into data */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);
