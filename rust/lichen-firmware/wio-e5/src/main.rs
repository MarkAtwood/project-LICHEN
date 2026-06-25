// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! LICHEN firmware for Seeed Wio-E5 (STM32WL55).
//!
//! This is the main entry point for the Wio-E5 board. The STM32WL55 has an
//! integrated SubGHz radio (SX126x-compatible), making it ideal for LoRa.

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::Config;
use embassy_time::Timer;
use panic_halt as _;

/// LED blink task - proves the firmware is running.
#[embassy_executor::task]
async fn blink(mut led: Output<'static>) {
    loop {
        info!("LED on");
        led.set_high();
        Timer::after_millis(500).await;

        info!("LED off");
        led.set_low();
        Timer::after_millis(500).await;
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Initialize the HAL with default config
    // STM32WL uses MSI as default clock, HSE for SubGHz radio
    // ponytail: default config is fine for blinky, radio init will need clock tuning
    let p = embassy_stm32::init(Config::default());

    info!("LICHEN Wio-E5 firmware starting");

    // Wio-E5 has an LED on PB5
    let led = Output::new(p.PB5, Level::Low, Speed::Low);

    // Spawn the blink task
    spawner.spawn(blink(led)).unwrap();

    // Main loop - placeholder for radio and protocol tasks
    // ponytail: radio init goes here when lichen-embassy stm32wl module is ready
    loop {
        Timer::after_secs(10).await;
        info!("heartbeat");
    }
}
