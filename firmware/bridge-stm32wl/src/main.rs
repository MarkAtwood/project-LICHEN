//! LICHEN LoRa Bridge - STM32WL version
//! Uses the STM32WL's integrated SubGHz radio (SX1262-compatible).
//!
//! This is a minimal scaffold that demonstrates the queue-based architecture.
//! The actual SubGHz radio driver integration is a TODO.

#![no_std]
#![no_main]

use defmt::{info, warn};
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::Timer;
use {defmt_rtt as _, panic_probe as _};

// ─── Radio Queue Types ───────────────────────────────────────────────────────

/// Packet to transmit over radio.
#[derive(Clone, Copy)]
pub struct TxPacket {
    pub data: [u8; 256],
    pub len: usize,
}

impl TxPacket {
    pub const fn empty() -> Self {
        Self { data: [0; 256], len: 0 }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut pkt = Self::empty();
        let len = data.len().min(256);
        pkt.data[..len].copy_from_slice(&data[..len]);
        pkt.len = len;
        pkt
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Received packet from radio.
#[derive(Clone, Copy)]
pub struct RxPacket {
    pub data: [u8; 256],
    pub len: usize,
    pub rssi: i16,
    pub snr: i8,
}

impl RxPacket {
    pub const fn empty() -> Self {
        Self { data: [0; 256], len: 0, rssi: 0, snr: 0 }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ─── Static Channels ─────────────────────────────────────────────────────────
// ponytail: 8-deep queues, sufficient for typical mesh traffic

/// Queue for packets to transmit over radio.
static TX_QUEUE: Channel<CriticalSectionRawMutex, TxPacket, 8> = Channel::new();

/// Queue for packets received from radio.
static RX_QUEUE: Channel<CriticalSectionRawMutex, RxPacket, 8> = Channel::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init(Default::default());

    info!("LICHEN bridge (STM32WL) starting...");

    // LED for status (PA5 on Nucleo-WLE5JC)
    let mut led = Output::new(p.PA5, Level::Low, Speed::Low);

    // ─── SubGHz Radio Init ───
    // STM32WL has integrated SubGHz radio accessed via internal SPI.
    // The radio is SX1262-compatible and uses p.SUBGHZSPI peripheral.
    //
    // TODO: Initialize SubGHz radio using embassy-stm32's subghz module
    // or stm32wl-subghz crate when version compatibility is resolved.
    //
    // For now, this is a placeholder that matches the bridge-rust pattern.
    // The radio would be configured for:
    // - 915 MHz frequency
    // - SF10 spreading factor
    // - 125 kHz bandwidth
    // - CR 4/5 coding rate

    info!("SubGHz radio init placeholder (TODO: integrate driver)");

    // Blink LED to indicate ready
    led.set_high();
    Timer::after_millis(100).await;
    led.set_low();

    // Spawn radio task
    spawner.spawn(radio_task().unwrap());

    info!("STM32WL bridge ready");

    // Main loop - just keep alive
    loop {
        Timer::after_millis(1000).await;
    }
}

// ─── Radio Task ──────────────────────────────────────────────────────────────

/// Radio task: handles TX queue and RX polling.
///
/// This is a placeholder for the full radio driver. Currently just demonstrates
/// the queue-based architecture.
#[embassy_executor::task]
async fn radio_task() {
    info!("radio_task started");

    // ponytail: placeholder until full SubGHz driver integration
    // Real implementation would:
    // 1. Initialize SubGHz SPI via Spi::new_subghz()
    // 2. Configure RF switch pins (PC3, PC4, PC5 on Nucleo boards)
    // 3. Use DIO1 interrupt for RX done
    // 4. Handle TX/RX state machine
    // 5. Process packets through the queues

    let tx_receiver = TX_QUEUE.receiver();
    let _rx_sender = RX_QUEUE.sender(); // ponytail: used when full SubGHz driver integrated

    loop {
        // Wait for TX packet or RX timeout
        match select(tx_receiver.receive(), Timer::after_millis(100)).await {
            Either::First(pkt) => {
                // TX packet available
                info!("radio TX {} bytes", pkt.len);
                // TODO: actual SubGHz transmit
                Timer::after_millis(50).await; // Simulate TX time
            }
            Either::Second(_) => {
                // RX poll timeout - check for received packet
                // TODO: check SubGHz RX buffer
                // For now, just continue loop
            }
        }
    }
}

/// Queue a packet for radio transmission.
///
/// Returns immediately. Packet will be transmitted asynchronously.
#[allow(dead_code)]
pub fn queue_radio_tx(data: &[u8]) -> bool {
    match TX_QUEUE.try_send(TxPacket::from_slice(data)) {
        Ok(()) => true,
        Err(_) => {
            warn!("TX queue full, dropping packet");
            false
        }
    }
}

/// Try to receive a packet from the radio.
///
/// Returns immediately with None if no packet available.
#[allow(dead_code)]
pub fn try_radio_rx() -> Option<RxPacket> {
    RX_QUEUE.try_receive().ok()
}
