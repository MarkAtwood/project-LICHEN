//! Embassy HAL implementations for LICHEN.
//!
//! Provides implementations of `lichen_hal` traits for various embedded targets.
//! Each target is feature-gated:
//!
//! - `esp32s3`: ESP32-S3 with SX1262 (esp-hal)
//! - `nrf52840`: nRF52840 with SX1262 (embassy-nrf)
//! - `rp2040`: RP2040 with SX1262 (embassy-rp)
//! - `stm32wl`: STM32WL55 with integrated SubGHz (embassy-stm32)
//! - `mock`: Host-side mock for testing
//! - `std`: Enable std (automatically enabled by mock/sim)

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

/// R-02-006 (spec/02-physical-link.md 3.2): the LICHEN sync word 0x34 is the
/// Semtech "public network" sync word. lora-phy's SX126x driver programs it
/// only when `enable_public_network` is true (`LoRa::new(.., public, ..)`
/// writes 0x3444 to REG_LORA_SYNC_WORD — the SX126x encoding of the SX127x
/// 0x34 sync byte); `false` would program 0x1424 (private 0x12), leaving
/// Rust nodes deaf to C nodes, which program 0x34 unconditionally
/// (lr1110.c R-02-006). Bound at compile time to the canonical constant so a
/// deliberate constant change flips the wire setting with it.
#[cfg(any(feature = "esp32s3", feature = "stm32wl", test))]
pub(crate) const ENABLE_PUBLIC_NETWORK: bool = lichen_core::constants::LORA_SYNC_WORD == 0x34;

#[cfg(test)]
mod tests {
    use super::ENABLE_PUBLIC_NETWORK;

    #[test]
    fn lichen_sync_word_is_the_semtech_public_network_word() {
        // R-02-006 pin: 0x34 on the wire, and the lora-phy public/private
        // selector resolves to the public (0x3444) programming.
        assert_eq!(lichen_core::constants::LORA_SYNC_WORD, 0x34);
        assert!(ENABLE_PUBLIC_NETWORK);
    }
}

/// Mock HAL implementation for host-side testing.
#[cfg(feature = "mock")]
pub mod mock;

/// Simulation radio that bridges to lichen-sim via TCP.
/// Use when running in QEMU or other emulators.
#[cfg(feature = "sim")]
pub mod sim;

/// ESP32-S3 HAL implementation using esp-hal + lora-phy.
#[cfg(feature = "esp32s3")]
pub mod esp32s3;

/// STM32WL HAL implementation using embassy-stm32 + lora-phy.
#[cfg(feature = "stm32wl")]
pub mod stm32wl;

// ponytail: other targets stubbed until needed
// #[cfg(feature = "nrf52840")]
// pub mod nrf52840;
// #[cfg(feature = "rp2040")]
// pub mod rp2040;
