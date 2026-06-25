//! LICHEN LoRa Bridge - Rust/Embassy version
//! Minimal "hello world" that initializes USB serial and SX1262 radio.

#![no_std]
#![no_main]

use defmt::{info, error};
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::gpio::{Level, Output, OutputDrive, Input, Pull};
use embassy_nrf::spim::{self, Spim};
use embassy_nrf::usb::Driver;
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_nrf::{bind_interrupts, pac, peripherals, usb};
use embassy_time::Timer;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config};
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    USBD => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
    SPIM3 => embassy_nrf::spim::InterruptHandler<peripherals::SPI3>;
});

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());

    info!("LICHEN bridge (Rust) starting...");

    // LED for status (Arduino pin 35 = P1.03)
    let mut led = Output::new(p.P1_03, Level::High, OutputDrive::Standard);

    // Enable high-frequency clock (required for USB)
    info!("Enabling HFCLK...");
    pac::CLOCK.tasks_hfclkstart().write_value(1);
    while pac::CLOCK.events_hfclkstarted().read() != 1 {}

    // ─── SPI for SX1262 ───
    let mut spi_config = spim::Config::default();
    spi_config.frequency = spim::Frequency::M8;

    let mut spi = Spim::new(
        p.SPI3,
        Irqs,
        p.P1_11,  // SCK
        p.P1_13,  // MISO
        p.P1_12,  // MOSI
        spi_config,
    );

    let mut nss = Output::new(p.P1_10, Level::High, OutputDrive::Standard);
    let mut reset = Output::new(p.P1_06, Level::High, OutputDrive::Standard);
    let busy = Input::new(p.P1_14, Pull::None);
    let _dio1 = Input::new(p.P1_15, Pull::None);

    info!("SPI configured for SX1262");

    // ─── Radio Init ───
    // ponytail: skip full lora-phy init, just probe the chip

    // Reset sequence
    reset.set_low();
    Timer::after_millis(10).await;
    reset.set_high();
    Timer::after_millis(20).await;

    // Wait for BUSY to go low
    for _ in 0..100 {
        if busy.is_low() {
            break;
        }
        Timer::after_millis(1).await;
    }

    if busy.is_high() {
        error!("SX1262 BUSY timeout");
    }

    // Read status (GetStatus command = 0xC0)
    let tx = [0xC0, 0x00];
    let mut rx = [0u8; 2];
    nss.set_low();
    let _ = spi.transfer(&mut rx, &tx).await;
    nss.set_high();

    let status = rx[1];
    info!("SX1262 status: 0x{:02x}", status);

    // Check chip mode bits [6:4] - should be STDBY_RC (0x2) or STDBY_XOSC (0x3)
    let mode = (status >> 4) & 0x07;
    if mode == 0x02 || mode == 0x03 {
        info!("SX1262 initialized OK (mode={})", mode);
    } else {
        error!("SX1262 unexpected mode: {}", mode);
    }

    led.set_low();

    // ─── USB CDC Setup ───
    let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));

    let mut config = Config::new(0x239a, 0x0029);  // Adafruit nRF52840
    config.manufacturer = Some("LICHEN");
    config.product = Some("LoRa Bridge");
    config.serial_number = Some("001");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut msos_descriptor = [0; 256];
    let mut control_buf = [0; 64];
    let mut state = State::new();

    let mut builder = Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut msos_descriptor,
        &mut control_buf,
    );

    let mut class = CdcAcmClass::new(&mut builder, &mut state, 64);
    let mut usb = builder.build();

    info!("USB ready");

    // ─── Run USB and echo loop concurrently ───
    let usb_fut = usb.run();

    let echo_fut = async {
        let mut buf = [0u8; 64];
        loop {
            class.wait_connection().await;
            info!("USB connected");

            loop {
                match class.read_packet(&mut buf).await {
                    Ok(n) if n > 0 => {
                        info!("USB rx {} bytes", n);
                        // Echo back with prefix
                        let _ = class.write_packet(b"# echo: ").await;
                        let _ = class.write_packet(&buf[..n]).await;
                        let _ = class.write_packet(b"\r\n").await;
                    }
                    Err(_) => {
                        info!("USB disconnected");
                        break;
                    }
                    _ => {}
                }
            }
        }
    };

    join(usb_fut, echo_fut).await;
}
