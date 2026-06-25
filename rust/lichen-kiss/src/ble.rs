//! BLE GATT service for KISS transport.
//!
//! Provides a BLE GATT service for KISS frame transport, enabling
//! wireless connection to TNC applications like APRSDroid.
//!
//! Service UUID: 00000001-ba2a-46c9-ae49-01b0961f68bb
//!
//! Available with feature `kiss-ble`.

/// KISS BLE service UUID.
pub const SERVICE_UUID: &str = "00000001-ba2a-46c9-ae49-01b0961f68bb";

/// TX characteristic UUID (write to device).
pub const TX_CHAR_UUID: &str = "00000002-ba2a-46c9-ae49-01b0961f68bb";

/// RX characteristic UUID (notify from device).
pub const RX_CHAR_UUID: &str = "00000003-ba2a-46c9-ae49-01b0961f68bb";

// Stub - to be implemented
