//! LICHEN link layer (spec section 4).
//!
//! Implements the LICHEN frame format with LLSec flags, replay-window tracking,
//! and stubs for future AES-CCM encryption and Schnorr-48 link signatures.
//!
//! # Frame Types
//!
//! The stack uses distinct types for frames at different processing stages:
//!
//! - [`frame::LichenFrame`]: Raw parsed wire frame (zero-copy, borrowed).
//! - [`link_layer::AuthenticatedFrame`]: Frame after signature verification and
//!   replay check. Contains the inner payload and authenticated sender identity.
//! - `lichen_node::ReceivedIpv6`: Complete RX output with decompressed IPv6 and
//!   radio metadata (RSSI/SNR). This is the type application code receives.
//!
//! A common `Frame` trait is intentionally avoided: these represent different
//! protocol layers with incompatible semantics. Link frames have replay counters
//! and MICs; IPv6 packets have headers and hop limits. Forcing a shared trait
//! would be leaky abstraction.
//!
//! # Threat Model Note
//!
//! Keys are device-held: anyone with physical access has the key. The existing
//! side-channel mitigations (constant-time comparison, zeroize-on-drop) are
//! retained as low-cost best practice, but don't meaningfully improve security
//! for this use case. Remote timing attacks over a high-latency LoRa mesh are
//! impractical. Don't add more crypto hardening without a concrete threat.
//!
//! Wire layout (spec 4.1):
//! ```text
//! +--------+--------+-------+--------+----------+---------+-------+
//! | Length | LLSec  | Epoch | SeqNum | Dst Addr | Payload |  MIC  |
//! +--------+--------+-------+--------+----------+---------+-------+
//!    1B       1B       1B      2B       0/2/8B     var      4/8B
//! ```
//!
//! LLSec byte packs from LSB:
//!   bits 0-1 : AddrMode  (0=broadcast, 1=16-bit, 2=EUI-64, 3=elided)
//!   bits 2-4 : MicLength (0=32-bit, 1=64-bit)
//!   bit  5   : signature present (Schnorr-48)
//!   bit  6   : encrypted (AES-CCM)
//!   bit  7   : reserved (must be 0)

#![no_std]

pub mod frame;
pub mod keys;
pub mod replay;
pub mod seqnum;

pub use keys::{PrivateKey, PublicKey, Seed};
pub use seqnum::LinkSeqNum;

#[cfg(feature = "schnorr")]
pub mod schnorr;

#[cfg(feature = "schnorr")]
pub mod identity;

#[cfg(all(feature = "schnorr", feature = "std"))]
pub mod link_layer;
#[cfg(all(feature = "schnorr", feature = "std"))]
pub use link_layer::LinkRxError;

#[cfg(any(test, feature = "std"))]
extern crate std;

/// Test utilities shared across crate test modules.
#[cfg(test)]
pub(crate) mod test_utils {
    extern crate std;
    use std::vec::Vec;

    /// Parse a hex string into bytes.
    pub fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
