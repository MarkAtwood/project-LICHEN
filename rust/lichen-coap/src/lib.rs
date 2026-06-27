//! CoAP protocol implementation for LICHEN (RFC 7252, RFC 7959).
//!
//! Provides message types, options, and blockwise transfer support.
//! All CoAP traffic in LICHEN uses UDP port 5683 (or 5684 for DTLS) and is
//! header-compressed via SCHC before transmission over the link layer.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod block;
pub mod codec;
pub mod message;
pub mod option;

pub use block::{BlockOption, BlockReceiver, BlockSender};
pub use codec::{CoapBuilder, CoapError, CoapOption, CoapPacket};
pub use message::{MessageCode, MessageType};

#[cfg(feature = "tokio")]
pub mod client;
