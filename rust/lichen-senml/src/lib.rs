//! SenML sensor data records for LICHEN (RFC 8428).
//!
//! Provides the `Record` type and CBOR encode/decode (RFC 8428 §6). LICHEN uses
//! SenML-CBOR (Content-Format 112) for sensor payloads, with base names of
//! the form `urn:dev:mac:<EUI-64>:`.

#![no_std]

pub mod cbor;
pub mod record;

pub use cbor::CborError;
pub use record::Record;

#[cfg(feature = "std")]
extern crate std;
