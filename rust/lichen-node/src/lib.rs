//! LICHEN node integration crate.
//!
//! Combines the link layer, SCHC compression, CoAP stack, and RPL routing
//! into a single surface for embedded node firmware. The `Node` type is the
//! main entry point; it owns the per-layer state and dispatches received
//! frames down the receive path and up the transmit path.
//!
//! The `Stack` type (std only) provides the full TX/RX path over a radio.

#![no_std]

pub mod dispatch;
pub mod node;
pub mod routing;
#[cfg(feature = "std")]
pub mod stack;
#[cfg(feature = "std")]
pub mod secure;

pub use dispatch::{Dispatcher, Resource, Request, Response};
pub use node::{Node, RplEvent};
#[cfg(feature = "std")]
pub use node::RplNode;
pub use routing::{NeighborTable, Neighbor};
#[cfg(feature = "std")]
pub use routing::Router;
#[cfg(feature = "std")]
pub use stack::{Stack, TxError, RxError, RxFrame};
#[cfg(feature = "std")]
pub use secure::{SecureStack, SecureError};

#[cfg(feature = "std")]
extern crate std;
