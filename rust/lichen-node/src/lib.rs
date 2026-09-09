//! LICHEN node integration crate.
//!
//! Combines the link layer, SCHC compression, CoAP stack, and RPL routing
//! into a single surface for embedded node firmware. The `Node` type is the
//! main entry point; it owns the per-layer state and dispatches received
//! frames down the receive path and up the transmit path.
//!
//! # Stack Types
//!
//! For CoAP communication, use [`SecureStack`] (the default). Per spec section 8.7,
//! **all CoAP traffic MUST use OSCORE end-to-end encryption**.
//!
//! - **[`SecureStack`]** — OSCORE-protected CoAP. Use this for all application traffic.
//! # Integration Testing
//!
//! This crate has integration tests that exercise the full protocol path without mocking:
//!
//! - **`stack::tests::stack_ping_pong`** — Two `Stack` instances connected via `LoopbackRadio`.
//!   Alice sends ICMPv6 Echo Request → Radio TX → L2 sign → SCHC compress → wire →
//!   Radio RX → L2 verify → SCHC decompress → IPv6 → ICMPv6 → Echo Reply back.
//!   Real crypto, real compression, real packet handling.
//!
//! - **`secure::tests::secure_stack_oscore_roundtrip`** — OSCORE-protected CoAP GET
//!   over the full stack with end-to-end encryption.
//!
//! - **`node::tests::echo_request_to_self_yields_reply`** — SCHC-compressed Echo Request
//!   processed through the node's `handle_frame` path with reply verification.
//!
//! These tests catch integration bugs that unit tests miss: compression/decompression
//! round-trip issues, L2 signature verification across peers, message ID threading, etc.
//!
//! Run with: `cargo test --features std`

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
pub mod announce;
#[cfg(feature = "std")]
pub mod announce_store;
pub mod dispatch;
#[cfg(feature = "std")]
pub mod forward_buffer;
pub mod gradient;
pub mod hybrid;
pub mod node;
pub mod port_dispatch;
pub mod routing;
#[cfg(feature = "std")]
pub mod rpl_stack;
#[cfg(feature = "std")]
pub mod runtime;
#[cfg(feature = "std")]
pub mod scheduler;
#[cfg(feature = "std")]
pub mod secure;
#[cfg(feature = "std")]
pub mod secure_dispatch;
#[cfg(feature = "std")]
pub mod stack;
#[cfg(feature = "std")]
pub mod tdma_scheduler;

#[cfg(feature = "std")]
pub use announce::seq_gt;
#[cfg(feature = "std")]
pub use announce::AnnounceProcessor;
#[cfg(feature = "std")]
pub use announce::AnnounceRejectReason;
#[cfg(feature = "std")]
pub use announce::AnnounceResult;
#[cfg(feature = "std")]
pub use announce::MAX_TRACKED_ORIGINATORS;
#[cfg(feature = "std")]
pub use announce_store::AnnounceStoreError;
#[cfg(feature = "std")]
pub use announce_store::AnnounceTrustState;
#[cfg(feature = "std")]
pub use announce_store::AnnounceTrustStore;
pub use dispatch::Dispatcher;
pub use dispatch::Request;
pub use dispatch::Resource;
pub use dispatch::Response;
pub use gradient::GeoCoords;
pub use gradient::GradientEntry;
pub use gradient::GradientSource;
#[cfg(feature = "std")]
pub use gradient::GradientTable;
pub use gradient::DATA_GRADIENT_TIMEOUT_MS;
pub use gradient::GRADIENT_TIMEOUT_MS;
pub use hybrid::AddressClass;
#[cfg(feature = "std")]
pub use hybrid::HybridRouter;
#[cfg(feature = "std")]
pub use hybrid::MeshPrefix;
#[cfg(feature = "std")]
pub use hybrid::PendingPacket;
pub use hybrid::RouteDecision;
pub use hybrid::RouteResult;
#[cfg(feature = "std")]
pub use node::rpl_code;
#[cfg(feature = "std")]
pub use node::DaoHandlingOutcome;
pub use node::Node;
pub use node::RplEvent;
#[cfg(feature = "std")]
pub use node::RplNode;
pub use port_dispatch::dispatch_by_port;
pub use port_dispatch::AppProtocol;
pub use port_dispatch::DispatchError;
pub use port_dispatch::Dispatched;
pub use port_dispatch::UdpDispatchError;
#[cfg(feature = "std")]
pub use routing::DtnBuffer;
#[cfg(feature = "std")]
pub use routing::DtnMessage;
pub use routing::Neighbor;
pub use routing::NeighborTable;
#[cfg(feature = "std")]
pub use routing::RouteTarget;
#[cfg(feature = "std")]
pub use routing::Router;
#[cfg(feature = "std")]
pub use routing::TrickleAwareNeighborLiveness;
pub use routing::TrickleSafeLivenessPolicy;
#[cfg(feature = "std")]
pub use routing::DTN_BUFFER_MAX_BYTES;
#[cfg(feature = "std")]
pub use rpl_stack::RplReceiveOutcome;
#[cfg(feature = "std")]
pub use rpl_stack::RplStack;
// SECURITY: SecureStack is the primary export for CoAP traffic per spec section 8.7.
// Use Stack (PlaintextStack) only for ICMPv6, diagnostics, or testing.
#[cfg(feature = "std")]
pub use secure::SecureError;
#[cfg(feature = "std")]
pub use secure::SecureObserveCorrelation;
#[cfg(feature = "std")]
pub use secure::SecureObserveRegistration;
#[cfg(feature = "std")]
pub use secure::SecureObserveResponse;
#[cfg(feature = "std")]
pub use secure::SecureStack;
#[cfg(feature = "std")]
pub use stack::Priority;
#[cfg(feature = "std")]
pub use stack::ReceivedIpv6;
#[cfg(feature = "std")]
pub use stack::RxError;
#[cfg(feature = "std")]
pub use stack::Stack;
#[cfg(feature = "std")]
pub use stack::TxError;
/// Type alias for `Stack` — use only for ICMPv6, diagnostics, or testing.
/// For CoAP traffic, use [`SecureStack`] instead (per spec section 8.7).
#[cfg(feature = "std")]
pub type PlaintextStack<R> = Stack<R>;
#[cfg(feature = "std")]
pub use forward_buffer::ForwardBuffer;
#[cfg(feature = "std")]
pub use forward_buffer::ForwardEntry;
#[cfg(feature = "std")]
pub use forward_buffer::ForwardError;
#[cfg(feature = "std")]
pub use forward_buffer::ForwardStats;
#[cfg(feature = "std")]
pub use forward_buffer::MAX_FORWARDING_SOURCES;
#[cfg(feature = "std")]
pub use forward_buffer::MAX_PACKETS_PER_SOURCE;
#[cfg(feature = "std")]
pub use lichen_link::link_layer::LinkRxError;
#[cfg(feature = "std")]
pub use scheduler::AnnounceScheduler;
#[cfg(feature = "std")]
pub use scheduler::AnnounceTransmitter;
#[cfg(feature = "std")]
pub use scheduler::SchedulerConfig;
#[cfg(feature = "std")]
pub use scheduler::SchedulerError;
#[cfg(feature = "std")]
pub use tdma_scheduler::TdmaScheduler;
#[cfg(feature = "std")]
pub use tdma_scheduler::TdmaSchedulerError;

#[cfg(feature = "std")]
extern crate std;
