//! Routing integration: wraps lichen-rpl with neighbor tracking and node-level API.
//!
//! RPL Non-Storing Mode (MOP=1) is the primary routing protocol. The `Router`
//! type owns DODAG state, trickle timer, and neighbor table, providing a
//! unified interface for the node's receive/transmit paths.
//!
//! Also provides GPSR geographic forwarding fallback (spec 9.7) when gradient
//! routes are unavailable and LOADng discovery times out.
//!
//! Requires `std` feature for full RPL integration.

#[cfg(feature = "std")]
mod dtn;
pub mod dtn_option;
#[cfg(feature = "std")]
mod gpsr;
mod neighbor;
#[cfg(feature = "std")]
mod router;
#[cfg(all(test, feature = "std"))]
mod tests;

pub use dtn_option::decide_expiry_action;
pub use dtn_option::parse_dtn_option;
pub use dtn_option::DtnOption;
pub use dtn_option::ExpiryAction;
pub use dtn_option::DTN_FLAG_S;

// Re-exports from neighbor module
pub use neighbor::GeoCoords;
pub use neighbor::LinkEtx;
pub use neighbor::Neighbor;
pub use neighbor::NeighborTable;
#[cfg(feature = "std")]
pub use neighbor::TrickleAwareNeighborLiveness;
pub use neighbor::TrickleSafeLivenessPolicy;
pub use neighbor::MAX_NEIGHBORS;

// Re-exports from router module
#[cfg(feature = "std")]
pub(crate) use router::dao_parents_for_source;
#[cfg(feature = "std")]
pub use router::DioProcessOutcome;
#[cfg(feature = "std")]
pub use router::Router;
#[cfg(feature = "std")]
pub use router::RplMaintenanceOutcome;

// Re-exports from dtn module
#[cfg(feature = "std")]
pub use dtn::DtnBuffer;
#[cfg(feature = "std")]
pub use dtn::DtnMessage;
#[cfg(feature = "std")]
pub use dtn::DTN_BUFFER_MAX_BYTES;

// Re-exports from lichen-rpl
#[cfg(feature = "std")]
pub use lichen_rpl::dodag::DodagRole;
#[cfg(feature = "std")]
pub use lichen_rpl::dodag::DodagState;
#[cfg(feature = "std")]
pub use lichen_rpl::dodag::ParentCandidate;
#[cfg(feature = "std")]
pub use lichen_rpl::dodag::ROOT_RANK;
#[cfg(feature = "std")]
pub use lichen_rpl::message::Dao;
#[cfg(feature = "std")]
pub use lichen_rpl::message::DaoOriginSignature;
#[cfg(feature = "std")]
pub use lichen_rpl::message::Dio;
#[cfg(feature = "std")]
pub use lichen_rpl::message::DodagConfig;
#[cfg(feature = "std")]
pub use lichen_rpl::message::OptionIter;
#[cfg(feature = "std")]
pub use lichen_rpl::message::RplError;
#[cfg(feature = "std")]
pub use lichen_rpl::message::RplTarget;
#[cfg(feature = "std")]
pub use lichen_rpl::message::SignedDaoEnvelope;
#[cfg(feature = "std")]
pub use lichen_rpl::message::TransitInfo;
#[cfg(feature = "std")]
pub use lichen_rpl::message::DAO_ORIGIN_SIGNATURE_LEN;
#[cfg(feature = "std")]
pub use lichen_rpl::message::OPT_DODAG_CONFIG;
#[cfg(feature = "std")]
pub use lichen_rpl::message::OPT_RPL_TARGET;
#[cfg(feature = "std")]
pub use lichen_rpl::message::OPT_TRANSIT_INFO;
#[cfg(feature = "std")]
pub use lichen_rpl::routing::DaoOriginHighWater;
#[cfg(feature = "std")]
pub use lichen_rpl::routing::DaoPersistentOpenError;
#[cfg(feature = "std")]
pub use lichen_rpl::routing::DaoProvisionError;
#[cfg(feature = "std")]
pub use lichen_rpl::routing::DaoRxState;
#[cfg(feature = "std")]
pub use lichen_rpl::routing::RouteTarget;
#[cfg(feature = "std")]
pub use lichen_rpl::routing::RoutingTable;
#[cfg(feature = "std")]
pub use lichen_rpl::routing::SourceRoutingHeader;
#[cfg(feature = "std")]
pub use lichen_rpl::trickle::TrickleEvent;
#[cfg(feature = "std")]
pub use lichen_rpl::trickle::TrickleTimer;

// Internal re-exports for router module
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::dao_origin_digest;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::DaoAdmissionState;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::DaoManager;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::DaoProcessError;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::DaoProcessOutcome;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::DaoProcessTiming;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::DaoTxError;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::DaoTxState;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::DaoVerifyError;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::SignatureVerifiedDao;
