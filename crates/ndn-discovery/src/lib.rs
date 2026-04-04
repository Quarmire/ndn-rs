//! # ndn-discovery — Pluggable neighbor and service discovery
//!
//! Provides the [`DiscoveryProtocol`] and [`DiscoveryContext`] traits that
//! decouple discovery logic from the engine core, along with supporting types
//! and the [`NoDiscovery`] null object for routers that do not need automatic
//! neighbor finding.
//!
//! ## Architecture
//!
//! The engine owns a single `Arc<dyn DiscoveryProtocol>` field.  Protocols
//! observe face lifecycle events and inbound packets via hooks; they mutate
//! engine state (faces, FIB, neighbor table) exclusively through the narrow
//! [`DiscoveryContext`] interface.
//!
//! Multiple protocols can run simultaneously via [`CompositeDiscovery`], which
//! validates that their claimed name prefixes do not overlap at construction
//! time and routes inbound packets by prefix match.
//!
//! ## Crate layout
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`protocol`] | `DiscoveryProtocol` trait, `ProtocolId` |
//! | [`context`]  | `DiscoveryContext`, `NeighborTableView` traits |
//! | [`neighbor`] | `NeighborTable`, `NeighborEntry`, `NeighborState`, `NeighborUpdate` |
//! | [`mac_addr`] | `MacAddr` — link-layer address shared between discovery and face layer |
//! | [`no_discovery`] | `NoDiscovery` — no-op protocol for standalone deployments |
//! | [`composite`] | `CompositeDiscovery` — runs multiple protocols simultaneously |
//! | [`backoff`] | `BackoffConfig`, `BackoffState` — exponential backoff with jitter |

pub mod backoff;
pub mod composite;
pub mod context;
pub mod hello;
pub mod mac_addr;
pub mod neighbor;
pub mod no_discovery;
pub mod protocol;
pub mod udp_nd;
pub mod wire;

pub use backoff::{BackoffConfig, BackoffState};
pub use composite::CompositeDiscovery;
pub use context::{DiscoveryContext, NeighborTableView};
pub use mac_addr::MacAddr;
pub use neighbor::{NeighborEntry, NeighborState, NeighborTable, NeighborUpdate};
pub use no_discovery::NoDiscovery;
pub use hello::{
    CAP_CONTENT_STORE, CAP_FRAGMENTATION, CAP_SVS, CAP_VALIDATION,
    DiffEntry, HelloPayload, NeighborDiff,
    T_ADD_ENTRY, T_CAPABILITIES, T_NEIGHBOR_DIFF, T_NODE_NAME, T_REMOVE_ENTRY, T_SERVED_PREFIX,
};
pub use protocol::{DiscoveryProtocol, InboundMeta, LinkAddr, ProtocolId};
pub use udp_nd::UdpNeighborDiscovery;
