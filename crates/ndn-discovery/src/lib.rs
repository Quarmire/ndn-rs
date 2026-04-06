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
//! | [`protocol`]        | `DiscoveryProtocol` trait, `ProtocolId` |
//! | [`context`]         | `DiscoveryContext`, `NeighborTableView` traits |
//! | [`neighbor`]        | `NeighborTable`, `NeighborEntry`, `NeighborState`, `NeighborUpdate` |
//! | [`mac_addr`]        | `MacAddr` — link-layer address shared between discovery and face layer |
//! | [`no_discovery`]    | `NoDiscovery` — no-op protocol for standalone deployments |
//! | [`composite`]       | `CompositeDiscovery` — runs multiple protocols simultaneously |
//! | [`backoff`]         | `BackoffConfig`, `BackoffState` — exponential backoff with jitter |
//! | [`config`]          | `DiscoveryConfig`, `DiscoveryProfile`, `ServiceDiscoveryConfig` |
//! | [`scope`]           | Well-known namespace prefixes and link-local scope predicates |
//! | [`strategy`]        | `NeighborProbeStrategy` trait and scheduler implementations |
//! | [`probe`]           | SWIM direct/indirect probe packet builders and parsers |
//! | [`prefix_announce`] | Service record publisher and browser (`/ndn/local/sd/services/`) |

#![allow(missing_docs)]

pub mod backoff;
pub mod composite;
pub mod config;
pub mod context;
pub mod gossip;
pub mod hello;
pub mod hello_protocol;
pub mod link_medium;
pub mod mac_addr;
pub mod neighbor;
pub mod no_discovery;
pub mod prefix_announce;
pub mod probe;
pub mod protocol;
pub mod scope;
pub mod service_discovery;
pub mod strategy;
pub mod udp_nd;
pub mod wire;

pub use backoff::{BackoffConfig, BackoffState};
pub use composite::CompositeDiscovery;
pub use config::{
    DiscoveryConfig, DiscoveryProfile, DiscoveryScope, HelloStrategyKind, PrefixAnnouncementMode,
    ServiceDiscoveryConfig, ServiceValidationPolicy,
};
pub use context::{DiscoveryContext, NeighborTableView};
pub use gossip::{EpidemicGossip, SvsServiceDiscovery};
pub use hello::{
    CAP_CONTENT_STORE, CAP_FRAGMENTATION, CAP_SVS, CAP_VALIDATION, DiffEntry, HelloPayload,
    NeighborDiff, T_ADD_ENTRY, T_CAPABILITIES, T_NEIGHBOR_DIFF, T_NODE_NAME, T_REMOVE_ENTRY,
    T_SERVED_PREFIX,
};
pub use hello_protocol::HelloProtocol;
pub use link_medium::{HelloCore, HelloState, LinkMedium};
pub use mac_addr::MacAddr;
pub use neighbor::{NeighborEntry, NeighborState, NeighborTable, NeighborUpdate};
pub use no_discovery::NoDiscovery;
pub use prefix_announce::{ServiceRecord, build_browse_interest, make_record_name};
pub use probe::{
    DirectProbe, IndirectProbe, build_direct_probe, build_indirect_probe,
    build_indirect_probe_encoded, build_probe_ack, is_probe_ack, parse_direct_probe,
    parse_indirect_probe,
};
pub use protocol::{DiscoveryProtocol, InboundMeta, LinkAddr, ProtocolId};
pub use scope::{
    global_root, gossip_prefix, hello_prefix, is_link_local, is_nd_packet, is_sd_packet,
    mgmt_prefix, nd_root, ndn_local, peers_prefix, probe_direct, probe_via, routing_lsa,
    routing_prefix, scope_root, sd_services, sd_updates, site_root,
};
pub use service_discovery::{ServiceDiscoveryProtocol, decode_peer_list};
pub use strategy::composite::CompositeStrategy;
pub use strategy::{
    BackoffScheduler, NeighborProbeStrategy, PassiveScheduler, ProbeRequest, ReactiveScheduler,
    SwimScheduler, TriggerEvent, build_strategy,
};
pub use udp_nd::UdpNeighborDiscovery;
