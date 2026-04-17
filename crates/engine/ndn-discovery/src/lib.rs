//! # ndn-discovery — Pluggable neighbor and service discovery
//!
//! Provides the [`DiscoveryProtocol`] and [`DiscoveryContext`] traits that
//! decouple discovery logic from the engine core, along with supporting types
//! and the [`NoDiscovery`] null object for routers that do not need automatic
//! neighbor finding.

#![allow(missing_docs)]

pub mod backoff;
pub mod composite;
pub mod config;
pub mod context;
pub mod gossip;
pub mod hello;
pub mod mac_addr;
pub mod neighbor;
pub mod no_discovery;
pub mod prefix_announce;
pub mod protocol;
pub mod scope;
pub mod service_discovery;
pub mod strategy;
pub mod wire;

pub use backoff::{BackoffConfig, BackoffState};
pub use composite::CompositeDiscovery;
pub use config::{
    DiscoveryConfig, DiscoveryProfile, DiscoveryScope, HelloStrategyKind, PrefixAnnouncementMode,
    ServiceDiscoveryConfig, ServiceValidationPolicy,
};
pub use context::{DiscoveryContext, NeighborTableView};
pub use gossip::{EpidemicGossip, SvsServiceDiscovery};
#[cfg(feature = "udp-hello")]
pub use hello::UdpNeighborDiscovery;
#[cfg(all(feature = "ether-nd", target_os = "linux"))]
pub use hello::ether::EtherNeighborDiscovery;
pub use hello::{
    CAP_CONTENT_STORE, CAP_FRAGMENTATION, CAP_SVS, CAP_VALIDATION, DiffEntry, HelloPayload,
    NeighborDiff, T_ADD_ENTRY, T_CAPABILITIES, T_NEIGHBOR_DIFF, T_NODE_NAME, T_REMOVE_ENTRY,
    T_SERVED_PREFIX,
};
pub use hello::{
    DirectProbe, IndirectProbe, build_direct_probe, build_indirect_probe,
    build_indirect_probe_encoded, build_probe_ack, is_probe_ack, parse_direct_probe,
    parse_indirect_probe,
};
pub use hello::{HelloCore, HelloProtocol, HelloState, LinkMedium};
pub use mac_addr::MacAddr;
pub use neighbor::{NeighborEntry, NeighborState, NeighborTable, NeighborUpdate};
pub use no_discovery::NoDiscovery;
pub use prefix_announce::{ServiceRecord, build_browse_interest, make_record_name};
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
