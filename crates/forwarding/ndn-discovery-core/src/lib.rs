//! `DiscoveryProtocol` trait, `NeighborTable`, `NoDiscovery` default.
//!
//! Lives in its own crate so `ndn-engine` can depend on the trait without
//! pulling in concrete (and wasm-incompatible) discovery implementations.
//! Native protocols live in `ndn-discovery`.

#![allow(missing_docs)]

pub mod backoff;
pub mod context;
pub mod mac_addr;
pub mod neighbor;
pub mod no_discovery;
pub mod protocol;
pub mod scope;

pub use backoff::{BackoffConfig, BackoffState};
pub use context::{
    DiscoveryContext, FaceLifecycleContext, NeighborContext, NeighborTableView, RoutingTableContext,
};
pub use mac_addr::MacAddr;
pub use neighbor::{NeighborEntry, NeighborState, NeighborTable, NeighborUpdate};
pub use no_discovery::NoDiscovery;
pub use protocol::{DiscoveryProtocol, InboundMeta, LinkAddr, ProtocolId};
pub use scope::{
    DiscoveryScope, global_root, gossip_prefix, is_link_local, is_nd_packet, is_sd_packet,
    localhop_autoconf_hub, mgmt_prefix, nd_root, ndn_local, peers_prefix, probe_ping, routing_lsa,
    routing_prefix, scope_root, sd_root, sd_service_info_under, sd_services, sd_services_under,
    sd_updates, sd_updates_under, site_root,
};
