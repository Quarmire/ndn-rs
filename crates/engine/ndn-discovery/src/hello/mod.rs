//! SWIM/Hello neighbor discovery protocol family.
//!
//! `HelloProtocol<T>` is the generic state machine; `LinkMedium` implementations
//! provide link-specific face creation, signing, and address extraction.

pub mod medium;
pub mod payload;
pub mod probe;
pub mod protocol;

#[cfg(feature = "udp-hello")]
pub mod udp;

#[cfg(all(feature = "ether-nd", target_os = "linux"))]
pub mod ether;

pub use medium::{HELLO_PREFIX_DEPTH, HELLO_PREFIX_STR, HelloCore, HelloState, LinkMedium};
pub use payload::{
    CAP_CONTENT_STORE, CAP_FRAGMENTATION, CAP_SVS, CAP_VALIDATION, DiffEntry, HelloPayload,
    NeighborDiff, T_ADD_ENTRY, T_CAPABILITIES, T_NEIGHBOR_DIFF, T_NODE_NAME, T_PUBLIC_KEY,
    T_REMOVE_ENTRY, T_SERVED_PREFIX, T_UNICAST_PORT,
};
pub use probe::{
    DirectProbe, IndirectProbe, build_direct_probe, build_indirect_probe,
    build_indirect_probe_encoded, build_probe_ack, is_probe_ack, parse_direct_probe,
    parse_indirect_probe,
};
pub use protocol::HelloProtocol;

#[cfg(feature = "udp-hello")]
pub use udp::UdpNeighborDiscovery;
