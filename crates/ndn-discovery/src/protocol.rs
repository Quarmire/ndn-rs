//! `DiscoveryProtocol` trait, `ProtocolId`, and `InboundMeta` types.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::{DiscoveryContext, MacAddr};

/// Link-layer source address of an inbound packet.
///
/// Populated by the engine when the face layer can provide a sender address
/// (multicast faces via `recv_with_source`). `None` for unicast faces where
/// the sender identity is already implicit in the face itself.
#[derive(Clone, Debug)]
pub enum LinkAddr {
    /// Source MAC extracted from the Ethernet frame header.
    Ether(MacAddr),
    /// Source IP:port extracted from the UDP socket (`recvfrom`).
    Udp(SocketAddr),
}

/// Per-packet metadata passed to [`DiscoveryProtocol::on_inbound`].
///
/// Carries side-channel information that does not appear in the NDN wire
/// bytes — primarily the link-layer source address needed to create a
/// unicast reply face without embedding addresses in the Interest payload.
#[derive(Clone, Debug, Default)]
pub struct InboundMeta {
    /// Source address of the sender, if the face layer exposed it.
    pub source: Option<LinkAddr>,
}

impl InboundMeta {
    /// Metadata with no source address (unicast face or unknown sender).
    pub const fn none() -> Self {
        Self { source: None }
    }

    /// Metadata carrying an Ethernet source MAC.
    pub fn ether(mac: MacAddr) -> Self {
        Self { source: Some(LinkAddr::Ether(mac)) }
    }

    /// Metadata carrying a UDP source address.
    pub fn udp(addr: SocketAddr) -> Self {
        Self { source: Some(LinkAddr::Udp(addr)) }
    }
}

/// Stable identifier for a discovery protocol instance.
///
/// Used to tag FIB entries so they can be bulk-removed when the protocol
/// stops or reconfigures, and to route inbound packets in `CompositeDiscovery`
/// without ambiguity.
///
/// Implementations should use a short, descriptive ASCII string such as
/// `"ether-nd"`, `"swim"`, or `"sd-browser"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolId(pub &'static str);

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// A pluggable discovery protocol.
///
/// Implementations observe face lifecycle events and inbound packets;
/// they mutate engine state exclusively through the [`DiscoveryContext`]
/// interface, making them decoupled from the engine and independently
/// testable.
///
/// # Namespace isolation
///
/// Each protocol declares which NDN name prefixes it uses via
/// [`claimed_prefixes`].  [`CompositeDiscovery`] checks at construction
/// time that no two protocols claim overlapping prefixes.  All discovery
/// prefixes live under the reserved `/ndn/local/` sub-tree.
///
/// [`CompositeDiscovery`]: crate::CompositeDiscovery
pub trait DiscoveryProtocol: Send + Sync + 'static {
    /// Unique protocol identifier.
    fn protocol_id(&self) -> ProtocolId;

    /// NDN name prefixes this protocol reserves.
    ///
    /// Typically sub-prefixes of `/ndn/local/nd/` (neighbor discovery) or
    /// `/ndn/local/sd/` (service discovery).  Used for namespace conflict
    /// detection and inbound routing in `CompositeDiscovery`.
    fn claimed_prefixes(&self) -> &[Name];

    /// Called when a new face comes up (after `FaceTable::insert`).
    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    /// Called when a face goes down (before `FaceTable::remove`).
    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    /// Called for every inbound raw packet before it enters the pipeline.
    ///
    /// Returns `true` if the packet was consumed by this protocol and should
    /// **not** be forwarded through the NDN pipeline.  Return `false` to let
    /// the packet continue normally.
    ///
    /// `meta` carries the link-layer source address when the face layer
    /// exposes it (multicast faces). Discovery protocols use `meta.source`
    /// to create unicast reply faces without embedding addresses in the
    /// Interest payload.
    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool;

    /// Periodic tick, called by the engine's tick task at `tick_interval`.
    ///
    /// Use this to send hellos, check timeouts, rotate probes, and update
    /// SWIM gossip state.
    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext);

    /// How often the engine should call `on_tick`.
    ///
    /// The default (100 ms) works for most deployments.  High-mobility
    /// profiles may use 20–50 ms; static deployments may use 1 s.
    fn tick_interval(&self) -> Duration {
        Duration::from_millis(100)
    }
}
