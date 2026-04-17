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
/// (multicast faces via `recv_with_source`).
#[derive(Clone, Debug)]
pub enum LinkAddr {
    Ether(MacAddr),
    Udp(SocketAddr),
}

/// Per-packet metadata passed to [`DiscoveryProtocol::on_inbound`].
///
/// Carries side-channel information that does not appear in the NDN wire
/// bytes -- primarily the link-layer source address needed to create a
/// unicast reply face without embedding addresses in the Interest payload.
#[derive(Clone, Debug, Default)]
pub struct InboundMeta {
    pub source: Option<LinkAddr>,
}

impl InboundMeta {
    pub const fn none() -> Self {
        Self { source: None }
    }

    pub fn ether(mac: MacAddr) -> Self {
        Self {
            source: Some(LinkAddr::Ether(mac)),
        }
    }

    pub fn udp(addr: SocketAddr) -> Self {
        Self {
            source: Some(LinkAddr::Udp(addr)),
        }
    }
}

/// Stable identifier for a discovery protocol instance.
///
/// Used to tag FIB entries for bulk removal on protocol shutdown, and to
/// route inbound packets in `CompositeDiscovery`.
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
/// interface.  Each protocol declares reserved name prefixes via
/// [`claimed_prefixes`]; [`CompositeDiscovery`](crate::CompositeDiscovery)
/// enforces non-overlapping prefixes at construction time.
pub trait DiscoveryProtocol: Send + Sync + 'static {
    fn protocol_id(&self) -> ProtocolId;

    /// NDN name prefixes this protocol reserves (under `/ndn/local/`).
    fn claimed_prefixes(&self) -> &[Name];

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    /// Returns `true` if the packet was consumed and should not enter the
    /// forwarding pipeline.
    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool;

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext);

    /// How often the engine should call `on_tick`.  Default: 100 ms.
    fn tick_interval(&self) -> Duration {
        Duration::from_millis(100)
    }
}
