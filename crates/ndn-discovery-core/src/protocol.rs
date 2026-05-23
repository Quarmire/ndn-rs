//! `DiscoveryProtocol` trait, `ProtocolId`, `InboundMeta`.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::{DiscoveryContext, MacAddr};

/// Link-layer source observed on an inbound discovery packet. Lets a
/// protocol pin a unicast reply without parsing the NDN content for a
/// self-reported address.
#[derive(Clone, Debug)]
pub enum LinkAddr {
    Ether(MacAddr),
    Udp(SocketAddr),
}

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

/// Stable owner id for FIB / neighbour-table entries installed by a
/// discovery or routing protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolId(pub &'static str);

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Pluggable neighbour / service discovery protocol driven by the
/// engine's discovery dispatcher.
///
/// Implementations must be `Send + Sync` and may be invoked concurrently
/// from the engine's read and tick tasks.
pub trait DiscoveryProtocol: Send + Sync + 'static {
    fn protocol_id(&self) -> ProtocolId;

    /// Prefixes routed into [`Self::on_inbound`]; non-matching packets
    /// flow through the normal forwarding pipeline.
    fn claimed_prefixes(&self) -> &[Name];

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    /// Return `true` to consume the packet (it will not be forwarded),
    /// `false` to let the pipeline forward it.
    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool;

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext);

    /// Default 100ms.
    fn tick_interval(&self) -> Duration {
        Duration::from_millis(100)
    }
}
