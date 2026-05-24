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

    /// Stable per-sender id for NDNLPv2 reassembly keying on a multi-access
    /// face. `0` means "no link-layer source" (point-to-point / unicast), which
    /// the reassembler treats as a single stream. Distinct senders on a shared
    /// medium (Ethernet/UDP multicast, BLE advertising) get distinct ids so
    /// their fragment sequences cannot alias into a corrupt reassembly. Mirrors
    /// NFD's `(EndpointId, Sequence)` reassembly key.
    pub fn endpoint_id(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        match &self.source {
            None => 0,
            Some(LinkAddr::Ether(mac)) => {
                // 48-bit MAC packed into the low bits — never collides for
                // distinct MACs. `max(1)` keeps it distinct from the unicast 0.
                let b = mac.as_bytes();
                let v = (b[0] as u64) << 40
                    | (b[1] as u64) << 32
                    | (b[2] as u64) << 24
                    | (b[3] as u64) << 16
                    | (b[4] as u64) << 8
                    | (b[5] as u64);
                v.max(1)
            }
            Some(LinkAddr::Udp(addr)) => {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                addr.hash(&mut h);
                h.finish().max(1)
            }
        }
    }
}

#[cfg(test)]
mod endpoint_id_tests {
    use super::*;
    use crate::MacAddr;

    #[test]
    fn endpoint_id_distinguishes_senders() {
        let a = InboundMeta::ether(MacAddr([0xAA, 0, 0, 0, 0, 1]));
        let b = InboundMeta::ether(MacAddr([0xAA, 0, 0, 0, 0, 2]));
        assert_ne!(a.endpoint_id(), b.endpoint_id(), "distinct MACs → distinct ids");
        assert_eq!(
            a.endpoint_id(),
            InboundMeta::ether(MacAddr([0xAA, 0, 0, 0, 0, 1])).endpoint_id(),
            "same MAC → same id"
        );
        assert_eq!(InboundMeta::none().endpoint_id(), 0, "no source → unicast 0");
        assert_ne!(a.endpoint_id(), 0, "a real sender id must not collide with unicast 0");
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
