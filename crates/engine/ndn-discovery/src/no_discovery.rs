//! `NoDiscovery` — null-object discovery protocol.

use std::time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::{DiscoveryContext, DiscoveryProtocol, InboundMeta, ProtocolId};

/// No-op discovery protocol.  All hooks are empty; claims no prefixes.
pub struct NoDiscovery;

impl DiscoveryProtocol for NoDiscovery {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId("no-discovery")
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &[]
    }

    fn on_face_up(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}
    fn on_face_down(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    fn on_inbound(
        &self,
        _raw: &Bytes,
        _incoming_face: FaceId,
        _meta: &InboundMeta,
        _ctx: &dyn DiscoveryContext,
    ) -> bool {
        false
    }

    fn on_tick(&self, _now: Instant, _ctx: &dyn DiscoveryContext) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DiscoveryProtocol;

    #[test]
    fn no_discovery_claims_no_prefixes() {
        assert!(NoDiscovery.claimed_prefixes().is_empty());
    }

    #[test]
    fn no_discovery_never_consumes() {
        struct StubCtx;
        impl crate::DiscoveryContext for StubCtx {
            fn alloc_face_id(&self) -> FaceId {
                FaceId(0)
            }
            fn add_face(&self, _: std::sync::Arc<dyn ndn_transport::ErasedFace>) -> FaceId {
                FaceId(0)
            }
            fn remove_face(&self, _: FaceId) {}
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
            fn neighbors(&self) -> std::sync::Arc<dyn crate::NeighborTableView> {
                crate::NeighborTable::new()
            }
            fn update_neighbor(&self, _: crate::NeighborUpdate) {}
            fn send_on(&self, _: FaceId, _: bytes::Bytes) {}
            fn now(&self) -> std::time::Instant {
                std::time::Instant::now()
            }
        }

        let ctx = StubCtx;
        let pkt = Bytes::from_static(b"\x05\x10hello");
        assert!(!NoDiscovery.on_inbound(&pkt, FaceId(1), &InboundMeta::none(), &ctx));
    }
}
