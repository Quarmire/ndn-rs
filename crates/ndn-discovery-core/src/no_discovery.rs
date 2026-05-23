//! Null-object discovery protocol.

use std::time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::{DiscoveryContext, DiscoveryProtocol, InboundMeta, ProtocolId};

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
        impl crate::FaceLifecycleContext for StubCtx {
            fn alloc_face_id(&self) -> FaceId {
                FaceId(0)
            }
            fn add_face(&self, _: std::sync::Arc<ndn_transport::Face>) -> FaceId {
                FaceId(0)
            }
            fn remove_face(&self, _: FaceId) {}
        }
        impl crate::RoutingTableContext for StubCtx {
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
        }
        impl crate::NeighborContext for StubCtx {
            fn neighbors(&self) -> std::sync::Arc<dyn crate::NeighborTableView> {
                crate::NeighborTable::new()
            }
            fn update_neighbor(&self, _: crate::NeighborUpdate) {}
        }
        impl crate::DiscoveryContext for StubCtx {
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
