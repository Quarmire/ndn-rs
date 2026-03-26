use smallvec::{SmallVec, smallvec};

use ndn_packet::Name;
use ndn_pipeline::{ForwardingAction, NackReason};
use ndn_transport::FaceId;

use crate::{Strategy, StrategyContext};

/// Multicast strategy: forward on all FIB nexthops except the incoming face.
pub struct MulticastStrategy {
    name: Name,
}

impl MulticastStrategy {
    pub fn new() -> Self {
        Self { name: Name::root() }
    }
}

impl Default for MulticastStrategy {
    fn default() -> Self { Self::new() }
}

impl Strategy for MulticastStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    async fn after_receive_interest(
        &self,
        ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        let Some(fib) = ctx.fib_entry else {
            return smallvec![ForwardingAction::Nack(NackReason::NoRoute)];
        };
        let faces: SmallVec<[FaceId; 4]> = fib
            .nexthops_excluding(ctx.in_face)
            .into_iter()
            .map(|n| n.face_id)
            .collect();
        if faces.is_empty() {
            return smallvec![ForwardingAction::Nack(NackReason::NoRoute)];
        }
        smallvec![ForwardingAction::Forward(faces)]
    }

    async fn after_receive_data(
        &self,
        _ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        SmallVec::new()
    }
}
