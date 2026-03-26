use smallvec::{SmallVec, smallvec};

use ndn_packet::Name;
use ndn_pipeline::{ForwardingAction, NackReason};

use crate::{Strategy, StrategyContext};

/// Best-route strategy: forward on the lowest-cost FIB nexthop, excluding the
/// incoming face (split-horizon).
pub struct BestRouteStrategy {
    name: Name,
}

impl BestRouteStrategy {
    pub fn new() -> Self {
        Self { name: Name::root() }
    }
}

impl Default for BestRouteStrategy {
    fn default() -> Self { Self::new() }
}

impl Strategy for BestRouteStrategy {
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
        let nexthops = fib.nexthops_excluding(ctx.in_face);
        match nexthops.first() {
            Some(nh) => smallvec![ForwardingAction::Forward(smallvec![nh.face_id])],
            None     => smallvec![ForwardingAction::Nack(NackReason::NoRoute)],
        }
    }

    async fn after_receive_data(
        &self,
        _ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        // Fan-back to in-record faces is handled by the engine via PIT lookup.
        SmallVec::new()
    }
}
