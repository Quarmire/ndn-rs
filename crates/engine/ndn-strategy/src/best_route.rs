use bytes::Bytes;
use smallvec::{SmallVec, smallvec};

use ndn_packet::{Name, NameComponent};
use ndn_transport::{ForwardingAction, NackReason};

use crate::{Strategy, StrategyContext};

/// Best-route strategy: forward on the lowest-cost FIB nexthop, excluding the
/// incoming face (split-horizon).
pub struct BestRouteStrategy {
    name: Name,
}

impl BestRouteStrategy {
    pub fn strategy_name() -> Name {
        Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhost")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"strategy")),
            NameComponent::generic(Bytes::from_static(b"best-route")),
        ])
    }

    pub fn new() -> Self {
        Self {
            name: Self::strategy_name(),
        }
    }
}

impl Default for BestRouteStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for BestRouteStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        let Some(fib) = ctx.fib_entry else {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        };
        let nexthops = fib.nexthops_excluding(ctx.in_face);
        match nexthops.first() {
            Some(nh) => Some(smallvec![ForwardingAction::Forward(smallvec![nh.face_id])]),
            None => Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]),
        }
    }

    async fn after_receive_interest(
        &self,
        ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        self.decide(ctx).unwrap()
    }

    async fn after_receive_data(
        &self,
        _ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        SmallVec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MeasurementsTable;
    use crate::context::{FibEntry, FibNexthop};
    use ndn_transport::FaceId;
    use std::sync::Arc;

    fn make_ctx<'a>(
        name: &'a Arc<Name>,
        in_face: FaceId,
        fib_entry: Option<&'a FibEntry>,
        measurements: &'a MeasurementsTable,
    ) -> StrategyContext<'a> {
        static EMPTY: std::sync::LazyLock<ndn_transport::AnyMap> =
            std::sync::LazyLock::new(ndn_transport::AnyMap::new);
        StrategyContext {
            name,
            in_face,
            fib_entry,
            pit_token: None,
            measurements,
            extensions: &EMPTY,
        }
    }

    #[tokio::test]
    async fn no_fib_entry_returns_nack_no_route() {
        let strategy = BestRouteStrategy::new();
        let name = Arc::new(Name::root());
        let measurements = MeasurementsTable::new();
        let ctx = make_ctx(&name, FaceId(0), None, &measurements);
        let actions = strategy.after_receive_interest(&ctx).await;
        assert!(matches!(
            actions.as_slice(),
            [ForwardingAction::Nack(NackReason::NoRoute)]
        ));
    }

    #[tokio::test]
    async fn best_nexthop_selected() {
        let strategy = BestRouteStrategy::new();
        let name = Arc::new(Name::root());
        let measurements = MeasurementsTable::new();
        let fib = FibEntry {
            nexthops: vec![
                FibNexthop {
                    face_id: FaceId(2),
                    cost: 10,
                },
                FibNexthop {
                    face_id: FaceId(3),
                    cost: 20,
                },
            ],
        };
        let ctx = make_ctx(&name, FaceId(1), Some(&fib), &measurements);
        let actions = strategy.after_receive_interest(&ctx).await;
        // First nexthop not equal to in_face should be forwarded
        if let [ForwardingAction::Forward(faces)] = actions.as_slice() {
            assert_eq!(faces[0], FaceId(2));
        } else {
            panic!("expected Forward");
        }
    }

    #[tokio::test]
    async fn split_horizon_excludes_in_face() {
        let strategy = BestRouteStrategy::new();
        let name = Arc::new(Name::root());
        let measurements = MeasurementsTable::new();
        // Only nexthop is the same as in_face → no route
        let fib = FibEntry {
            nexthops: vec![FibNexthop {
                face_id: FaceId(1),
                cost: 0,
            }],
        };
        let ctx = make_ctx(&name, FaceId(1), Some(&fib), &measurements);
        let actions = strategy.after_receive_interest(&ctx).await;
        assert!(matches!(
            actions.as_slice(),
            [ForwardingAction::Nack(NackReason::NoRoute)]
        ));
    }

    #[tokio::test]
    async fn after_receive_data_returns_empty() {
        let strategy = BestRouteStrategy::new();
        let name = Arc::new(Name::root());
        let measurements = MeasurementsTable::new();
        let ctx = make_ctx(&name, FaceId(0), None, &measurements);
        let actions = strategy.after_receive_data(&ctx).await;
        assert!(actions.is_empty());
    }

    #[test]
    fn strategy_name() {
        let s = BestRouteStrategy::new();
        let comps = s.name().components();
        assert_eq!(comps.len(), 4);
        assert_eq!(comps[3].value.as_ref(), b"best-route");
    }
}
