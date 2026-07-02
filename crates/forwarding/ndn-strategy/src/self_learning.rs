use std::sync::Arc;

use bytes::Bytes;
use smallvec::{SmallVec, smallvec};

use ndn_packet::{Name, NameComponent};
use ndn_transport::ForwardingAction;

use crate::{ErasedStrategy, Strategy, StrategyContext, register_strategy};

register_strategy!(
    SELF_LEARNING_REG,
    b"self-learning",
    1,
    || Arc::new(SelfLearningStrategy::new()) as Arc<dyn ErasedStrategy>,
);

/// Self-learning strategy (mirrors NFD `self-learning-strategy.cpp`): with no
/// usable route, **flood** the Interest as a discovery probe (`Broadcast`);
/// with a route, forward on all nexthops (excluding the incoming face). Routes
/// are *learned* from validated PrefixAnnouncements carried back on Data — the
/// engine validates the announcement and installs the route (the strategy stays
/// side-effect-free; see the data pipeline's self-learning hook).
pub struct SelfLearningStrategy {
    name: Name,
}

impl SelfLearningStrategy {
    /// `/localhost/nfd/strategy/self-learning/v=1`.
    pub fn strategy_name() -> Name {
        Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhost")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"strategy")),
            NameComponent::generic(Bytes::from_static(b"self-learning")),
        ])
        .append_version(1)
    }

    pub fn new() -> Self {
        Self {
            name: Self::strategy_name(),
        }
    }
}

impl Default for SelfLearningStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for SelfLearningStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        let faces: SmallVec<[ndn_transport::FaceId; 4]> = ctx
            .fib_entry
            .map(|fib| {
                fib.nexthops_excluding(ctx.in_face)
                    .into_iter()
                    .map(|n| n.face_id)
                    .collect()
            })
            .unwrap_or_default();
        if faces.is_empty() {
            // No usable route → discovery flood.
            Some(smallvec![ForwardingAction::Broadcast])
        } else {
            Some(smallvec![ForwardingAction::Forward(faces)])
        }
    }

    fn after_receive_interest(&self, ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        self.decide(ctx).unwrap()
    }

    fn after_receive_data(&self, _ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        // Route learning from PrefixAnnouncements happens engine-side (the data
        // pipeline validates the announcement before installing).
        SmallVec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MeasurementsTable;
    use crate::context::{FibEntry, FibNexthop};
    use ndn_transport::FaceId;

    fn ctx<'a>(
        name: &'a Arc<Name>,
        in_face: FaceId,
        fib: Option<&'a FibEntry>,
        m: &'a MeasurementsTable,
    ) -> StrategyContext<'a> {
        static EMPTY: std::sync::LazyLock<ndn_transport::AnyMap> =
            std::sync::LazyLock::new(ndn_transport::AnyMap::new);
        static RT: std::sync::LazyLock<Arc<dyn ndn_runtime::Runtime>> =
            std::sync::LazyLock::new(|| Arc::new(ndn_runtime::TokioRuntime));
        StrategyContext {
            name,
            in_face,
            fib_entry: fib,
            pit_token: None,
            tried_faces: &[],
            measurements: m,
            signals: &crate::NoSignals,
            extensions: &EMPTY,
            runtime: &RT,
        }
    }

    #[tokio::test]
    async fn no_route_broadcasts() {
        let s = SelfLearningStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let actions = s.after_receive_interest(&ctx(&name, FaceId(1), None, &m));
        assert!(matches!(actions.as_slice(), [ForwardingAction::Broadcast]));
    }

    #[tokio::test]
    async fn route_forwards_on_nexthops() {
        let s = SelfLearningStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let fib = FibEntry {
            nexthops: vec![FibNexthop {
                face_id: FaceId(2),
                cost: 10,
            }],
        };
        let actions = s.after_receive_interest(&ctx(&name, FaceId(1), Some(&fib), &m));
        match actions.as_slice() {
            [ForwardingAction::Forward(faces)] => assert_eq!(faces.as_slice(), &[FaceId(2)]),
            _ => panic!("expected Forward to the learned nexthop"),
        }
    }
}
