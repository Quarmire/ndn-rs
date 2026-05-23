use std::sync::Arc;

use bytes::Bytes;
use smallvec::{SmallVec, smallvec};

use ndn_packet::{Name, NameComponent};
use ndn_transport::FaceId;
use ndn_transport::{ForwardingAction, NackReason};

use crate::{ErasedStrategy, Strategy, StrategyContext, register_strategy};

register_strategy!(
    MULTICAST_REG,
    b"multicast",
    5,
    || Arc::new(MulticastStrategy::new()) as Arc<dyn ErasedStrategy>,
);

/// Multicast strategy: forward on all FIB nexthops except the incoming face.
pub struct MulticastStrategy {
    name: Name,
}

impl MulticastStrategy {
    /// Canonical NFD name `/localhost/nfd/strategy/multicast/v=5`.
    /// Trailing `VersionNameComponent` (TLV 0x36) matches NFD
    /// `daemon/fw/multicast-strategy.cpp` `appendVersion(5)`.
    pub fn strategy_name() -> Name {
        Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhost")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"strategy")),
            NameComponent::generic(Bytes::from_static(b"multicast")),
        ])
        .append_version(5)
    }

    pub fn new() -> Self {
        Self {
            name: Self::strategy_name(),
        }
    }
}

impl Default for MulticastStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for MulticastStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        let Some(fib) = ctx.fib_entry else {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        };
        let faces: SmallVec<[FaceId; 4]> = fib
            .nexthops_excluding(ctx.in_face)
            .into_iter()
            .map(|n| n.face_id)
            .collect();
        if faces.is_empty() {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        }
        Some(smallvec![ForwardingAction::Forward(faces)])
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
        static RUNTIME: std::sync::LazyLock<Arc<dyn ndn_runtime::Runtime>> =
            std::sync::LazyLock::new(|| Arc::new(ndn_runtime::TokioRuntime));
        StrategyContext {
            name,
            in_face,
            fib_entry,
            pit_token: None,
            measurements,
            signals: &crate::NoSignals,
            extensions: &EMPTY,
            runtime: &RUNTIME,
        }
    }

    #[tokio::test]
    async fn no_fib_returns_nack() {
        let s = MulticastStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let ctx = make_ctx(&name, FaceId(0), None, &m);
        let actions = s.after_receive_interest(&ctx).await;
        assert!(matches!(
            actions.as_slice(),
            [ForwardingAction::Nack(NackReason::NoRoute)]
        ));
    }

    #[tokio::test]
    async fn all_nexthops_sent_except_in_face() {
        let s = MulticastStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let fib = FibEntry {
            nexthops: vec![
                FibNexthop {
                    face_id: FaceId(1),
                    cost: 0,
                },
                FibNexthop {
                    face_id: FaceId(2),
                    cost: 0,
                },
                FibNexthop {
                    face_id: FaceId(3),
                    cost: 0,
                },
            ],
        };
        let ctx = make_ctx(&name, FaceId(1), Some(&fib), &m);
        let actions = s.after_receive_interest(&ctx).await;
        if let [ForwardingAction::Forward(faces)] = actions.as_slice() {
            assert_eq!(faces.len(), 2);
            assert!(faces.contains(&FaceId(2)));
            assert!(faces.contains(&FaceId(3)));
            assert!(!faces.contains(&FaceId(1)));
        } else {
            panic!("expected Forward");
        }
    }

    #[tokio::test]
    async fn all_nexthops_excluded_returns_nack() {
        let s = MulticastStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let fib = FibEntry {
            nexthops: vec![FibNexthop {
                face_id: FaceId(1),
                cost: 0,
            }],
        };
        let ctx = make_ctx(&name, FaceId(1), Some(&fib), &m);
        let actions = s.after_receive_interest(&ctx).await;
        assert!(matches!(
            actions.as_slice(),
            [ForwardingAction::Nack(NackReason::NoRoute)]
        ));
    }

    #[tokio::test]
    async fn after_receive_data_is_empty() {
        let s = MulticastStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let ctx = make_ctx(&name, FaceId(0), None, &m);
        assert!(s.after_receive_data(&ctx).await.is_empty());
    }

    #[test]
    fn strategy_name_ends_with_version_v5() {
        let s = MulticastStrategy::new();
        let comps = Strategy::name(&s).components();
        assert_eq!(comps.len(), 5);
        let last = comps.last().expect("non-empty name");
        assert_eq!(last.typ, ndn_packet::tlv_type::VERSION);
        assert_eq!(last.value.as_ref(), &[5u8]);
    }
}
