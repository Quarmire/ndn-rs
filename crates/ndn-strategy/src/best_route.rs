use std::sync::Arc;

use bytes::Bytes;
use smallvec::{SmallVec, smallvec};

use ndn_packet::{Name, NameComponent};
use ndn_transport::{ForwardingAction, NackReason};

use crate::{ErasedStrategy, Strategy, StrategyContext, register_strategy};

register_strategy!(
    BEST_ROUTE_REG,
    b"best-route",
    5,
    || Arc::new(BestRouteStrategy::new()) as Arc<dyn ErasedStrategy>,
);

/// Best-route strategy: forward on the lowest-cost FIB nexthop, excluding the
/// incoming face (split-horizon).
pub struct BestRouteStrategy {
    name: Name,
}

impl BestRouteStrategy {
    /// Canonical NFD name `/localhost/nfd/strategy/best-route/v=5`.
    /// Trailing `VersionNameComponent` (TLV 0x36) matches NFD
    /// `daemon/fw/best-route-strategy.cpp` `appendVersion(5)`.
    pub fn strategy_name() -> Name {
        Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhost")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"strategy")),
            NameComponent::generic(Bytes::from_static(b"best-route")),
        ])
        .append_version(5)
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

    /// On Nack, exclude the nacking upstream (`in_face`) and retry on
    /// the next-best nexthop; propagate the Nack downstream if none
    /// remain. Mirrors NFD `daemon/fw/best-route-strategy.cpp`
    /// `afterReceiveNack` → `processNack`.
    ///
    /// Without per-PIT-entry out-records, two nexthops that mutually
    /// nack can ping-pong; bounded in practice by HopLimit, PIT
    /// lifetime, and nonce-based loop detection.
    async fn on_nack(
        &self,
        ctx: &StrategyContext<'_>,
        reason: ndn_transport::NackReason,
    ) -> ForwardingAction {
        let Some(fib) = ctx.fib_entry else {
            return ForwardingAction::Nack(reason);
        };
        let nexthops = fib.nexthops_excluding(ctx.in_face);
        match nexthops.first() {
            Some(nh) => ForwardingAction::Forward(smallvec![nh.face_id]),
            None => ForwardingAction::Nack(reason),
        }
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
            extensions: &EMPTY,
            runtime: &RUNTIME,
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

    #[tokio::test]
    async fn on_nack_retries_another_nexthop() {
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
        let ctx = make_ctx(&name, FaceId(2), Some(&fib), &measurements);
        let action = strategy.on_nack(&ctx, NackReason::NoRoute).await;
        match action {
            ForwardingAction::Forward(faces) => {
                assert_eq!(faces.as_slice(), &[FaceId(3)]);
            }
            _ => panic!("expected Forward to nexthop 3 on retry"),
        }
    }

    #[tokio::test]
    async fn on_nack_propagates_when_exhausted() {
        let strategy = BestRouteStrategy::new();
        let name = Arc::new(Name::root());
        let measurements = MeasurementsTable::new();
        let fib = FibEntry {
            nexthops: vec![FibNexthop {
                face_id: FaceId(7),
                cost: 0,
            }],
        };
        let ctx = make_ctx(&name, FaceId(7), Some(&fib), &measurements);
        let action = strategy.on_nack(&ctx, NackReason::Duplicate).await;
        assert!(
            matches!(action, ForwardingAction::Nack(NackReason::Duplicate)),
            "no other nexthop available — must propagate the Nack"
        );
    }

    #[tokio::test]
    async fn on_nack_propagates_when_no_fib() {
        let strategy = BestRouteStrategy::new();
        let name = Arc::new(Name::root());
        let measurements = MeasurementsTable::new();
        let ctx = make_ctx(&name, FaceId(1), None, &measurements);
        let action = strategy.on_nack(&ctx, NackReason::Congestion).await;
        assert!(matches!(
            action,
            ForwardingAction::Nack(NackReason::Congestion)
        ));
    }

    #[test]
    fn strategy_name() {
        let s = BestRouteStrategy::new();
        let comps = Strategy::name(&s).components();
        assert_eq!(comps.len(), 5);
        assert_eq!(comps[3].value.as_ref(), b"best-route");
        assert_eq!(
            comps[4].typ,
            ndn_packet::tlv_type::VERSION,
            "last component must be a Version (TLV 0x36)"
        );
    }

    /// `nfdc strategy-choice set` requires the version suffix on the wire.
    #[test]
    fn strategy_name_ends_with_version_v5() {
        let s = BestRouteStrategy::new();
        let comps = Strategy::name(&s).components();
        assert_eq!(comps.len(), 5, "name must have 5 components incl. version");
        let last = comps.last().expect("non-empty name");
        assert_eq!(
            last.typ,
            ndn_packet::tlv_type::VERSION,
            "final component must be VersionNameComponent (TLV 0x36)"
        );
        assert_eq!(
            last.value.as_ref(),
            &[5u8],
            "version value must be 5 (NFD canonical)"
        );
    }
}
