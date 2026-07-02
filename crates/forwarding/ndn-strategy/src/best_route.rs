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
        // Prefer an upstream not yet tried for this Interest (D.09 failover);
        // fall back to any non-incoming nexthop for liveness once every
        // nexthop has been tried (a retransmission should still be re-sent).
        let untried = fib.nexthops_excluding_any(ctx.in_face, ctx.tried_faces);
        let nexthops = if untried.is_empty() {
            fib.nexthops_excluding(ctx.in_face)
        } else {
            untried
        };
        match nexthops.first() {
            Some(nh) => Some(smallvec![ForwardingAction::Forward(smallvec![nh.face_id])]),
            None => Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]),
        }
    }

    fn after_receive_interest(&self, ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        self.decide(ctx).unwrap()
    }

    fn after_receive_data(&self, _ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        SmallVec::new()
    }

    /// On Nack, exclude the nacking upstream (`in_face`) and retry on
    /// the next-best nexthop; propagate the Nack downstream if none
    /// remain. Mirrors NFD `daemon/fw/best-route-strategy.cpp`
    /// `afterReceiveNack` → `processNack`.
    ///
    /// Tried-upstream exclusion (`ctx.tried_faces`, from the PIT entry's
    /// out-records) closes the former ping-pong gap (D.09): a face already
    /// forwarded to for this Interest is never retried, so two mutually-
    /// nacking nexthops resolve to a downstream Nack instead of looping.
    fn on_nack(
        &self,
        ctx: &StrategyContext<'_>,
        reason: ndn_transport::NackReason,
    ) -> ForwardingAction {
        let Some(fib) = ctx.fib_entry else {
            return ForwardingAction::Nack(reason);
        };
        // Exclude the nacking upstream AND every upstream already tried for
        // this PIT entry (D.09): retrying an already-tried face is exactly the
        // mutual-Nack ping-pong. If no untried upstream remains, propagate the
        // Nack downstream rather than loop.
        let nexthops = fib.nexthops_excluding_any(ctx.in_face, ctx.tried_faces);
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
        make_ctx_tried(name, in_face, fib_entry, measurements, &[])
    }

    fn make_ctx_tried<'a>(
        name: &'a Arc<Name>,
        in_face: FaceId,
        fib_entry: Option<&'a FibEntry>,
        measurements: &'a MeasurementsTable,
        tried_faces: &'a [FaceId],
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
            tried_faces,
            measurements,
            signals: &crate::NoSignals,
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
        let actions = strategy.after_receive_interest(&ctx);
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
        let actions = strategy.after_receive_interest(&ctx);
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
        let actions = strategy.after_receive_interest(&ctx);
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
        let actions = strategy.after_receive_data(&ctx);
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
        let action = strategy.on_nack(&ctx, NackReason::NoRoute);
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
        let action = strategy.on_nack(&ctx, NackReason::Duplicate);
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
        let action = strategy.on_nack(&ctx, NackReason::Congestion);
        assert!(matches!(
            action,
            ForwardingAction::Nack(NackReason::Congestion)
        ));
    }

    /// D.09: a forward (decide) excludes already-tried upstreams, picking an
    /// untried nexthop instead of re-sending to the same one.
    #[tokio::test]
    async fn decide_prefers_untried_upstream() {
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
        // Face 2 already tried → the lowest-cost UNTRIED nexthop (3) is chosen.
        let tried = [FaceId(2)];
        let ctx = make_ctx_tried(&name, FaceId(1), Some(&fib), &measurements, &tried);
        let actions = strategy.after_receive_interest(&ctx);
        match actions.as_slice() {
            [ForwardingAction::Forward(faces)] => assert_eq!(faces.as_slice(), &[FaceId(3)]),
            _ => panic!("expected Forward to the untried nexthop 3"),
        }
    }

    /// D.09: when every nexthop has been tried, `decide` falls back to a
    /// liveness re-send (a retransmission must still go somewhere).
    #[tokio::test]
    async fn decide_falls_back_to_resend_when_all_tried() {
        let strategy = BestRouteStrategy::new();
        let name = Arc::new(Name::root());
        let measurements = MeasurementsTable::new();
        let fib = FibEntry {
            nexthops: vec![FibNexthop {
                face_id: FaceId(2),
                cost: 10,
            }],
        };
        let tried = [FaceId(2)];
        let ctx = make_ctx_tried(&name, FaceId(1), Some(&fib), &measurements, &tried);
        let actions = strategy.after_receive_interest(&ctx);
        match actions.as_slice() {
            [ForwardingAction::Forward(faces)] => assert_eq!(faces.as_slice(), &[FaceId(2)]),
            _ => panic!("all-tried must re-send to nexthop 2 for liveness"),
        }
    }

    /// D.09: on Nack, an already-tried upstream is NOT retried — with only one
    /// FIB nexthop already tried, the Nack propagates (no ping-pong).
    #[tokio::test]
    async fn on_nack_does_not_retry_tried_upstream() {
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
        // Nack arrives from face 2; face 3 already tried → no untried upstream
        // remains, so the Nack must propagate rather than ping-pong back to 3.
        let tried = [FaceId(3)];
        let ctx = make_ctx_tried(&name, FaceId(2), Some(&fib), &measurements, &tried);
        let action = strategy.on_nack(&ctx, NackReason::NoRoute);
        assert!(
            matches!(action, ForwardingAction::Nack(NackReason::NoRoute)),
            "both nexthops exhausted (one nacking, one already tried) → propagate"
        );
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
