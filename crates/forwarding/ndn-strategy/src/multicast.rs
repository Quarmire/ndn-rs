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
        let candidates: SmallVec<[FaceId; 4]> = fib
            .nexthops_excluding(ctx.in_face)
            .into_iter()
            .map(|n| n.face_id)
            .collect();
        // Genuinely nowhere to send: that is NoRoute.
        if candidates.is_empty() {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        }
        // NFD multicast-strategy.cpp gates each upstream through
        // `decidePerUpstream`; an upstream sent this Interest within the
        // window is skipped, not re-sent.
        let faces: SmallVec<[FaceId; 4]> = candidates
            .into_iter()
            .filter(|f| !ctx.suppressed_faces.contains(f))
            .collect();
        // ALL upstreams merely suppressed is NOT NoRoute — it means "not
        // now". NFD `continue`s past a SUPPRESS verdict and sends nothing,
        // leaving the PIT entry pending. Answering NoRoute here tells the
        // consumer the name is unreachable and kills the stream: measured on
        // the fleet as video dropping to ZERO and telemetry gapping the moment
        // suppression went live, because the emptiness check below originally
        // meant "the FIB has no nexthop" and the filter silently changed what
        // empty means.
        if faces.is_empty() {
            return Some(SmallVec::new());
        }
        Some(smallvec![ForwardingAction::Forward(faces)])
    }

    fn after_receive_interest(&self, ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        self.decide(ctx).unwrap()
    }

    fn after_receive_data(&self, _ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
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
            tried_faces: &[],
            suppressed_faces: &[],
            entry_retx_suppressed: false,
            measurements,
            signals: &crate::NoSignals,
            extensions: &EMPTY,
            runtime: &RUNTIME,
        }
    }

    /// All upstreams suppressed must send NOTHING — never a NoRoute Nack.
    ///
    /// NoRoute tells the consumer the name is unreachable and ends the fetch;
    /// suppression only means "not this instant" (NFD `continue`s past a
    /// SUPPRESS verdict). Regression guard for a live outage: reusing the
    /// existing `faces.is_empty()` NoRoute branch after filtering suppressed
    /// upstreams took fleet video to zero and gapped telemetry.
    #[tokio::test]
    async fn all_upstreams_suppressed_sends_nothing_not_noroute() {
        let s = MulticastStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let fib = FibEntry {
            nexthops: vec![
                FibNexthop { face_id: FaceId(1), cost: 1 },
                FibNexthop { face_id: FaceId(2), cost: 1 },
            ],
        };
        let suppressed = [FaceId(1), FaceId(2)];
        let mut ctx = make_ctx(&name, FaceId(9), Some(&fib), &m);
        ctx.suppressed_faces = &suppressed;

        let actions = s.decide(&ctx).expect("a verdict");
        assert!(
            !actions.iter().any(|a| matches!(a, ForwardingAction::Nack(_))),
            "suppression must never answer Nack"
        );
        assert!(actions.is_empty(), "nothing is sent while every upstream is suppressed");
    }

    /// A genuinely empty nexthop set is still NoRoute.
    #[tokio::test]
    async fn no_nexthops_at_all_still_answers_noroute() {
        let s = MulticastStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let fib = FibEntry { nexthops: vec![] };
        let ctx = make_ctx(&name, FaceId(9), Some(&fib), &m);
        let actions = s.decide(&ctx).expect("a verdict");
        assert!(
            actions.iter().any(|a| matches!(a, ForwardingAction::Nack(NackReason::NoRoute))),
            "an empty nexthop set is genuinely NoRoute"
        );
    }

    #[tokio::test]
    async fn no_fib_returns_nack() {
        let s = MulticastStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let ctx = make_ctx(&name, FaceId(0), None, &m);
        let actions = s.after_receive_interest(&ctx);
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
        let actions = s.after_receive_interest(&ctx);
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
        let actions = s.after_receive_interest(&ctx);
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
        assert!(s.after_receive_data(&ctx).is_empty());
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

