use std::sync::Arc;

use bytes::Bytes;
use smallvec::{SmallVec, smallvec};

use ndn_packet::{Name, NameComponent};
use ndn_transport::FaceId;
use ndn_transport::{ForwardingAction, NackReason};

use crate::{ErasedStrategy, Strategy, StrategyContext, register_strategy};

register_strategy!(
    BROADCAST_REG,
    b"broadcast",
    1,
    || Arc::new(BroadcastStrategy::new()) as Arc<dyn ErasedStrategy>,
);

/// Broadcast (ad-hoc re-radiation) strategy: forward on **all** FIB nexthops, *including the incoming
/// face* — i.e. multicast without split-horizon. This is what a shared broadcast medium (a named-radio
/// mesh) needs: a relay has exactly one radio face, so an Interest it heard on that face must be
/// re-broadcast on the *same* face to reach the next hop. Every stock strategy calls
/// `nexthops_excluding(in_face)` and so silently drops the relay's re-broadcast; this one does not.
///
/// Storm control is not the strategy's job here and needs no dup-nonce logic: the relay forwards the
/// original wire bytes (same nonce), so neighbours' PIT nonce-dedup + the Dead-Nonce-List already drop
/// the echo/duplicates, and same-name fresh-nonce Interests aggregate in the PIT. Pair it with a radio
/// face of `LinkType::AdHoc` so the returning Data also re-radiates through the relay.
pub struct BroadcastStrategy {
    name: Name,
}

impl BroadcastStrategy {
    /// `/localhost/nfd/strategy/broadcast/v=1`.
    pub fn strategy_name() -> Name {
        Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhost")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"strategy")),
            NameComponent::generic(Bytes::from_static(b"broadcast")),
        ])
        .append_version(1)
    }

    pub fn new() -> Self {
        Self { name: Self::strategy_name() }
    }
}

impl Default for BroadcastStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for BroadcastStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        let Some(fib) = ctx.fib_entry else {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        };
        // ALL nexthops, INCLUDING the arrival face — no split horizon (that is the whole point).
        let faces: SmallVec<[FaceId; 4]> = fib.nexthops.iter().map(|n| n.face_id).collect();
        if faces.is_empty() {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
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
            measurements,
            signals: &crate::NoSignals,
            extensions: &EMPTY,
            runtime: &RUNTIME,
        }
    }

    #[test]
    fn no_fib_returns_nack() {
        let s = BroadcastStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let ctx = make_ctx(&name, FaceId(0), None, &m);
        assert!(matches!(
            s.after_receive_interest(&ctx).as_slice(),
            [ForwardingAction::Nack(NackReason::NoRoute)]
        ));
    }

    /// The defining property: the incoming face is re-broadcast on (single-radio multi-hop).
    #[test]
    fn re_broadcasts_on_the_incoming_face() {
        let s = BroadcastStrategy::new();
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let fib = FibEntry { nexthops: vec![FibNexthop { face_id: FaceId(1), cost: 0 }] };
        // Interest arrived on the ONLY nexthop face (the radio face) — multicast would Nack; we forward.
        let ctx = make_ctx(&name, FaceId(1), Some(&fib), &m);
        if let [ForwardingAction::Forward(faces)] = s.after_receive_interest(&ctx).as_slice() {
            assert!(faces.contains(&FaceId(1)), "must re-broadcast on the arrival radio face");
        } else {
            panic!("expected Forward on the incoming face, not a Nack");
        }
    }

    #[test]
    fn strategy_name_ends_with_version_v1() {
        let s = BroadcastStrategy::new();
        let comps = Strategy::name(&s).components();
        assert_eq!(comps.len(), 5);
        let last = comps.last().unwrap();
        assert_eq!(last.typ, ndn_packet::tlv_type::VERSION);
        assert_eq!(last.value.as_ref(), &[1u8]);
    }
}
