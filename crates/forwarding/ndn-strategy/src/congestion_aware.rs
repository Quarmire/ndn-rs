//! PCON-style congestion-aware multipath strategy.
//!
//! Like [`MeasuredStrategy`](crate::MeasuredStrategy) it ranks FIB nexthops by a
//! blend of static cost and live signals — but instead of always forwarding on
//! the single best face, it **spreads Interests proportionally** across the
//! viable faces, biased toward the least-congested. Traffic shifts *smoothly*
//! off a face as its congestion signal rises and drifts back as it drains, which
//! is the property that keeps multipath load-balancing from oscillating (the
//! all-or-nothing failure mode of a pure "pick the current best" rule).
//!
//! The closed loop is: a forwarder's egress CoDel marking stamps a congestion
//! mark when its queue builds; the mark rides back on Data and the engine folds
//! it into the per-face [`LinkSignals::congestion`] this strategy reads; the
//! weight of that face drops, so fewer Interests are sent its way, the queue
//! drains, marks stop, the signal decays, and the weight recovers. This is the
//! forwarding-plane half of PCON (Schneider et al. 2016); the consumer-window
//! half already lives in `ndn_transport::CongestionController`.
//!
//! This is generic congestion control — it serves classical wired multipath
//! (the regime PCON was designed for) first; the only wireless-specific input
//! (corruption-vs-congestion loss differentiation) is left to the signal source
//! that populates `LinkSignals`, so the strategy itself stays link-agnostic.
//!
//! [`LinkSignals::congestion`]: ndn_signals_core::LinkSignals::congestion

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use smallvec::{SmallVec, smallvec};

use ndn_packet::{Name, NameComponent};
use ndn_signals_core::CongestionLevel;
use ndn_transport::{FaceId, ForwardingAction, NackReason};

use crate::{ErasedStrategy, Strategy, StrategyContext, register_strategy};

register_strategy!(CONGESTION_AWARE_REG, b"congestion-aware", 1, || Arc::new(
    CongestionAwareStrategy::new()
)
    as Arc<dyn ErasedStrategy>,);

/// Avalanche-mix the round-robin cursor before reducing mod the weight total, so
/// consecutive Interests interleave across faces proportionally. A plain
/// `cursor * odd_constant % total` only visits a subset of residues when the constant
/// shares a factor with `total` (skewing the realized split); a full splitmix64 mix has
/// no such structure, so the reduction is ~uniform for any `total`.
fn scatter(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// **Congestion-aware multipath** (PCON-flavoured): weighted load-spreading over
/// FIB nexthops, biased away from congested faces. See the module docs.
pub struct CongestionAwareStrategy {
    name: Name,
    /// Monotonic cursor driving the weighted round-robin selection. Interior
    /// mutability so the strategy stays `&self` (one instance serves a namespace).
    cursor: AtomicU64,
}

impl CongestionAwareStrategy {
    /// `/localhost/nfd/strategy/congestion-aware/v=1`.
    pub fn strategy_name() -> Name {
        Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhost")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"strategy")),
            NameComponent::generic(Bytes::from_static(b"congestion-aware")),
        ])
        .append_version(1)
    }

    pub fn new() -> Self {
        Self {
            name: Self::strategy_name(),
            cursor: AtomicU64::new(0),
        }
    }

    /// Cost score for a nexthop — **lower is better**, same blend as
    /// `MeasuredStrategy` but with a steeper congestion penalty (reacting to the
    /// bridged congestion signal is this strategy's whole purpose). Saturates at 0.
    fn score(&self, ctx: &StrategyContext<'_>, face_id: FaceId, static_cost: u32) -> i64 {
        let mut s = static_cost as i64;

        // RTT penalty from a single source — the measured EWMA when available, else the
        // bridged signal. (Adding both double-counts the RTT for any face that has both.)
        let mut rtt_added = false;
        if let Some(entry) = ctx.measurements.get(ctx.name)
            && let Some(rtt) = entry.rtt_per_face.get(&face_id)
        {
            s += (rtt.srtt_ns / 1.0e7) as i64; // +1 per 10 ms EWMA RTT
            rtt_added = true;
        }

        if let Some(sig) = ctx.signals.link(face_id) {
            if !rtt_added && let Some(rtt_ms) = sig.observed_rtt_ms {
                s += (rtt_ms / 10.0) as i64;
            }
            if let Some(tput) = sig.observed_tput_bps {
                s -= (tput / 1_000_000) as i64; // -1 per Mbps
            }
            if let Some(rx) = sig.retransmit_rate {
                s += (rx * 100.0) as i64;
            }
            // Steeper than MeasuredStrategy (100/20): congestion is the signal
            // this strategy exists to act on.
            s += match sig.congestion {
                Some(CongestionLevel::High) => 300,
                Some(CongestionLevel::Medium) => 80,
                _ => 0,
            };
            if let Some(rssi) = sig.rssi_dbm {
                let weak = (-(rssi as i64)) - 60;
                if weak > 0 {
                    s += weak;
                }
            }
        }

        s.max(0)
    }

    /// Viable nexthops (excluding the in-face and any already-tried upstream)
    /// paired with a **selection weight** — higher = more traffic. Weight is
    /// scale-invariant: the best face gets 1000, and a face `d` cost-points worse
    /// gets `1000/(1+d)`, so comparable faces share load while clearly-worse
    /// (e.g. congested) ones keep only a small recovery-probing trickle.
    fn weighted(&self, ctx: &StrategyContext<'_>) -> SmallVec<[(FaceId, u64); 4]> {
        let Some(fib) = ctx.fib_entry else {
            return SmallVec::new();
        };
        let scored: SmallVec<[(FaceId, i64); 4]> = fib
            .nexthops_excluding_any(ctx.in_face, ctx.tried_faces)
            .iter()
            .map(|nh| (nh.face_id, self.score(ctx, nh.face_id, nh.cost)))
            .collect();
        let Some(min) = scored.iter().map(|(_, s)| *s).min() else {
            return SmallVec::new();
        };
        scored
            .into_iter()
            .map(|(f, s)| {
                let delta = (s - min) as u64;
                (f, (1000 / (1 + delta)).max(1))
            })
            .collect()
    }

    /// Pick one nexthop, spreading load proportionally to weight via a
    /// scattered weighted round-robin.
    fn pick(&self, ctx: &StrategyContext<'_>) -> Option<FaceId> {
        let cands = self.weighted(ctx);
        match cands.as_slice() {
            [] => None,
            [(f, _)] => Some(*f),
            _ => {
                let total: u64 = cands.iter().map(|(_, w)| *w).sum();
                let pos = scatter(self.cursor.fetch_add(1, Ordering::Relaxed)) % total;
                let mut acc = 0u64;
                for (f, w) in &cands {
                    acc += *w;
                    if pos < acc {
                        return Some(*f);
                    }
                }
                cands.last().map(|(f, _)| *f)
            }
        }
    }

    /// Single best (lowest-score) viable nexthop — used for deterministic Nack
    /// failover (vs. the weighted spread used for normal forwarding).
    fn best(&self, ctx: &StrategyContext<'_>) -> Option<FaceId> {
        let mut cands = self.weighted(ctx);
        // Higher weight == lower score == better; pick the max-weight face.
        cands.sort_by_key(|(_, w)| std::cmp::Reverse(*w));
        cands.first().map(|(f, _)| *f)
    }
}

impl Default for CongestionAwareStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for CongestionAwareStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        if ctx.fib_entry.is_none() {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        }
        match self.pick(ctx) {
            Some(face_id) => Some(smallvec![ForwardingAction::Forward(smallvec![face_id])]),
            None => Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]),
        }
    }

    fn after_receive_interest(&self, ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        // `decide` always returns Some today; fall back to "no action" (drop) rather than
        // panic on the hot path if that ever changes.
        self.decide(ctx).unwrap_or_default()
    }

    fn after_receive_data(&self, _ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        SmallVec::new()
    }

    /// On Nack, fail over to the best untried upstream (the nacking `in_face` and
    /// prior tries are excluded by `Self::weighted`); propagate if none remain.
    fn on_nack(&self, ctx: &StrategyContext<'_>, reason: NackReason) -> ForwardingAction {
        match self.best(ctx) {
            Some(face_id) => ForwardingAction::Forward(smallvec![face_id]),
            None => ForwardingAction::Nack(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{FibEntry, FibNexthop};
    use crate::measurements::MeasurementsTable;
    use crate::signals::SignalsTable;
    use ndn_signals_core::{LinkSignals, SignalStore};

    fn ctx_with<'a>(
        name: &'a Arc<Name>,
        fib: &'a FibEntry,
        signals: &'a SignalsTable,
        measurements: &'a MeasurementsTable,
        rt: &'a Arc<dyn ndn_runtime::Runtime>,
        ext: &'a ndn_transport::AnyMap,
    ) -> StrategyContext<'a> {
        StrategyContext {
            name,
            in_face: FaceId(0),
            fib_entry: Some(fib),
            pit_token: None,
            tried_faces: &[],
            measurements,
            signals,
            extensions: ext,
            runtime: rt,
        }
    }

    struct Rig {
        name: Arc<Name>,
        measurements: MeasurementsTable,
        rt: Arc<dyn ndn_runtime::Runtime>,
        ext: ndn_transport::AnyMap,
    }
    impl Rig {
        fn new() -> Self {
            Self {
                name: Arc::new("/ndn/node/peer".parse().unwrap()),
                measurements: MeasurementsTable::new(),
                rt: ndn_runtime::default_runtime(),
                ext: ndn_transport::AnyMap::new(),
            }
        }
    }

    /// Count picks per face over `n` Interests.
    fn distribution(
        s: &CongestionAwareStrategy,
        ctx: &StrategyContext<'_>,
        n: usize,
    ) -> Vec<(FaceId, usize)> {
        let mut counts: std::collections::HashMap<FaceId, usize> = std::collections::HashMap::new();
        for _ in 0..n {
            if let Some(ForwardingAction::Forward(faces)) =
                s.decide(ctx).and_then(|mut v| v.drain(..).next())
            {
                *counts.entry(faces[0]).or_default() += 1;
            }
        }
        let mut v: Vec<_> = counts.into_iter().collect();
        v.sort_by_key(|(f, _)| f.0);
        v
    }

    #[test]
    fn equal_faces_share_load_evenly() {
        let r = Rig::new();
        let fib = FibEntry {
            nexthops: vec![
                FibNexthop {
                    face_id: FaceId(1),
                    cost: 10,
                },
                FibNexthop {
                    face_id: FaceId(2),
                    cost: 10,
                },
            ],
        };
        let signals = SignalsTable::new();
        let s = CongestionAwareStrategy::new();
        let ctx = ctx_with(&r.name, &fib, &signals, &r.measurements, &r.rt, &r.ext);
        let dist = distribution(&s, &ctx, 200);
        // Both faces carry a substantial, roughly-balanced share (not blocky).
        for (_, c) in &dist {
            assert!(
                (60..=140).contains(c),
                "equal faces should split ~evenly over 200, got {dist:?}"
            );
        }
        assert_eq!(dist.len(), 2);
    }

    #[test]
    fn congested_face_loses_the_bulk_of_traffic() {
        let r = Rig::new();
        let fib = FibEntry {
            nexthops: vec![
                FibNexthop {
                    face_id: FaceId(1),
                    cost: 10,
                }, // clean
                FibNexthop {
                    face_id: FaceId(2),
                    cost: 10,
                }, // congested
            ],
        };
        let signals = SignalsTable::new();
        signals.set_link(
            FaceId(2),
            LinkSignals {
                congestion: Some(CongestionLevel::High),
                ..LinkSignals::default()
            },
        );
        let s = CongestionAwareStrategy::new();
        let ctx = ctx_with(&r.name, &fib, &signals, &r.measurements, &r.rt, &r.ext);
        let dist = distribution(&s, &ctx, 200);
        let clean = dist
            .iter()
            .find(|(f, _)| *f == FaceId(1))
            .map(|(_, c)| *c)
            .unwrap_or(0);
        let congested = dist
            .iter()
            .find(|(f, _)| *f == FaceId(2))
            .map(|(_, c)| *c)
            .unwrap_or(0);
        assert!(
            clean > 180,
            "clean face should carry the bulk, got clean={clean} congested={congested}"
        );
        assert!(
            congested < 20,
            "congested face should get only a trickle, got {congested}"
        );
    }

    #[test]
    fn single_viable_face_always_picked() {
        let r = Rig::new();
        let fib = FibEntry {
            nexthops: vec![FibNexthop {
                face_id: FaceId(7),
                cost: 10,
            }],
        };
        let signals = SignalsTable::new();
        let s = CongestionAwareStrategy::new();
        let ctx = ctx_with(&r.name, &fib, &signals, &r.measurements, &r.rt, &r.ext);
        let dist = distribution(&s, &ctx, 50);
        assert_eq!(dist, vec![(FaceId(7), 50)]);
    }

    #[test]
    fn no_route_nacks() {
        let r = Rig::new();
        let signals = SignalsTable::new();
        let s = CongestionAwareStrategy::new();
        let empty = FibEntry { nexthops: vec![] };
        let mut ctx = ctx_with(&r.name, &empty, &signals, &r.measurements, &r.rt, &r.ext);
        ctx.fib_entry = None;
        assert!(matches!(
            s.decide(&ctx).unwrap().first(),
            Some(ForwardingAction::Nack(NackReason::NoRoute))
        ));
    }

    #[test]
    fn on_nack_fails_over_to_untried() {
        let r = Rig::new();
        let fib = FibEntry {
            nexthops: vec![
                FibNexthop {
                    face_id: FaceId(1),
                    cost: 10,
                },
                FibNexthop {
                    face_id: FaceId(2),
                    cost: 20,
                },
            ],
        };
        let signals = SignalsTable::new();
        let s = CongestionAwareStrategy::new();
        let mut ctx = ctx_with(&r.name, &fib, &signals, &r.measurements, &r.rt, &r.ext);
        // Face 1 already tried (and is the in-face's pick); nack must move to 2.
        ctx.tried_faces = &[FaceId(1)];
        match s.on_nack(&ctx, NackReason::Congestion) {
            ForwardingAction::Forward(faces) => assert_eq!(faces.as_slice(), &[FaceId(2)]),
            _ => panic!("expected failover to FaceId(2)"),
        }
    }
}
