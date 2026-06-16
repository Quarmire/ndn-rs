//! Adaptive best-route strategy that blends the static `LinkProfile` cost prior
//! with live measured signals.

use std::sync::Arc;

use bytes::Bytes;
use smallvec::{SmallVec, smallvec};

use ndn_packet::{Name, NameComponent};
use ndn_signals_core::CongestionLevel;
use ndn_transport::{FaceId, ForwardingAction, NackReason};

use crate::{ErasedStrategy, Strategy, StrategyContext, register_strategy};

register_strategy!(
    MEASURED_REG,
    b"measured",
    1,
    || Arc::new(MeasuredStrategy::new()) as Arc<dyn ErasedStrategy>,
);

/// **Measured best-route**: rank FIB nexthops by a blend of the static
/// per-face cost (the [`LinkProfile`](ndn_transport::LinkProfile) prior) and
/// live measurement — prefix-level EWMA RTT ([`MeasurementsTable`]) plus per-face
/// [`LinkSignals`] (link RTT, throughput, congestion, retransmit rate, RSSI),
/// then forward on the best.
///
/// With no signals yet it reduces to pure static cost, so it behaves exactly
/// like [`BestRouteStrategy`] on a cold link and adapts as measurements accrue.
/// Used on the per-peer `/ndn/node/<id>` routes: a phone prefers a warm Wi-Fi
/// Aware **NDP** (low static cost + good RTT) over BLE, but shifts off the NDP if
/// it degrades (rising RTT / congestion / retransmits) even though its static
/// cost is lower — the dynamic counterpart to the cost-only `BestRoute`.
///
/// [`BestRouteStrategy`]: crate::BestRouteStrategy
/// [`LinkSignals`]: ndn_signals_core::LinkSignals
/// [`MeasurementsTable`]: crate::MeasurementsTable
pub struct MeasuredStrategy {
    name: Name,
}

impl MeasuredStrategy {
    /// `/localhost/nfd/strategy/measured/v=1`.
    pub fn strategy_name() -> Name {
        Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhost")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"strategy")),
            NameComponent::generic(Bytes::from_static(b"measured")),
        ])
        .append_version(1)
    }

    pub fn new() -> Self {
        Self {
            name: Self::strategy_name(),
        }
    }

    /// Cost score for a nexthop — **lower is better**. The static cost is the
    /// prior; measured signals adjust it (all in the same small "cost point"
    /// units as `LinkProfile`, so e.g. a 200 ms RTT (+20) can outweigh the
    /// 40-point static gap between Wi-Fi Aware and BLE). Saturates at 0.
    fn score(&self, ctx: &StrategyContext<'_>, face_id: FaceId, static_cost: u32) -> i64 {
        let mut s = static_cost as i64;

        // Prefix-level EWMA RTT (the forwarder's own round-trip measurement):
        // +1 point per 10 ms.
        if let Some(entry) = ctx.measurements.get(ctx.name)
            && let Some(rtt) = entry.rtt_per_face.get(&face_id)
        {
            s += (rtt.srtt_ns / 1.0e7) as i64;
        }

        // Per-face link signals (what the radio/backend can read).
        if let Some(sig) = ctx.signals.link(face_id) {
            if let Some(rtt_ms) = sig.observed_rtt_ms {
                s += (rtt_ms / 10.0) as i64;
            }
            if let Some(tput) = sig.observed_tput_bps {
                s -= (tput / 1_000_000) as i64; // -1 point per Mbps
            }
            if let Some(rx) = sig.retransmit_rate {
                s += (rx * 100.0) as i64; // 0.0..=1.0 → 0..100
            }
            s += match sig.congestion {
                Some(CongestionLevel::High) => 100,
                Some(CongestionLevel::Medium) => 20,
                _ => 0,
            };
            if let Some(rssi) = sig.rssi_dbm {
                // Penalise weak signal: nothing down to -60 dBm, then ramp.
                let weak = (-(rssi as i64)) - 60;
                if weak > 0 {
                    s += weak;
                }
            }
        }

        s.max(0)
    }

    /// Nexthops (excluding the in-face) sorted best-first by [`Self::score`].
    fn ranked(&self, ctx: &StrategyContext<'_>) -> SmallVec<[FaceId; 4]> {
        let Some(fib) = ctx.fib_entry else {
            return SmallVec::new();
        };
        let mut scored: SmallVec<[(i64, FaceId); 4]> = fib
            .nexthops_excluding(ctx.in_face)
            .iter()
            .map(|nh| (self.score(ctx, nh.face_id, nh.cost), nh.face_id))
            .collect();
        scored.sort_by_key(|(s, _)| *s);
        scored.into_iter().map(|(_, f)| f).collect()
    }
}

impl Default for MeasuredStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for MeasuredStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        if ctx.fib_entry.is_none() {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        }
        match self.ranked(ctx).first() {
            Some(&face_id) => Some(smallvec![ForwardingAction::Forward(smallvec![face_id])]),
            None => Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]),
        }
    }

    fn after_receive_interest(
        &self,
        ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        self.decide(ctx).unwrap()
    }

    fn after_receive_data(
        &self,
        _ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        SmallVec::new()
    }

    /// On Nack, retry on the next-best nexthop (the nacking `in_face` is already
    /// excluded by [`Self::ranked`]); propagate downstream if none remain.
    fn on_nack(
        &self,
        ctx: &StrategyContext<'_>,
        reason: NackReason,
    ) -> ForwardingAction {
        match self.ranked(ctx).first() {
            Some(&face_id) => ForwardingAction::Forward(smallvec![face_id]),
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

    #[test]
    fn cold_link_falls_back_to_static_cost() {
        // No signals → pick the lowest static cost (like BestRoute).
        let name: Arc<Name> = Arc::new("/ndn/node/peer".parse().unwrap());
        let fib = FibEntry {
            nexthops: vec![
                FibNexthop { face_id: FaceId(8), cost: 20 }, // NAN
                FibNexthop { face_id: FaceId(11), cost: 10 }, // NDP
                FibNexthop { face_id: FaceId(9), cost: 50 }, // BLE
            ],
        };
        let signals = SignalsTable::new();
        let measurements = MeasurementsTable::new();
        let rt: Arc<dyn ndn_runtime::Runtime> = ndn_runtime::default_runtime();
        let ext = ndn_transport::AnyMap::new();
        let s = MeasuredStrategy::new();
        assert_eq!(s.ranked(&ctx_with(&name, &fib, &signals, &measurements, &rt, &ext)).first().copied(), Some(FaceId(11)));
    }

    #[test]
    fn degraded_cheap_face_loses_to_a_healthy_dearer_one() {
        // The cheap NDP face (cost 10) is congested + high-RTT; the dearer BLE
        // face (cost 50) is clean → BLE should win.
        let name: Arc<Name> = Arc::new("/ndn/node/peer".parse().unwrap());
        let fib = FibEntry {
            nexthops: vec![
                FibNexthop { face_id: FaceId(11), cost: 10 }, // NDP, degraded
                FibNexthop { face_id: FaceId(9), cost: 50 },  // BLE, clean
            ],
        };
        let signals = SignalsTable::new();
        signals.set_link(
            FaceId(11),
            LinkSignals {
                observed_rtt_ms: Some(800.0),
                congestion: Some(CongestionLevel::High),
                ..LinkSignals::default()
            },
        );
        let measurements = MeasurementsTable::new();
        let rt: Arc<dyn ndn_runtime::Runtime> = ndn_runtime::default_runtime();
        let ext = ndn_transport::AnyMap::new();
        let s = MeasuredStrategy::new();
        assert_eq!(
            s.ranked(&ctx_with(&name, &fib, &signals, &measurements, &rt, &ext)).first().copied(),
            Some(FaceId(9)),
            "a congested 800ms NDP should lose to a clean BLE despite lower static cost",
        );
    }
}
