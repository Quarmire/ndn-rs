//! Shared forwarding strategies (sans-IO).
//!
//! A strategy decides *which* nexthop(s) to use and *when* — the step after
//! admission (loop / hop-limit / route checks in [`crate::pipeline`]). It is a
//! pure function of the candidate nexthops (the FIB result), the incoming face,
//! and — for richer strategies — measurement state and a clock; it emits a list
//! of [`ForwardAction`]s via a callback (no allocation, like
//! [`crate::store::PitStore::satisfy`]). The I/O shell enacts whatever is
//! emitted: native via its runtime, the constrained forwarder via its tick loop
//! (multicast / scheduled / suppressed forwards all ride the same seam).
//!
//! `BestRoute` and `Multicast` are the trivial first tenants — the same shape a
//! CCLF strategy will fill in (it additionally reads a `MeasurementStore` and
//! emits [`ForwardAction::After`] for content-quality backoff).

use crate::pipeline::ForwardAction;
use ndn_signals_core::SignalView;

/// A forwarding strategy: emit the actions to enact for one Interest.
///
/// `signals` is the platform-neutral cross-layer input surface (RSSI, GPS, …) —
/// the same [`SignalView`] the native engine threads through `StrategyContext`,
/// so a measured strategy's decision kernel is identical on native and
/// embedded. Strategies that ignore signals (`BestRoute`, `Multicast`) simply
/// don't read it; the I/O shell passes `&NoSignals` by default.
pub trait Strategy<F: Copy + Eq> {
    /// `nexthops` are the FIB's candidate faces for the name; `incoming` is the
    /// face the Interest arrived on; `signals` exposes cross-layer inputs. Call
    /// `emit` once per action to take.
    fn decide(
        &self,
        nexthops: &[F],
        incoming: F,
        signals: &dyn SignalView<F>,
        emit: &mut dyn FnMut(ForwardAction<F>),
    );
}

/// Forward to the single lowest-cost nexthop that is not the incoming face
/// (split horizon). Nexthops are assumed cost-ordered by the FIB.
pub struct BestRoute;

impl<F: Copy + Eq> Strategy<F> for BestRoute {
    fn decide(
        &self,
        nexthops: &[F],
        incoming: F,
        _signals: &dyn SignalView<F>,
        emit: &mut dyn FnMut(ForwardAction<F>),
    ) {
        if let Some(&nh) = nexthops.iter().find(|&&f| f != incoming) {
            emit(ForwardAction::Now(nh));
        }
    }
}

/// Forward to every nexthop except the incoming face.
pub struct Multicast;

impl<F: Copy + Eq> Strategy<F> for Multicast {
    fn decide(
        &self,
        nexthops: &[F],
        incoming: F,
        _signals: &dyn SignalView<F>,
        emit: &mut dyn FnMut(ForwardAction<F>),
    ) {
        for &nh in nexthops.iter().filter(|&&f| f != incoming) {
            emit(ForwardAction::Now(nh));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collect emitted actions into a fixed buffer (ndn-fwd-core stays light).
    fn collect<S: Strategy<u8>>(s: &S, nexthops: &[u8], incoming: u8) -> ([ForwardAction<u8>; 8], usize) {
        let mut out = [ForwardAction::Now(0u8); 8];
        let mut n = 0;
        s.decide(nexthops, incoming, &ndn_signals_core::NoSignals, &mut |a| {
            if n < out.len() {
                out[n] = a;
                n += 1;
            }
        });
        (out, n)
    }

    #[test]
    fn best_route_picks_first_non_incoming() {
        let (out, n) = collect(&BestRoute, &[2, 3], 1);
        assert_eq!(&out[..n], &[ForwardAction::Now(2)]);
        // split horizon: the only nexthop is the incoming face -> nothing.
        let (_, n) = collect(&BestRoute, &[1], 1);
        assert_eq!(n, 0);
        // skips the incoming face, takes the next.
        let (out, n) = collect(&BestRoute, &[1, 4], 1);
        assert_eq!(&out[..n], &[ForwardAction::Now(4)]);
    }

    #[test]
    fn multicast_fans_out_excluding_incoming() {
        let (out, n) = collect(&Multicast, &[2, 3, 1], 1);
        assert_eq!(&out[..n], &[ForwardAction::Now(2), ForwardAction::Now(3)]);
    }
}
