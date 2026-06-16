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

/// Inputs to a strategy decision for one Interest, gathered by the I/O shell.
///
/// Bundling the inputs (rather than a long argument list) lets content-aware
/// strategies read the name and clock without disturbing simple ones, and lets
/// future inputs be added without breaking every impl. `signals` is the
/// platform-neutral cross-layer surface (RSSI, GPS, …) — the same
/// [`SignalView`] the native engine threads through `StrategyContext`, so a
/// measured strategy's kernel is identical on native and embedded.
pub struct DecideCtx<'a, F: Copy + Eq> {
    /// The Interest name as component byte-slices (content-aware strategies).
    pub components: &'a [&'a [u8]],
    /// The FIB's candidate faces for the name.
    pub nexthops: &'a [F],
    /// The face the Interest arrived on (split horizon / overhear).
    pub incoming: F,
    /// Monotonic millisecond clock (windowing for measured strategies). Simple
    /// strategies ignore it.
    pub now_ms: u32,
    /// Cross-layer inputs; `&NoSignals` when no source is installed.
    pub signals: &'a dyn SignalView<F>,
}

/// A forwarding strategy: emit the actions to enact for one Interest.
///
/// Strategies that ignore signals/name/clock (`BestRoute`, `Multicast`) simply
/// read `ctx.nexthops` / `ctx.incoming`. Content-aware strategies (CCLF) also
/// read `ctx.components` / `ctx.now_ms` and observe Data and named neighbors via
/// the default-no-op hooks, which the shell calls on the Data and beacon paths.
pub trait Strategy<F: Copy + Eq> {
    /// Decide what to forward for one Interest. Call `emit` once per action.
    fn decide(&self, ctx: &DecideCtx<'_, F>, emit: &mut dyn FnMut(ForwardAction<F>));

    /// Observe a Data packet (its name + arrival time) so content-aware
    /// strategies can score content connectivity. Default: no-op.
    fn observe_data(&self, _components: &[&[u8]], _now_ms: u32) {}

    /// Observe a named neighbor heard on `face` at the **network layer** (a
    /// signed presence/announcement, not a link/host address) so density-aware
    /// strategies can count neighbors. Default: no-op.
    fn observe_neighbor(&self, _face: F, _name: &[&[u8]], _now_ms: u32) {}
}

/// Forward to the single lowest-cost nexthop that is not the incoming face
/// (split horizon). Nexthops are assumed cost-ordered by the FIB.
pub struct BestRoute;

impl<F: Copy + Eq> Strategy<F> for BestRoute {
    fn decide(&self, ctx: &DecideCtx<'_, F>, emit: &mut dyn FnMut(ForwardAction<F>)) {
        if let Some(&nh) = ctx.nexthops.iter().find(|&&f| f != ctx.incoming) {
            emit(ForwardAction::Now(nh));
        }
    }
}

/// Forward to every nexthop except the incoming face.
pub struct Multicast;

impl<F: Copy + Eq> Strategy<F> for Multicast {
    fn decide(&self, ctx: &DecideCtx<'_, F>, emit: &mut dyn FnMut(ForwardAction<F>)) {
        for &nh in ctx.nexthops.iter().filter(|&&f| f != ctx.incoming) {
            emit(ForwardAction::Now(nh));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collect emitted actions into a fixed buffer (ndn-fwd-core stays light).
    fn collect<S: Strategy<u8>>(
        s: &S,
        nexthops: &[u8],
        incoming: u8,
    ) -> ([ForwardAction<u8>; 8], usize) {
        let mut out = [ForwardAction::Now(0u8); 8];
        let mut n = 0;
        let ctx = DecideCtx {
            components: &[b"a"],
            nexthops,
            incoming,
            now_ms: 0,
            signals: &ndn_signals_core::NoSignals,
        };
        s.decide(&ctx, &mut |a| {
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
