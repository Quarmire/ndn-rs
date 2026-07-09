//! Measurement — turning link timestamps into offset estimates (design §7).
//!
//! Three modes, all producing a [`Measured<i64>`]: a clock **offset** in
//! nanoseconds (by convention `remote − local`, or `A − B` for common-view)
//! carrying its noise (`sigma_ns`) and adversary exposure ([`MeasurementProvenance`]).
//! All operate on timestamps *already in nanoseconds* — a backend converts its
//! [`LinkStamp`](crate::LinkStamp) `raw` counter to ns via the domain's tick
//! rate before calling in, so this layer is unit-clean and bearer-agnostic.
//!
//! - **M1 two-way** ([`two_way`]) — PTP-style `t1..t4`. Cancels the offset from
//!   the path when the path is symmetric; the residual asymmetry is bounded by
//!   the mean path delay, which is folded into the uncertainty. Measured RTT
//!   therefore *bounds* the claimed tightness — you cannot assert a 1 µs clock
//!   over a 40 ms-jittering link.
//! - **M2 one-way** ([`one_way`]) — a stamped broadcast plus a modelled one-way
//!   delay. The reverse path is unmeasured, so the delay's own uncertainty is
//!   part of the result.
//! - **M3 common-view** ([`common_view`]) — two receivers of the *same* event
//!   subtract stamps. The transmitter's clock error and the common path cancel,
//!   so peers synchronise to each other through a beacon none of them trusts as
//!   a clock. **It does not bound distance** (a relay can re-radiate the event
//!   to one receiver), so the result's provenance is forced `distance_bounded =
//!   false` regardless of what the caller passed — safety by construction.

use crate::channel_obs::C_M_PER_S;
use crate::interval::TimeInterval;
use crate::provenance::{Measured, MeasurementProvenance};

/// Result of a two-way (M1) exchange.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TwoWay {
    /// The clock offset `remote − local`, ns, with uncertainty and provenance.
    pub offset: Measured<i64>,
    /// Round-trip path delay `d_out + d_back`, ns (turnaround excluded).
    pub rtt_ns: u64,
    /// Mean one-way path delay `rtt/2`, ns — the bound on the asymmetry error.
    pub mean_path_delay_ns: u64,
}

/// Robust `a − b` for ns timestamps via a wide intermediate, clamped to `i64`.
fn sub(a: i64, b: i64) -> i64 {
    (a as i128 - b as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// M1 — two-way offset from the four PTP timestamps (all ns):
/// `t1` local send, `t2` remote receive, `t3` remote send, `t4` local receive.
///
/// `offset = ((t2−t1) − (t4−t3)) / 2` assumes a symmetric path; the error from
/// real asymmetry is at most the mean path delay, so the uncertainty is
/// `prec_local + prec_remote + mean_path_delay`. `prov` is caller-supplied
/// (authenticity/replay); note that RTT gives a *physical* range bound but not
/// an *adversarial* one, so a two-way exchange alone does not justify
/// `distance_bounded = true`.
pub fn two_way(
    t1_ns: i64,
    t2_ns: i64,
    t3_ns: i64,
    t4_ns: i64,
    prec_local_ns: u32,
    prec_remote_ns: u32,
    prov: MeasurementProvenance,
) -> TwoWay {
    let out = sub(t2_ns, t1_ns); // d_out + offset
    let back = sub(t4_ns, t3_ns); // d_back − offset
    let offset = ((out as i128 - back as i128) / 2) as i64;
    // Path RTT excludes the remote turnaround: (t4−t1) − (t3−t2).
    let rtt = (sub(t4_ns, t1_ns) as i128 - sub(t3_ns, t2_ns) as i128).max(0) as u64;
    let mean_path = rtt / 2;
    let sigma = prec_local_ns as u64 + prec_remote_ns as u64 + mean_path;
    TwoWay {
        offset: Measured {
            value: offset,
            sigma_ns: sigma,
            prov,
        },
        rtt_ns: rtt,
        mean_path_delay_ns: mean_path,
    }
}

/// T1 distance bound from a rapid challenge–response, measured on the **local clock alone** —
/// the primitive that justifies setting [`MeasurementProvenance::distance_bounded`].
///
/// Unlike [`two_way`]'s `rtt_ns` — which nets out the remote's *self-reported* turnaround
/// (`t2`,`t3`), so a dishonest prover can shrink it to feign proximity — this uses only the
/// verifier's own send/receive stamps `t1_local_ns`,`t4_local_ns` and a **protocol-fixed**
/// `turnaround_floor_ns`: the least time the prover could possibly answer in, a constant the
/// verifier trusts, never a value the prover transmits. The prover can only answer *slower* than
/// the floor, and a relay/wormhole only *adds* propagation, so the implied one-way distance is a
/// sound **upper bound** — an emitter cannot forge being *closer* than it is. Returns `true` iff
/// that bound is within `max_plausible_m`, i.e. the emitter is provably local and the sample clears
/// the T1 floor ([`crate::provenance::T1Requirement`]).
///
/// `max_plausible_m` is the deployment's largest physically-credible emitter distance (link range
/// plus margin); a bound beyond it means added delay — a relay — and the sample is *not* bounded.
pub fn distance_bounded(
    t1_local_ns: i64,
    t4_local_ns: i64,
    turnaround_floor_ns: u64,
    max_plausible_m: f64,
) -> bool {
    // Elapsed on the local clock only; the true prover turnaround is at least the floor, so
    // subtracting the floor keeps the path RTT an over-estimate (upper bound stays sound).
    let elapsed = (t4_local_ns as i128 - t1_local_ns as i128).max(0) as u64;
    let path_rtt = elapsed.saturating_sub(turnaround_floor_ns);
    let one_way_m = C_M_PER_S * (path_rtt as f64) * 0.5e-9;
    one_way_m <= max_plausible_m
}

/// M2 — one-way offset from a stamped broadcast.
///
/// `offset = tx + modelled_delay − rx` (remote − local). The reverse path is
/// unmeasured, so `delay_uncertainty_ns` (the error in the modelled one-way
/// delay) is part of the result alongside the stamp precisions.
pub fn one_way(
    tx_ns: i64,
    rx_ns: i64,
    modelled_delay_ns: u64,
    delay_uncertainty_ns: u64,
    prec_tx_ns: u32,
    prec_rx_ns: u32,
    prov: MeasurementProvenance,
) -> Measured<i64> {
    let offset = (tx_ns as i128 + modelled_delay_ns as i128 - rx_ns as i128)
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    let sigma = prec_tx_ns as u64 + prec_rx_ns as u64 + delay_uncertainty_ns;
    Measured {
        value: offset,
        sigma_ns: sigma,
        prov,
    }
}

/// One receiver's reception of a common-view event.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RxObs {
    /// The receiver's stamp of the event, ns (its own clock).
    pub stamp_ns: i64,
    /// Modelled propagation delay from the emitter to this receiver, ns.
    pub prop_ns: u64,
    /// This receiver's stamp precision, ns.
    pub prec_ns: u32,
}

/// M3 — common-view inter-receiver offset `A − B` from two receivers hearing the
/// *same* event.
///
/// `offset_AB = (a.stamp − b.stamp) − (a.prop − b.prop)`. The transmitter's clock
/// error and the common emission time cancel; only the *difference* of the two
/// propagation delays enters, with `prop_diff_uncertainty_ns` its error.
///
/// **`distance_bounded` is forced `false`** on the result: common-view resists a
/// malicious *transmitter* (its error cancels) but not a *relay* that
/// re-radiates the event to one receiver — that is threat T1, which this
/// measurement cannot rule out.
pub fn common_view(
    a: RxObs,
    b: RxObs,
    prop_diff_uncertainty_ns: u64,
    mut prov: MeasurementProvenance,
) -> Measured<i64> {
    let prop_diff = a.prop_ns as i128 - b.prop_ns as i128;
    let offset = ((a.stamp_ns as i128 - b.stamp_ns as i128) - prop_diff)
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    let sigma = a.prec_ns as u64 + b.prec_ns as u64 + prop_diff_uncertainty_ns;
    prov.distance_bounded = false; // a relay defeats common-view (T1)
    Measured {
        value: offset,
        sigma_ns: sigma,
        prov,
    }
}

/// Self-consistency (design §9): a source's *effective* uncertainty is at least
/// its measured dispersion. A peer that claims 1 µs while its RTT jitters 40 ms
/// is held to the 40 ms — you cannot merely *assert* a tight clock.
pub fn self_consistent_uncertainty(claimed_ns: u64, measured_dispersion_ns: u64) -> u64 {
    claimed_ns.max(measured_dispersion_ns)
}

/// Turn an offset measurement (`remote − local`) into the wall-clock interval it
/// implies, given the local wall estimate — the bridge from [`two_way`] /
/// [`one_way`] into the Marzullo combiner ([`crate::combine::marzullo`]).
pub fn offset_to_wall(offset: &Measured<i64>, local_wall_ns: i64) -> TimeInterval {
    TimeInterval::new(local_wall_ns.saturating_add(offset.value), offset.sigma_ns)
}

/// A hardware-free clock + link model for exercising the measurement math with
/// injectable offset, drift, and path asymmetry — the `SimStampSource` the
/// design calls for (available to the crate's tests and, behind the `sim`
/// feature, to downstream test code).
#[cfg(any(test, feature = "sim"))]
#[cfg_attr(docsrs, doc(cfg(feature = "sim")))]
pub mod sim {
    /// A simulated clock: its reading is `true_time + offset + drift·true_time`.
    #[derive(Clone, Copy, Debug)]
    pub struct SimClock {
        /// Constant offset of this clock vs true time, ns.
        pub offset_ns: i64,
        /// Frequency error, parts per million (rate, not a one-off).
        pub drift_ppm: f32,
        /// The precision a stamp from this clock advertises, ns.
        pub precision_ns: u32,
    }

    impl SimClock {
        /// This clock's reading (ns) at true time `true_ns`.
        pub fn read(&self, true_ns: i64) -> i64 {
            let drift = (self.drift_ppm as f64 * 1e-6 * true_ns as f64) as i64;
            true_ns.saturating_add(self.offset_ns).saturating_add(drift)
        }
    }

    /// A simulated (possibly asymmetric) link.
    #[derive(Clone, Copy, Debug)]
    pub struct SimLink {
        /// Forward propagation delay, ns.
        pub delay_out_ns: u64,
        /// Reverse propagation delay, ns (differs from `delay_out_ns` to inject
        /// path asymmetry — the error two-way exchange cannot see).
        pub delay_back_ns: u64,
    }

    /// Simulate a two-way exchange started at true time `t1_true_ns` with a
    /// remote turnaround of `turnaround_ns`, returning `(t1, t2, t3, t4)` in ns.
    pub fn two_way_exchange(
        local: &SimClock,
        remote: &SimClock,
        link: &SimLink,
        t1_true_ns: i64,
        turnaround_ns: u64,
    ) -> (i64, i64, i64, i64) {
        let t1 = local.read(t1_true_ns);
        let arrive = t1_true_ns.saturating_add(link.delay_out_ns as i64);
        let t2 = remote.read(arrive);
        let send_back = arrive.saturating_add(turnaround_ns as i64);
        let t3 = remote.read(send_back);
        let t4_true = send_back.saturating_add(link.delay_back_ns as i64);
        let t4 = local.read(t4_true);
        (t1, t2, t3, t4)
    }
}

#[cfg(test)]
mod tests {
    use super::sim::{SimClock, SimLink, two_way_exchange};
    use super::*;
    use crate::provenance::{Authenticity, KeyId, PathId};

    fn prov() -> MeasurementProvenance {
        MeasurementProvenance {
            distance_bounded: false,
            replay_protected: true,
            authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(1)),
            path: PathId(1),
        }
    }

    fn clock(offset_ns: i64) -> SimClock {
        SimClock {
            offset_ns,
            drift_ppm: 0.0,
            precision_ns: 1_000,
        }
    }

    #[test]
    fn two_way_recovers_offset_on_symmetric_link() {
        // remote is +5 ms ahead of local; symmetric 1 ms path.
        let local = clock(0);
        let remote = clock(5_000_000);
        let link = SimLink {
            delay_out_ns: 1_000_000,
            delay_back_ns: 1_000_000,
        };
        let (t1, t2, t3, t4) = two_way_exchange(&local, &remote, &link, 1_000_000_000, 100_000);
        let r = two_way(t1, t2, t3, t4, 1_000, 1_000, prov());
        // Symmetric path → offset recovered exactly (stamps are noiseless here).
        assert_eq!(r.offset.value, 5_000_000, "offset = remote − local");
        assert_eq!(r.rtt_ns, 2_000_000, "path rtt excludes turnaround");
        assert_eq!(r.mean_path_delay_ns, 1_000_000);
    }

    #[test]
    fn two_way_asymmetry_stays_within_uncertainty() {
        // Same +5 ms offset, but a badly asymmetric path (out 1 ms, back 3 ms).
        let local = clock(0);
        let remote = clock(5_000_000);
        let link = SimLink {
            delay_out_ns: 1_000_000,
            delay_back_ns: 3_000_000,
        };
        let (t1, t2, t3, t4) = two_way_exchange(&local, &remote, &link, 2_000_000_000, 0);
        let r = two_way(t1, t2, t3, t4, 1_000, 1_000, prov());
        // The point estimate is biased by (d_out − d_back)/2 = −1 ms…
        let err = (r.offset.value - 5_000_000).unsigned_abs();
        // …but the uncertainty (≈ mean path delay 2 ms) covers the true value.
        assert!(
            err <= r.offset.sigma_ns,
            "asymmetry error {err} must be within uncertainty {}",
            r.offset.sigma_ns
        );
        assert!(
            r.offset.sigma_ns >= 2_000_000,
            "uncertainty reflects the path"
        );
    }

    #[test]
    fn one_way_recovers_offset() {
        // remote +5 ms; a 1 ms one-way delay, modelled exactly.
        let local = clock(0);
        let remote = clock(5_000_000);
        let tx = remote.read(1_000_000_000);
        let rx = local.read(1_000_000_000 + 1_000_000);
        let m = one_way(tx, rx, 1_000_000, 200_000, 1_000, 1_000, prov());
        assert_eq!(m.value, 5_000_000, "offset = remote − local");
        assert_eq!(m.sigma_ns, 1_000 + 1_000 + 200_000);
    }

    #[test]
    fn common_view_cancels_transmitter_clock_and_forces_unbounded() {
        // A + B hear the same beacon; the transmitter's own clock is irrelevant.
        // A is +2 ms vs true, B is +7 ms; A is 300 m closer (1 µs less prop).
        let a = clock(2_000_000);
        let b = clock(7_000_000);
        let emit_true = 3_000_000_000;
        let prop_a = 1_000u64; // ns
        let prop_b = 2_000u64;
        let rx_a = a.read(emit_true + prop_a as i64);
        let rx_b = b.read(emit_true + prop_b as i64);
        // Ask for distance_bounded: true — must be forced false.
        let mut asked = prov();
        asked.distance_bounded = true;
        let obs_a = RxObs {
            stamp_ns: rx_a,
            prop_ns: prop_a,
            prec_ns: 1_000,
        };
        let obs_b = RxObs {
            stamp_ns: rx_b,
            prop_ns: prop_b,
            prec_ns: 1_000,
        };
        let m = common_view(obs_a, obs_b, 100, asked);
        assert_eq!(m.value, 2_000_000 - 7_000_000, "offset A − B = −5 ms");
        assert!(
            !m.prov.distance_bounded,
            "common-view can't bound distance (T1)"
        );
    }

    #[test]
    fn distance_bound_passes_when_local_and_fails_a_relay() {
        // 100 m link, ~300 ns one-way → ~667 ns round trip; 500 ns turnaround floor.
        let floor = 500;
        let rtt_100m = (2.0 * 100.0 / C_M_PER_S / 1e-9) as i64; // ns
        let t1 = 1_000_000;
        let t4_local = t1 + floor as i64 + rtt_100m;
        // Within a 300 m plausible bound → provably local.
        assert!(distance_bounded(t1, t4_local, floor, 300.0));
        // A relay adds ~10 µs of tunnel delay → the implied distance blows past 300 m.
        let t4_relayed = t4_local + 10_000;
        assert!(!distance_bounded(t1, t4_relayed, floor, 300.0));
    }

    #[test]
    fn distance_bound_cannot_be_forged_closer_by_shrinking_turnaround() {
        // The prover cannot answer faster than the floor, so the verifier subtracts only the
        // trusted floor — a prover that "claims" a smaller turnaround has no timestamp here to lie
        // with. A genuinely local emitter within the floor+path passes; nothing the prover sends
        // enters the computation.
        let floor = 1_000;
        let t1 = 0;
        let t4 = t1 + floor as i64 + 300; // ~45 m of path
        assert!(distance_bounded(t1, t4, floor, 100.0));
        // If the round trip is entirely floor (co-located), distance is ~0 — still local.
        assert!(distance_bounded(t1, t1 + floor as i64, floor, 1.0));
    }

    #[test]
    fn self_consistency_holds_a_source_to_its_dispersion() {
        assert_eq!(self_consistent_uncertainty(1_000, 40_000_000), 40_000_000);
        assert_eq!(self_consistent_uncertainty(50_000_000, 1_000), 50_000_000);
    }

    #[test]
    fn offset_bridges_to_a_wall_interval() {
        let m = Measured {
            value: 5_000_000,
            sigma_ns: 2_000,
            prov: prov(),
        };
        let iv = offset_to_wall(&m, 1_700_000_000_000);
        assert_eq!(iv.center_ns, 1_700_000_000_000 + 5_000_000);
        assert_eq!(iv.radius_ns, 2_000);
    }
}
