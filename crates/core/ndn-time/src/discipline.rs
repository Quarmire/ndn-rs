//! The discipline loop — SENSE → DECIDE → ACT (design §9).
//!
//! Pure and sans-IO, like the radio plane's `MediumState`/`RadioPolicy`. This
//! module ties the rest of the crate together into one clock:
//!
//! - **SENSE** ([`TimeState`]) accumulates each peer's latest offset observation
//!   (a [`Measured<i64>`] from the [`measure`](crate::measure) layer) plus a ring
//!   of recent `(monotonic, offset)` points for skew estimation.
//! - **DECIDE** ([`TimePolicy::discipline`]) ages each sample by its holdover,
//!   **admits** the set against a [`StakesFloor`] (threat-diversity, upstream of
//!   the combiner), Marzullo-combines the surviving wall intervals, and regresses
//!   the combined offset over monotonic time to estimate the local clock's
//!   **frequency skew** as well as its offset. Marzullo is *robustness*, not
//!   *admission* — a fabricated majority is the authority gate's problem (T2).
//! - **ACT** ([`TimePolicy::act`]) turns the [`Correction`] into a
//!   capability-gated [`Discipline`]: an un-steerable reference (GPS) is
//!   *tracked*, a steerable clock is *stepped* once at bootstrap then *slewed*
//!   (bounded, so wall-reading consumers never see a jump), and an uncertain or
//!   unadmitted fix is *withheld*.
//!
//! The monotonic clock (principle P3) is never touched here — it is the
//! independent floor; discipline only ever adjusts the *wall* estimate.

use crate::capability::ClockCapability;
use crate::combine::marzullo;
use crate::interval::TimeInterval;
use crate::measure::offset_to_wall;
use crate::provenance::{MAX_MEASUREMENTS, Measured, MeasurementProvenance, StakesFloor, admits};

/// One peer's current offset observation, retained for the next discipline pass.
#[derive(Clone, Copy, Debug)]
pub struct PeerSample {
    /// The measured offset `remote − local`, ns, with its provenance.
    pub offset: Measured<i64>,
    /// Local monotonic clock (ns) at capture — anchors holdover aging and the
    /// skew regression (principle P3: monotonic, non-regressing, network-free).
    pub captured_mono_ns: u64,
    /// The peer's clock capability, used to age its uncertainty by holdover.
    pub cap: ClockCapability,
}

/// Points retained for the frequency-skew regression.
const SKEW_POINTS: usize = 16;

/// A streaming linear-regression estimator: the slope of the combined offset
/// against monotonic time is the local clock's fractional frequency error.
#[derive(Clone, Copy, Debug)]
pub struct SkewEstimator {
    pts: [(u64, i64); SKEW_POINTS],
    len: usize,
    head: usize,
}

impl Default for SkewEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl SkewEstimator {
    /// An empty estimator.
    pub const fn new() -> Self {
        Self {
            pts: [(0, 0); SKEW_POINTS],
            len: 0,
            head: 0,
        }
    }

    /// Record a `(monotonic ns, combined offset ns)` point (ring-buffered).
    pub fn push(&mut self, mono_ns: u64, offset_ns: i64) {
        self.pts[self.head] = (mono_ns, offset_ns);
        self.head = (self.head + 1) % SKEW_POINTS;
        if self.len < SKEW_POINTS {
            self.len += 1;
        }
    }

    /// Fractional frequency error in **parts per billion**: the slope of offset
    /// (ns) vs monotonic time (ns), scaled by 1e9. `None` if fewer than two
    /// points or the points share no time span (a degenerate fit).
    pub fn skew_ppb(&self) -> Option<i64> {
        if self.len < 2 {
            return None;
        }
        // x-origin = the smallest retained time, to keep the regression's
        // magnitudes small and stable.
        let mut x0 = u64::MAX;
        for &(t, _) in &self.pts[..self.len] {
            if t < x0 {
                x0 = t;
            }
        }
        let n = self.len as f64;
        let (mut sx, mut sy, mut sxy, mut sxx) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
        for &(t, y) in &self.pts[..self.len] {
            let x = t.saturating_sub(x0) as f64;
            let y = y as f64;
            sx += x;
            sy += y;
            sxy += x * y;
            sxx += x * x;
        }
        let denom = n * sxx - sx * sx;
        if denom == 0.0 {
            return None;
        }
        let slope = (n * sxy - sx * sy) / denom; // ns offset per ns mono (fractional)
        Some((slope * 1e9) as i64)
    }
}

/// SENSE — the per-peer sample bus plus the skew ring.
#[derive(Clone, Copy, Debug)]
pub struct TimeState {
    peers: [Option<(u64, PeerSample)>; MAX_MEASUREMENTS],
    /// The frequency-skew estimator, updated on each admitted fix.
    pub skew: SkewEstimator,
}

impl Default for TimeState {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeState {
    /// An empty state.
    pub const fn new() -> Self {
        Self {
            peers: [None; MAX_MEASUREMENTS],
            skew: SkewEstimator::new(),
        }
    }

    /// Insert or replace `peer_id`'s latest sample. A full table drops the
    /// sample (returns `false`); with `MAX_MEASUREMENTS` peers this is not
    /// reached in practice, and dropping fails safe (fewer inputs → wider fix).
    pub fn ingest(&mut self, peer_id: u64, sample: PeerSample) -> bool {
        // Replace an existing entry for this peer, else take the first free slot.
        let mut free: Option<usize> = None;
        for (i, slot) in self.peers.iter().enumerate() {
            match slot {
                Some((id, _)) if *id == peer_id => {
                    self.peers[i] = Some((peer_id, sample));
                    return true;
                }
                None if free.is_none() => free = Some(i),
                _ => {}
            }
        }
        if let Some(i) = free {
            self.peers[i] = Some((peer_id, sample));
            true
        } else {
            false
        }
    }

    /// Number of peers currently held.
    pub fn peer_count(&self) -> usize {
        self.peers.iter().filter(|s| s.is_some()).count()
    }
}

/// DECIDE — the outcome of one discipline pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Correction {
    /// How much to move the local wall clock, ns (`consensus_wall − local_wall`).
    pub offset_ns: i64,
    /// Uncertainty (half-width) of the combined fix, ns.
    pub uncertainty_ns: u64,
    /// Estimated local frequency skew, ppb, once enough history exists.
    pub freq_skew_ppb: Option<i64>,
    /// How many peers supported the combined interval (the Marzullo majority).
    pub support: usize,
    /// Whether the sample set cleared the admission floor. A `false` here means
    /// *nothing* usable — the fix is withheld regardless of the numbers.
    pub admitted: bool,
}

/// ACT — the capability-gated discipline action. Only ever adjusts the *wall*
/// estimate; the monotonic clock is untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discipline {
    /// Apply a one-time wall step of `correction_ns` — bootstrap only (no prior
    /// wall). Ongoing corrections slew instead, so wall consumers see no jump.
    Step {
        /// The wall-clock step to apply, ns (`consensus − local`).
        correction_ns: i64,
    },
    /// Steer the clock frequency by `rate_ppb` (bounded by the policy) to close
    /// the offset gradually — the normal ongoing correction.
    Slew {
        /// Frequency steer to apply, parts per billion (sign closes the offset).
        rate_ppb: i64,
    },
    /// Adopt `correction_ns` as truth without steering — an un-steerable
    /// reference (GPS) *is* the reference, not a thing to discipline.
    Track {
        /// The offset to adopt as truth, ns.
        correction_ns: i64,
    },
    /// The fix was unadmitted or too uncertain to act on — withhold, and report
    /// the uncertainty so a consumer can fail loud.
    Withhold {
        /// The combined uncertainty that fell short, ns (huge if unadmitted).
        uncertainty_ns: u64,
    },
}

/// DECIDE/ACT tunables.
#[derive(Clone, Copy, Debug)]
pub struct TimePolicy {
    /// Above this combined uncertainty, [`Self::act`] withholds high-stakes
    /// discipline (fail-closed).
    pub required_uncertainty_ns: u64,
    /// Maximum slew rate magnitude, ppb.
    pub max_slew_ppb: i64,
    /// Seconds over which a steerable clock nominally closes its offset — the
    /// `ns offset → ppb rate` constant (`rate = offset_ns / slew_time_const_s`).
    pub slew_time_const_s: i64,
    /// The admission floor the sample set must clear (threat-diversity).
    pub floor: StakesFloor,
}

impl Default for TimePolicy {
    fn default() -> Self {
        Self {
            required_uncertainty_ns: 1_000_000, // 1 ms
            max_slew_ppb: 500,
            slew_time_const_s: 1,
            floor: StakesFloor::high(),
        }
    }
}

impl TimePolicy {
    /// DECIDE — age, admit, combine, and estimate offset + skew.
    ///
    /// Takes `&mut TimeState` because an admitted fix pushes a point into the
    /// skew ring. `local_wall_ns` is the current wall estimate; `now_mono_ns` the
    /// current monotonic clock (for aging and the skew x-axis).
    pub fn discipline(
        &self,
        state: &mut TimeState,
        local_wall_ns: i64,
        now_mono_ns: u64,
    ) -> Correction {
        let mut intervals = [TimeInterval::new(0, 0); MAX_MEASUREMENTS];
        let mut provs = [MeasurementProvenance {
            distance_bounded: false,
            replay_protected: false,
            authenticity: crate::provenance::Authenticity::Unauthenticated,
            path: crate::provenance::PathId(0),
        }; MAX_MEASUREMENTS];
        let mut n = 0;

        for slot in state.peers.iter() {
            let Some((_, s)) = slot else { continue };
            // Age this sample's uncertainty by the holdover accrued since capture.
            let elapsed = now_mono_ns.saturating_sub(s.captured_mono_ns);
            let growth = s.cap.holdover.growth_ns(elapsed);
            let self_consistent = s.offset.sigma_ns.saturating_add(growth);
            let aged = Measured {
                value: s.offset.value,
                sigma_ns: self_consistent,
                prov: s.offset.prov,
            };
            intervals[n] = offset_to_wall(&aged, local_wall_ns);
            provs[n] = s.offset.prov;
            n += 1;
        }

        // Admission is upstream of the combiner (threat-diversity, not counting).
        if n == 0 || !admits(&provs[..n], &self.floor) {
            return Correction {
                offset_ns: 0,
                uncertainty_ns: u64::MAX,
                freq_skew_ppb: state.skew.skew_ppb(),
                support: 0,
                admitted: false,
            };
        }

        let Some(c) = marzullo(&intervals[..n]) else {
            return Correction {
                offset_ns: 0,
                uncertainty_ns: u64::MAX,
                freq_skew_ppb: state.skew.skew_ppb(),
                support: 0,
                admitted: false,
            };
        };

        let offset_ns = c.interval.center_ns.saturating_sub(local_wall_ns);
        state.skew.push(now_mono_ns, offset_ns);
        Correction {
            offset_ns,
            uncertainty_ns: c.interval.radius_ns,
            freq_skew_ppb: state.skew.skew_ppb(),
            support: c.support,
            admitted: true,
        }
    }

    /// ACT — turn a [`Correction`] into a capability-gated [`Discipline`].
    ///
    /// `has_prior_wall` is `false` only at bootstrap (no established wall yet),
    /// which is the one time a step is used instead of a slew.
    pub fn act(&self, c: &Correction, cap: &ClockCapability, has_prior_wall: bool) -> Discipline {
        if !c.admitted || c.uncertainty_ns > self.required_uncertainty_ns {
            return Discipline::Withhold {
                uncertainty_ns: c.uncertainty_ns,
            };
        }
        // An un-steerable reference is adopted, not disciplined.
        if cap.reference_only || !cap.disciplinable {
            return Discipline::Track {
                correction_ns: c.offset_ns,
            };
        }
        // Bootstrap: a one-time wall step. Monotonic consumers are unaffected.
        if !has_prior_wall {
            return Discipline::Step {
                correction_ns: c.offset_ns,
            };
        }
        // Ongoing: slew. Rate closes the offset (sign) at a bounded magnitude.
        let t = self.slew_time_const_s.max(1);
        let rate = (c.offset_ns / t).clamp(-self.max_slew_ppb, self.max_slew_ppb);
        Discipline::Slew { rate_ppb: rate }
    }

    /// Whether to re-beacon our own time: only when the fix is admitted and
    /// *tightened* our interval below what we last advertised (design §9:
    /// "re-emit if it tightens a downstream peer's interval").
    pub fn should_rebeacon(&self, c: &Correction, last_beaconed_uncertainty_ns: u64) -> bool {
        c.admitted && c.uncertainty_ns < last_beaconed_uncertainty_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{Authenticity, KeyId, PathId};

    fn authed(key: u64, path: u32, bounded: bool) -> MeasurementProvenance {
        MeasurementProvenance {
            distance_bounded: bounded,
            replay_protected: true,
            authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(key)),
            path: PathId(path),
        }
    }

    fn sample(offset_ns: i64, sigma_ns: u64, mono: u64, prov: MeasurementProvenance) -> PeerSample {
        PeerSample {
            offset: Measured {
                value: offset_ns,
                sigma_ns,
                prov,
            },
            captured_mono_ns: mono,
            cap: ClockCapability::oscillator_tcxo(),
        }
    }

    #[test]
    fn no_peers_is_withheld() {
        let policy = TimePolicy::default();
        let mut st = TimeState::new();
        let c = policy.discipline(&mut st, 1_000_000_000, 0);
        assert!(!c.admitted);
        assert!(matches!(
            policy.act(&c, &ClockCapability::oscillator_tcxo(), true),
            Discipline::Withhold { .. }
        ));
    }

    #[test]
    fn agreeing_authenticated_peers_produce_a_fix() {
        let policy = TimePolicy::default();
        let mut st = TimeState::new();
        // Two distinct authorised keys, disjoint paths, whose intervals overlap
        // around +5 ms (50 µs apart, ±50 µs each) — clears the high floor
        // (2 distinct keys, path-diverse) and Marzullo agrees on both.
        st.ingest(1, sample(5_000_000, 50_000, 0, authed(1, 1, false)));
        st.ingest(2, sample(5_050_000, 50_000, 0, authed(2, 2, false)));
        let c = policy.discipline(&mut st, 1_000_000_000, 0);
        assert!(
            c.admitted,
            "two distinct authed peers over disjoint paths clear T1/T2"
        );
        assert_eq!(c.support, 2, "overlapping intervals agree");
        assert!(
            (c.offset_ns - 5_025_000).unsigned_abs() <= 50_000,
            "offset in the agreed overlap around +5 ms, got {}",
            c.offset_ns
        );
    }

    #[test]
    fn unauthenticated_peers_are_withheld() {
        let policy = TimePolicy::default();
        let mut st = TimeState::new();
        st.ingest(
            1,
            sample(
                5_000_000,
                1_000,
                0,
                MeasurementProvenance {
                    distance_bounded: true,
                    replay_protected: true,
                    authenticity: Authenticity::Unauthenticated,
                    path: PathId(1),
                },
            ),
        );
        let c = policy.discipline(&mut st, 1_000_000_000, 0);
        assert!(!c.admitted, "an unauthenticated peer cannot found a fix");
    }

    #[test]
    fn holdover_widens_a_stale_sample() {
        let policy = TimePolicy::default();
        let mut st = TimeState::new();
        st.ingest(1, sample(0, 1_000, 0, authed(1, 1, false)));
        st.ingest(2, sample(0, 1_000, 0, authed(2, 2, false)));
        let fresh = policy.discipline(&mut st, 1_000_000_000, 0);
        // 60 s later, with no new samples, the fix is much wider (holdover).
        let mut st2 = st;
        let stale = policy.discipline(&mut st2, 1_000_000_000, 60_000_000_000);
        assert!(
            stale.uncertainty_ns > fresh.uncertainty_ns,
            "a 60 s-stale fix must be wider: {} vs {}",
            stale.uncertainty_ns,
            fresh.uncertainty_ns
        );
    }

    #[test]
    fn steerable_clock_slews_ongoing_but_steps_at_bootstrap() {
        let policy = TimePolicy::default();
        let c = Correction {
            offset_ns: 300, // 300 ns behind
            uncertainty_ns: 1_000,
            freq_skew_ppb: None,
            support: 2,
            admitted: true,
        };
        let cap = ClockCapability::oscillator_tcxo(); // disciplinable
        match policy.act(&c, &cap, false) {
            Discipline::Step { correction_ns } => assert_eq!(correction_ns, 300),
            other => panic!("bootstrap should step, got {other:?}"),
        }
        match policy.act(&c, &cap, true) {
            Discipline::Slew { rate_ppb } => {
                assert!(rate_ppb > 0 && rate_ppb <= policy.max_slew_ppb);
            }
            other => panic!("ongoing should slew, got {other:?}"),
        }
    }

    #[test]
    fn reference_clock_is_tracked_not_steered() {
        let policy = TimePolicy::default();
        let c = Correction {
            offset_ns: 42,
            uncertainty_ns: 1_000,
            freq_skew_ppb: None,
            support: 2,
            admitted: true,
        };
        // GNSS is reference_only + not disciplinable.
        match policy.act(&c, &ClockCapability::gnss_disciplined(), true) {
            Discipline::Track { correction_ns } => assert_eq!(correction_ns, 42),
            other => panic!("a reference clock is tracked, got {other:?}"),
        }
    }

    #[test]
    fn skew_regression_recovers_a_linear_drift() {
        // Offset grows 100 ns per 1 ms of monotonic time = 100_000 ppb.
        let mut sk = SkewEstimator::new();
        for i in 0..SKEW_POINTS as u64 {
            let mono = i * 1_000_000; // 1 ms steps
            let offset = (i as i64) * 100; // +100 ns per step
            sk.push(mono, offset);
        }
        let ppb = sk.skew_ppb().expect("enough points");
        assert!(
            (ppb - 100_000).abs() < 1_000,
            "expected ~100_000 ppb, got {ppb}"
        );
    }

    #[test]
    fn rebeacon_only_when_tighter() {
        let policy = TimePolicy::default();
        let tighter = Correction {
            offset_ns: 0,
            uncertainty_ns: 5_000,
            freq_skew_ppb: None,
            support: 3,
            admitted: true,
        };
        assert!(
            policy.should_rebeacon(&tighter, 20_000),
            "5µs beats last 20µs"
        );
        assert!(
            !policy.should_rebeacon(&tighter, 1_000),
            "not tighter than 1µs"
        );
        let unadmitted = Correction {
            admitted: false,
            ..tighter
        };
        assert!(!policy.should_rebeacon(&unadmitted, u64::MAX));
    }
}
