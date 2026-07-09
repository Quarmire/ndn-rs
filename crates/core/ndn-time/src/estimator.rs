//! The coupled time-and-shape estimator (named-time **§14**) — the consumer of Cut 3
//! [`ChannelObs`](crate::ChannelObs).
//!
//! Sync, ranging, and kinematics are not three problems but one: the time-of-flight term in a
//! one-way time transfer *is* `range / c`, so a clock offset and a distance are entangled in the
//! same measurement. This estimator fuses them into a single state — a peer's relative position,
//! velocity, and clock (offset + skew) — so range tightens the sync path-delay term, range-rate
//! gives velocity, and (per §14) the joint solution is what yields **GPS-denied relative
//! positioning**. It is a genuine nonlinear estimator (an EKF), not a one-liner.
//!
//! **State** (8-vector): relative position `p` (m), relative velocity `v` (m/s), clock offset `b`
//! (s; `peer = self + b`), clock skew `d` (s/s). **Process model**: constant velocity + constant
//! skew, with white-noise-acceleration process noise. **Measurements** (each scalar, with its own
//! variance — the honest `sigma` from [`ChannelObs`]):
//! - [`Range`](crate::ChannelObs::Range): `h = ‖p‖`.
//! - [`Doppler`](crate::ChannelObs::Doppler): `h = −(f_c/c)·(p·v)/‖p‖` (range-rate → shift).
//! - one-way time ([`observe_owd`](CoupledEstimator::observe_owd)): `h = b + ‖p‖/c` — **the
//!   coupling**; range resolves the path delay, tightening `b`.
//! - direct offset ([`observe_offset`](CoupledEstimator::observe_offset), e.g. two-way): `h = b`.
//!
//! **Observability is a named risk** (§14): whether relative position and clock are observable
//! depends on geometry and motion — a stationary or collinear formation can be unobservable
//! regardless of measurement quality. The filter never hides this: [`position_stddev`] reports the
//! current position uncertainty, which simply does not shrink when the geometry is unobservable.
//! [`Bearing`](crate::ChannelObs::Bearing) is intentionally **not** consumed here — it needs
//! trigonometry (this crate is `no_std`, `libm`-free) and, per §14, per-antenna phase calibration
//! makes AoA fragile enough that leaning on it is a design hazard; range is the forgiving observable.
//!
//! [`position_stddev`]: CoupledEstimator::position_stddev

use crate::channel_obs::{ChannelObs, C_M_PER_S};

/// State dimension: `[px, py, pz, vx, vy, vz, offset, skew]`.
const N: usize = 8;
const PX: usize = 0;
const VX: usize = 3;
const B: usize = 6;
const D: usize = 7;

/// A joint estimate of a peer's relative geometry and clock — the §14 coupled state machine.
///
/// Drive it with [`predict`](Self::predict) on a time step, then feed measurements as they arrive
/// ([`observe`](Self::observe) for a [`ChannelObs`], [`observe_owd`](Self::observe_owd) /
/// [`observe_offset`](Self::observe_offset) for time). Read the fused result via the accessors.
#[derive(Clone, Debug)]
pub struct CoupledEstimator {
    /// State mean.
    x: [f64; N],
    /// State covariance (symmetric).
    p: [[f64; N]; N],
    /// White-noise-acceleration density, `(m/s²)²·s` — how fast velocity may drift.
    q_accel: f64,
    /// Clock-skew random-walk density, `(s/s)²·s`.
    q_skew: f64,
}

impl CoupledEstimator {
    /// Initialise from a first guess and its 1-σ uncertainties. `pos`/`vel` are the relative
    /// position (m) and velocity (m/s); `offset` (s) and `skew` (s/s) the clock state. The `*_std`
    /// values seed the diagonal covariance — make them large when the guess is weak (e.g. a
    /// range-only cold start knows the distance but not the direction). `q_accel` / `q_skew` are the
    /// process-noise densities (maneuvering agility / oscillator random walk).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pos: [f64; 3],
        vel: [f64; 3],
        offset: f64,
        skew: f64,
        pos_std: f64,
        vel_std: f64,
        offset_std: f64,
        skew_std: f64,
        q_accel: f64,
        q_skew: f64,
    ) -> Self {
        let mut x = [0.0; N];
        x[PX..PX + 3].copy_from_slice(&pos);
        x[VX..VX + 3].copy_from_slice(&vel);
        x[B] = offset;
        x[D] = skew;
        let mut p = [[0.0; N]; N];
        let var = [
            pos_std * pos_std,
            pos_std * pos_std,
            pos_std * pos_std,
            vel_std * vel_std,
            vel_std * vel_std,
            vel_std * vel_std,
            offset_std * offset_std,
            skew_std * skew_std,
        ];
        for i in 0..N {
            p[i][i] = var[i];
        }
        Self {
            x,
            p,
            q_accel,
            q_skew,
        }
    }

    /// Predict forward by `dt_s` seconds: position advances by velocity, offset by skew, and the
    /// covariance grows by the state transition + process noise (constant-velocity / constant-skew).
    pub fn predict(&mut self, dt_s: f64) {
        if dt_s <= 0.0 {
            return;
        }
        // State: p += v·dt, b += d·dt.
        for k in 0..3 {
            self.x[PX + k] += self.x[VX + k] * dt_s;
        }
        self.x[B] += self.x[D] * dt_s;

        // Covariance: P = F P Fᵀ, with F = I plus the position←velocity and offset←skew couplings.
        let mut f = ident();
        for k in 0..3 {
            f[PX + k][VX + k] = dt_s;
        }
        f[B][D] = dt_s;
        self.p = mat_mul(&mat_mul(&f, &self.p), &transpose(&f));

        // White-noise-acceleration process noise on each position/velocity axis + the clock pair.
        let (dt2, dt3) = (dt_s * dt_s, dt_s * dt_s * dt_s);
        for k in 0..3 {
            self.p[PX + k][PX + k] += self.q_accel * dt3 / 3.0;
            self.p[PX + k][VX + k] += self.q_accel * dt2 / 2.0;
            self.p[VX + k][PX + k] += self.q_accel * dt2 / 2.0;
            self.p[VX + k][VX + k] += self.q_accel * dt_s;
        }
        self.p[B][B] += self.q_skew * dt3 / 3.0;
        self.p[B][D] += self.q_skew * dt2 / 2.0;
        self.p[D][B] += self.q_skew * dt2 / 2.0;
        self.p[D][D] += self.q_skew * dt_s;
    }

    /// Fold in a [`ChannelObs`]. Returns `false` for [`Bearing`](ChannelObs::Bearing) (not consumed
    /// here — see the module docs) and for a degenerate (near-zero range) geometry; `true` when the
    /// observation updated the state. `carrier_hz` is the RF carrier for the Doppler model
    /// (ignored by [`Range`](ChannelObs::Range)).
    pub fn observe(&mut self, obs: &ChannelObs, carrier_hz: f64) -> bool {
        match *obs {
            ChannelObs::Range { m, sigma_m } => self.observe_range(m, sigma_m),
            ChannelObs::Doppler { hz, sigma_hz } => self.observe_doppler(hz, sigma_hz, carrier_hz),
            ChannelObs::Bearing { .. } => false,
        }
    }

    /// A distance measurement `m ± sigma_m` (m): `h = ‖p‖`.
    pub fn observe_range(&mut self, m: f64, sigma_m: f64) -> bool {
        let r = self.range();
        if r < 1e-6 {
            return false;
        }
        let mut h = [0.0; N];
        for k in 0..3 {
            h[PX + k] = self.x[PX + k] / r;
        }
        self.update_scalar(&h, r, m, sigma_m * sigma_m);
        true
    }

    /// A Doppler shift `hz ± sigma_hz` at RF carrier `carrier_hz`: `h = −(f_c/c)·(p·v)/‖p‖`
    /// (closing → positive shift). Gives velocity — the state term the pure time/range path can't.
    pub fn observe_doppler(&mut self, hz: f64, sigma_hz: f64, carrier_hz: f64) -> bool {
        let r = self.range();
        if r < 1e-6 || carrier_hz <= 0.0 {
            return false;
        }
        let pv = self.x[PX] * self.x[VX] + self.x[PX + 1] * self.x[VX + 1] + self.x[PX + 2] * self.x[VX + 2];
        let rr = pv / r; // range-rate
        let k_fc = -carrier_hz / C_M_PER_S;
        let h_pred = k_fc * rr;
        // ∂rr/∂p_i = v_i/r − (p·v)·p_i/r³ ;  ∂rr/∂v_i = p_i/r
        let r3 = r * r * r;
        let mut h = [0.0; N];
        for k in 0..3 {
            h[PX + k] = k_fc * (self.x[VX + k] / r - pv * self.x[PX + k] / r3);
            h[VX + k] = k_fc * (self.x[PX + k] / r);
        }
        self.update_scalar(&h, h_pred, hz, sigma_hz * sigma_hz);
        true
    }

    /// A one-way time observation: the measured (offset + propagation delay) in seconds,
    /// `meas_s ± sigma_s`, modelled as `h = b + ‖p‖/c`. **This is the coupling** — the shared
    /// `range` term is why a range fix tightens the clock estimate and vice-versa.
    pub fn observe_owd(&mut self, meas_s: f64, sigma_s: f64) -> bool {
        let r = self.range();
        if r < 1e-6 {
            return false;
        }
        let mut h = [0.0; N];
        for k in 0..3 {
            h[PX + k] = self.x[PX + k] / (C_M_PER_S * r);
        }
        h[B] = 1.0;
        let h_pred = self.x[B] + r / C_M_PER_S;
        self.update_scalar(&h, h_pred, meas_s, sigma_s * sigma_s);
        true
    }

    /// A direct clock-offset measurement `meas_s ± sigma_s` (s) — e.g. a two-way exchange where the
    /// path delay cancels: `h = b`.
    pub fn observe_offset(&mut self, meas_s: f64, sigma_s: f64) {
        let mut h = [0.0; N];
        h[B] = 1.0;
        self.update_scalar(&h, self.x[B], meas_s, sigma_s * sigma_s);
    }

    /// The relative position estimate `[x, y, z]` (m).
    pub fn position(&self) -> [f64; 3] {
        [self.x[PX], self.x[PX + 1], self.x[PX + 2]]
    }
    /// The relative velocity estimate `[vx, vy, vz]` (m/s).
    pub fn velocity(&self) -> [f64; 3] {
        [self.x[VX], self.x[VX + 1], self.x[VX + 2]]
    }
    /// The clock-offset estimate (s; `peer = self + offset`).
    pub fn clock_offset(&self) -> f64 {
        self.x[B]
    }
    /// The clock-skew estimate (s/s).
    pub fn clock_skew(&self) -> f64 {
        self.x[D]
    }
    /// The current range estimate `‖p‖` (m).
    pub fn range(&self) -> f64 {
        sqrt(self.x[PX] * self.x[PX] + self.x[PX + 1] * self.x[PX + 1] + self.x[PX + 2] * self.x[PX + 2])
    }
    /// The 1-σ position uncertainty (m), `√tr(P_pos)` — the observability readout. It stays large
    /// when the geometry/motion leaves position unobservable (§14), and shrinks as fixes accrue.
    pub fn position_stddev(&self) -> f64 {
        sqrt(self.p[PX][PX] + self.p[PX + 1][PX + 1] + self.p[PX + 2][PX + 2])
    }
    /// The 1-σ clock-offset uncertainty (s), `√P_bb`.
    pub fn offset_stddev(&self) -> f64 {
        sqrt(self.p[B][B])
    }

    /// EKF scalar-measurement update: innovation `z − h_pred`, gain `K = P Hᵀ / (H P Hᵀ + r)`,
    /// `x += K·innov`, `P −= K (H P)`. Scalar innovation covariance → no matrix inversion.
    #[allow(clippy::needless_range_loop)] // matrix-vector math indexing several arrays in lockstep
    fn update_scalar(&mut self, h: &[f64; N], h_pred: f64, z: f64, r: f64) {
        // PHt = P·Hᵀ  (P symmetric)
        let mut pht = [0.0; N];
        for i in 0..N {
            let mut s = 0.0;
            for j in 0..N {
                s += self.p[i][j] * h[j];
            }
            pht[i] = s;
        }
        let mut s = r;
        for j in 0..N {
            s += h[j] * pht[j];
        }
        if s <= 0.0 {
            return;
        }
        let innov = z - h_pred;
        // x += K·innov ; P -= K·(HP) with K = PHt/s and HP = PHtᵀ (symmetry).
        for i in 0..N {
            let k_i = pht[i] / s;
            self.x[i] += k_i * innov;
            for j in 0..N {
                self.p[i][j] -= k_i * pht[j];
            }
        }
        // Re-symmetrise to damp numerical drift.
        for i in 0..N {
            for j in (i + 1)..N {
                let avg = 0.5 * (self.p[i][j] + self.p[j][i]);
                self.p[i][j] = avg;
                self.p[j][i] = avg;
            }
        }
    }
}

// ── tiny fixed-size linear algebra (no_std, no alloc) ───────────────────────────────────────────

fn ident() -> [[f64; N]; N] {
    let mut m = [[0.0; N]; N];
    for (i, row) in m.iter_mut().enumerate() {
        row[i] = 1.0;
    }
    m
}

fn transpose(a: &[[f64; N]; N]) -> [[f64; N]; N] {
    let mut t = [[0.0; N]; N];
    for i in 0..N {
        for j in 0..N {
            t[j][i] = a[i][j];
        }
    }
    t
}

fn mat_mul(a: &[[f64; N]; N], b: &[[f64; N]; N]) -> [[f64; N]; N] {
    let mut c = [[0.0; N]; N];
    for i in 0..N {
        for k in 0..N {
            let aik = a[i][k];
            if aik == 0.0 {
                continue;
            }
            for j in 0..N {
                c[i][j] += aik * b[k][j];
            }
        }
    }
    c
}

/// `no_std` square root (Newton's method) — matches the crate's `libm`-free policy.
fn sqrt(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut g = x;
    let mut i = 0;
    while i < 40 {
        let ng = 0.5 * (g + x / g);
        if (ng - g).abs() < 1e-12 * ng {
            return ng;
        }
        g = ng;
        i += 1;
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    // Truth: a peer moving on a line, with a fixed clock offset + skew.
    struct Truth {
        p: [f64; 3],
        v: [f64; 3],
        b: f64,
        d: f64,
    }
    impl Truth {
        fn step(&mut self, dt: f64) {
            for k in 0..3 {
                self.p[k] += self.v[k] * dt;
            }
            self.b += self.d * dt;
        }
        fn range(&self) -> f64 {
            sqrt(self.p[0] * self.p[0] + self.p[1] * self.p[1] + self.p[2] * self.p[2])
        }
        fn doppler(&self, fc: f64) -> f64 {
            let pv = self.p[0] * self.v[0] + self.p[1] * self.v[1] + self.p[2] * self.v[2];
            -fc / C_M_PER_S * pv / self.range()
        }
        fn owd(&self) -> f64 {
            self.b + self.range() / C_M_PER_S
        }
    }

    #[test]
    fn coupling_converges_range_and_clock_for_a_moving_peer() {
        // Range + Doppler + one-way time from a single observer converge the *observable* quantities
        // — range, clock offset, skew — and the range/owd coupling pins the clock far better than
        // the raw init. (Full 3D *direction* is rotationally ambiguous without bearing: §14's
        // observability caveat, exercised by `range_only_stationary_is_unobservable`.)
        let fc = 5.18e9;
        let mut t = Truth {
            p: [120.0, 60.0, 25.0],
            v: [4.0, -3.0, 1.0],
            b: 1.0e-3,
            d: 1.0e-7,
        };
        // Init: range ~9 m off, offset 0.3 ms off, skew unknown — wide covariance.
        let mut e = CoupledEstimator::new(
            [135.0, 48.0, 33.0],
            [1.0, -1.0, 0.0],
            1.3e-3,
            0.0,
            25.0,
            5.0,
            1.0e-3,
            1.0e-6,
            1.0,
            1.0e-14,
        );
        let dt = 0.1;
        let off_std0 = e.offset_stddev();
        for _ in 0..200 {
            t.step(dt);
            e.predict(dt);
            e.observe_range(t.range(), 1.0); // ±1 m
            e.observe_doppler(t.doppler(fc), 2.0, fc); // ±2 Hz
            e.observe_owd(t.owd(), 20e-9); // one-way time ±20 ns
        }
        // Range is observable and locks on:
        assert!((e.range() - t.range()).abs() < 3.0, "range err {}", (e.range() - t.range()).abs());
        // The coupling did its job: with range resolving the path delay, the clock offset is pinned
        // far below the 0.3 ms init error, and its uncertainty collapsed.
        assert!(
            (e.clock_offset() - t.b).abs() < 5e-8,
            "offset err {} s",
            (e.clock_offset() - t.b).abs()
        );
        assert!(e.offset_stddev() < off_std0 / 100.0, "clock uncertainty barely shrank");
        // Skew (from the offset drifting across the run) is recovered to within a few ppb.
        assert!((e.clock_skew() - t.d).abs() < 5e-9, "skew err {}", (e.clock_skew() - t.d).abs());
    }

    #[test]
    fn range_only_stationary_is_unobservable() {
        // A stationary peer with range-only fixes: the distance is known, the *direction* is not —
        // §14's observability hazard. Position uncertainty must NOT collapse.
        let mut e = CoupledEstimator::new(
            [100.0, 0.0, 0.0],
            [0.0, 0.0, 0.0],
            0.0,
            0.0,
            40.0,
            0.1,
            1e-6,
            1e-9,
            1e-6,
            1e-18,
        );
        let truth = [70.0, 70.0, 0.0]; // same 100 m range, different direction
        let r = sqrt(truth[0] * truth[0] + truth[1] * truth[1] + truth[2] * truth[2]);
        for _ in 0..300 {
            e.predict(0.1);
            e.observe_range(r, 1.0);
        }
        // Range pins the radial coordinate but the tangential stays wide → position σ well above the
        // range noise. The filter is honest about the unobservable direction rather than
        // over-converging to a wrong point.
        assert!(
            e.position_stddev() > 10.0,
            "range-only stationary should stay uncertain, got σ={}",
            e.position_stddev()
        );
    }
}
