//! Cross-domain clock mapping — relate two [`ClockDomainId`]s from paired stamps.
//!
//! Two clocks (a NIC TSF, a host `CLOCK_MONOTONIC`, a second radio's free-run RX counter) live in
//! different [`ClockDomainId`]s and are **not comparable** until a mapping relates them — a raw
//! value without knowing which counter it came from is a bug generator. Given paired observations
//! of the *same* event's stamp in each domain (a common-view frame heard on two radios, or a host
//! cross-timestamp of a NIC counter), a [`DomainMap`] fits the affine relation
//! `target ≈ intercept + slope · source`. The slope absorbs **both** the unit ratio (a microsecond
//! TSF vs a nanosecond host clock) **and** the relative frequency error; the intercept is the
//! phase. [`DomainMap::project`] then maps a stamp from one domain into the other so the two can be
//! differenced, and [`DomainMap::residual_ticks`] reports the fit's spread as an honest uncertainty
//! on that projection.
//!
//! This is Linux PHC / PTP cross-timestamp practice generalised, and reuses the same origin-shifted
//! streaming least-squares as the discipline loop's frequency-skew estimator — pure, `no_std`,
//! allocation-free.

use crate::{ClockDomainId, LinkStamp};

/// Paired observations retained for the cross-domain regression (a ring buffer of the most recent).
const MAP_POINTS: usize = 16;

/// A learned affine map from a **source** clock domain to a **target** clock domain, built from
/// paired stamps of shared events. See the [module docs](self).
#[derive(Clone, Copy, Debug)]
pub struct DomainMap {
    source: ClockDomainId,
    target: ClockDomainId,
    /// `(source_raw, target_raw)` pairs, ring-buffered.
    pts: [(u64, u64); MAP_POINTS],
    len: usize,
    head: usize,
}

/// The parameters of a non-degenerate least-squares fit (private; `x` is origin-shifted).
#[derive(Clone, Copy)]
struct Fit {
    x0: u64,
    x_mean: f64,
    y_mean: f64,
    slope: f64,
}

impl DomainMap {
    /// An empty map from `source` to `target`. Record pairs with [`observe`](Self::observe) before
    /// projecting.
    pub const fn new(source: ClockDomainId, target: ClockDomainId) -> Self {
        Self {
            source,
            target,
            pts: [(0, 0); MAP_POINTS],
            len: 0,
            head: 0,
        }
    }

    /// The source domain — the domain of the `raw` values passed to [`project`](Self::project).
    pub const fn source(&self) -> ClockDomainId {
        self.source
    }

    /// The target domain — the domain [`project`](Self::project) returns values in.
    pub const fn target(&self) -> ClockDomainId {
        self.target
    }

    /// Paired observations currently retained (saturates at 16).
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no observation has been recorded yet.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the fit is non-degenerate (at least two points spanning some source time), i.e.
    /// [`project`](Self::project) / [`skew_ppb`](Self::skew_ppb) will return `Some`.
    pub fn is_ready(&self) -> bool {
        self.fit().is_some()
    }

    /// Record a paired observation of one shared event: its stamp `source_raw` in the source domain
    /// and `target_raw` in the target domain. Oldest pairs are evicted past the 16-point window, so
    /// the fit tracks slow drift between the clocks.
    pub fn observe(&mut self, source_raw: u64, target_raw: u64) {
        self.pts[self.head] = (source_raw, target_raw);
        self.head = (self.head + 1) % MAP_POINTS;
        if self.len < MAP_POINTS {
            self.len += 1;
        }
    }

    /// Origin-shifted streaming least-squares of target vs source. `x0` (the smallest source value)
    /// is subtracted to keep the sums small and stable. `None` if fewer than two points or the
    /// source values share no span (a vertical, un-fittable set).
    fn fit(&self) -> Option<Fit> {
        if self.len < 2 {
            return None;
        }
        let mut x0 = u64::MAX;
        for &(s, _) in &self.pts[..self.len] {
            if s < x0 {
                x0 = s;
            }
        }
        let n = self.len as f64;
        let (mut sx, mut sy, mut sxy, mut sxx) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
        for &(s, t) in &self.pts[..self.len] {
            let x = s.saturating_sub(x0) as f64;
            let y = t as f64;
            sx += x;
            sy += y;
            sxy += x * y;
            sxx += x * x;
        }
        let denom = n * sxx - sx * sx;
        if denom == 0.0 {
            return None;
        }
        Some(Fit {
            x0,
            x_mean: sx / n,
            y_mean: sy / n,
            slope: (n * sxy - sx * sy) / denom,
        })
    }

    /// Project a source-domain raw value into the target domain (in target ticks). `None` until a
    /// non-degenerate fit exists. Returns `i128` because a projection may fall outside `u64` while
    /// extrapolating (or before the phase is well-anchored); a caller comparing recent stamps can
    /// treat an in-range positive result as the target-domain equivalent. Pair with
    /// [`residual_ticks`](Self::residual_ticks) for its uncertainty.
    pub fn project(&self, source_raw: u64) -> Option<i128> {
        let f = self.fit()?;
        let x = source_raw.saturating_sub(f.x0) as f64;
        Some((f.y_mean + f.slope * (x - f.x_mean)) as i128)
    }

    /// The largest absolute residual of the fit (in target ticks) — a conservative ± on any
    /// [`project`](Self::project) result. `None` until a fit exists. A clean, jitter-free pair of
    /// clocks yields ~0; jitter/asymmetry in the paired stamps shows up here honestly.
    pub fn residual_ticks(&self) -> Option<u64> {
        let f = self.fit()?;
        let mut max = 0.0f64;
        for &(s, t) in &self.pts[..self.len] {
            let x = s.saturating_sub(f.x0) as f64;
            let pred = f.y_mean + f.slope * (x - f.x_mean);
            let r = (t as f64 - pred).abs();
            if r > max {
                max = r;
            }
        }
        Some(max as u64)
    }

    /// Fractional frequency error of the target clock relative to the source, in parts-per-billion
    /// (the fit slope minus 1, scaled). **Only meaningful when both domains tick at the same
    /// nominal rate** (e.g. two microsecond TSFs, or two nanosecond clocks) — for mixed-unit domains
    /// (a µs TSF projected into a ns host clock) the slope is the unit ratio, so use
    /// [`project`](Self::project) instead. `None` until a fit exists.
    pub fn skew_ppb(&self) -> Option<i64> {
        let f = self.fit()?;
        Some(((f.slope - 1.0) * 1e9) as i64)
    }

    /// Project a [`LinkStamp`] from this map's source domain into its target domain — the bridge
    /// that makes a stamp taken on one radio/clock comparable against another. The result carries
    /// the target domain and the *same* latch point, with its precision **widened** by the
    /// mapping's own uncertainty (`residual_ticks` × `target_tick_ns`, the target's nominal tick
    /// in ns) added to the source stamp's — an honest ± that never shrinks. Returns `None` if the
    /// stamp is not in the source domain or the fit is not ready yet.
    pub fn project_stamp(&self, stamp: &LinkStamp, target_tick_ns: u32) -> Option<LinkStamp> {
        if stamp.domain != self.source {
            return None;
        }
        let raw = self.project(stamp.raw)?.max(0) as u64;
        let map_unc_ns = self
            .residual_ticks()
            .unwrap_or(0)
            .saturating_mul(u64::from(target_tick_ns));
        let precision_ns =
            (u64::from(stamp.precision_ns) + map_unc_ns).min(u64::from(u32::MAX)) as u32;
        Some(LinkStamp::new(raw, self.target, precision_ns, stamp.latch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ClockDomainId = ClockDomainId(1);
    const B: ClockDomainId = ClockDomainId(2);

    #[test]
    fn empty_is_not_ready() {
        let m = DomainMap::new(A, B);
        assert!(m.is_empty());
        assert!(!m.is_ready());
        assert_eq!(m.project(100), None);
        assert_eq!(m.skew_ppb(), None);
    }

    #[test]
    fn recovers_exact_affine_same_unit() {
        // target = 5000 + 1 * source (pure phase offset, same rate/unit).
        let mut m = DomainMap::new(A, B);
        for s in (0u64..8).map(|i| i * 1000) {
            m.observe(s, 5000 + s);
        }
        assert!(m.is_ready());
        assert_eq!(m.project(10_000), Some(15_000));
        assert_eq!(m.residual_ticks(), Some(0));
        assert_eq!(m.skew_ppb(), Some(0)); // same rate
    }

    #[test]
    fn recovers_frequency_skew() {
        // target runs 100 ppm fast: slope = 1.0001 -> skew ~= 100_000 ppb.
        let mut m = DomainMap::new(A, B);
        for i in 0u64..12 {
            let s = i * 1_000_000;
            let t = 2_000 + (s as f64 * 1.0001) as u64;
            m.observe(s, t);
        }
        let ppb = m.skew_ppb().unwrap();
        assert!((ppb - 100_000).abs() < 500, "skew {ppb} ppb");
    }

    #[test]
    fn maps_across_units_us_to_ns() {
        // source is a µs TSF, target a ns host clock offset by 7_000_000 ns: slope = 1000.
        let mut m = DomainMap::new(A, B);
        for i in 0u64..8 {
            let src_us = i * 1000;
            let tgt_ns = 7_000_000 + src_us * 1000;
            m.observe(src_us, tgt_ns);
        }
        // 12_000 µs -> 7_000_000 + 12_000*1000 = 19_000_000 ns.
        assert_eq!(m.project(12_000), Some(19_000_000));
    }

    #[test]
    fn residual_reflects_jitter() {
        // A wobbly pair (±3 target ticks around target = source) -> residual >= the wobble.
        let mut m = DomainMap::new(A, B);
        let wobble = [0i64, 3, -2, 1, -3, 2, 0, -1];
        for (i, w) in wobble.iter().enumerate() {
            let s = (i as u64) * 100;
            m.observe(s, (s as i64 + w) as u64);
        }
        assert!(m.residual_ticks().unwrap() >= 1);
    }

    #[test]
    fn project_stamp_moves_domain_and_keeps_latch() {
        use crate::LatchPoint;
        let mut m = DomainMap::new(A, B);
        for s in (0u64..8).map(|i| i * 1000) {
            m.observe(s, 5000 + s); // exact affine, residual 0
        }
        let src = LinkStamp::new(10_000, A, 1_000, LatchPoint::MacDone);
        let proj = m.project_stamp(&src, 1000).unwrap();
        assert_eq!(proj.domain, B);
        assert_eq!(proj.raw, 15_000);
        assert_eq!(proj.latch, LatchPoint::MacDone);
        assert_eq!(proj.precision_ns, 1_000); // residual 0 -> unchanged (at the MacDone floor)
        // a stamp already in the target (wrong source) domain is rejected.
        let wrong = LinkStamp::new(10_000, B, 1_000, LatchPoint::MacDone);
        assert!(m.project_stamp(&wrong, 1000).is_none());
    }
}
