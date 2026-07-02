//! Uncertainty as a first-class interval (principle P2).

/// A wall-clock estimate as an interval `[center - radius, center + radius]`,
/// in nanoseconds since the Unix epoch.
///
/// This is the NTP root-dispersion idea promoted to a required, load-bearing
/// field: a time value is never a bare point. A wide interval means "I don't
/// know the time well" — which is exactly what lets a degraded or attacked node
/// be *correctly distrusted* instead of silently wrong.
///
/// `center` is signed (a pre-1970 or far-future estimate is representable);
/// `radius` is unsigned and saturating (uncertainty never wraps to a tiny
/// value, which would be a security bug — see [`Self::widened`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeInterval {
    /// Best estimate of wall-clock time, Unix nanoseconds.
    pub center_ns: i64,
    /// Half-width of the interval, nanoseconds. The true time is believed to
    /// lie in `[center_ns - radius_ns, center_ns + radius_ns]`.
    pub radius_ns: u64,
}

impl TimeInterval {
    /// An interval from a center and a half-width.
    pub const fn new(center_ns: i64, radius_ns: u64) -> Self {
        Self {
            center_ns,
            radius_ns,
        }
    }

    /// The lower bound, saturating so an enormous radius cannot wrap the bound
    /// past `i64::MIN`.
    pub const fn lo(&self) -> i64 {
        self.center_ns.saturating_sub_unsigned(self.radius_ns)
    }

    /// The upper bound, saturating at `i64::MAX`.
    pub const fn hi(&self) -> i64 {
        self.center_ns.saturating_add_unsigned(self.radius_ns)
    }

    /// Whether `t` (Unix nanoseconds) lies within the interval.
    pub const fn contains(&self, t: i64) -> bool {
        self.lo() <= t && t <= self.hi()
    }

    /// Full width `2 * radius_ns`, saturating.
    pub const fn width_ns(&self) -> u64 {
        self.radius_ns.saturating_mul(2)
    }

    /// Widen the interval by `extra_ns` (e.g. holdover growth since the last
    /// sync, or an asymmetry penalty). Saturating: uncertainty only ever grows
    /// here, and can never wrap to a smaller — falsely confident — radius.
    #[must_use]
    pub const fn widened(&self, extra_ns: u64) -> Self {
        Self {
            center_ns: self.center_ns,
            radius_ns: self.radius_ns.saturating_add(extra_ns),
        }
    }

    /// The intersection of two intervals, or `None` if they are disjoint.
    ///
    /// Intersecting two independent estimates of the same quantity is how
    /// evidence tightens a fix; disjointness is a *disagreement* the caller must
    /// treat as possible tampering (widen, do not pick a point).
    pub fn intersect(&self, other: &TimeInterval) -> Option<TimeInterval> {
        let lo = self.lo().max(other.lo());
        let hi = self.hi().min(other.hi());
        if lo > hi {
            return None;
        }
        // Rebuild center/radius from the intersected bounds. Width fits u64
        // because both inputs' widths did and intersection only shrinks it.
        let radius = (hi.wrapping_sub(lo) as u64) / 2;
        let center = lo.saturating_add_unsigned(radius);
        Some(TimeInterval::new(center, radius))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_saturate_and_do_not_wrap() {
        let huge = TimeInterval::new(0, u64::MAX);
        assert_eq!(huge.lo(), i64::MIN);
        assert_eq!(huge.hi(), i64::MAX);
    }

    #[test]
    fn contains_is_inclusive() {
        let iv = TimeInterval::new(100, 10);
        assert!(iv.contains(90));
        assert!(iv.contains(110));
        assert!(!iv.contains(89));
        assert!(!iv.contains(111));
    }

    #[test]
    fn widened_only_grows_and_saturates() {
        let iv = TimeInterval::new(100, 10);
        assert_eq!(iv.widened(5).radius_ns, 15);
        assert_eq!(iv.widened(u64::MAX).radius_ns, u64::MAX);
    }

    #[test]
    fn intersect_tightens_overlap() {
        let a = TimeInterval::new(100, 20); // [80, 120]
        let b = TimeInterval::new(110, 20); // [90, 130]
        let c = a.intersect(&b).expect("overlap");
        assert_eq!(c.lo(), 90);
        assert_eq!(c.hi(), 120);
    }

    #[test]
    fn intersect_disjoint_is_none() {
        let a = TimeInterval::new(0, 5); // [-5, 5]
        let b = TimeInterval::new(100, 5); // [95, 105]
        assert!(a.intersect(&b).is_none());
    }
}
