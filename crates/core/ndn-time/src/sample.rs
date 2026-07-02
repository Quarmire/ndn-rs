//! A single time sample — a wall-clock belief anchored to monotonic capture.

use crate::interval::TimeInterval;
use crate::provenance::MeasurementProvenance;

/// One validated observation of wall-clock time.
///
/// The wall-clock estimate is an interval (principle P2). It is anchored to
/// `captured_mono_ns` — a reading of the *local monotonic* clock at capture,
/// which cannot regress and needs no network (principle P3). Anchoring to
/// monotonic time is what lets the combiner age a sample's uncertainty by
/// holdover (`elapsed = now_mono - captured_mono_ns`) and order samples
/// *before* any wall-clock sync exists.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TimeSample {
    /// Wall-clock estimate as an interval, Unix nanoseconds.
    pub wall: TimeInterval,
    /// Local monotonic clock at the instant this sample was captured,
    /// nanoseconds. Monotone, network-free, non-regressing.
    pub captured_mono_ns: u64,
    /// Adversary exposure of this sample.
    pub prov: MeasurementProvenance,
}

impl TimeSample {
    /// Build a sample.
    pub const fn new(
        wall: TimeInterval,
        captured_mono_ns: u64,
        prov: MeasurementProvenance,
    ) -> Self {
        Self {
            wall,
            captured_mono_ns,
            prov,
        }
    }

    /// This sample's wall interval **aged to `now_mono_ns`** by widening its
    /// radius with `holdover_growth` accrued since capture. Never narrows; if
    /// `now_mono_ns` precedes capture (clock read races) the interval is
    /// returned unaged rather than narrowed.
    pub fn aged(&self, now_mono_ns: u64, holdover_growth: impl Fn(u64) -> u64) -> TimeInterval {
        let elapsed = now_mono_ns.saturating_sub(self.captured_mono_ns);
        self.wall.widened(holdover_growth(elapsed))
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn aging_widens_with_elapsed_monotonic_time() {
        let s = TimeSample::new(TimeInterval::new(1_000, 100), 500, prov());
        // grow 1 ns per ns elapsed for the test.
        let iv0 = s.aged(500, |e| e);
        let iv1 = s.aged(1_500, |e| e); // elapsed 1000
        assert_eq!(iv0.radius_ns, 100);
        assert_eq!(iv1.radius_ns, 1_100);
    }

    #[test]
    fn aging_does_not_narrow_on_backward_now() {
        let s = TimeSample::new(TimeInterval::new(1_000, 100), 500, prov());
        let iv = s.aged(400, |e| e); // now precedes capture
        assert_eq!(iv.radius_ns, 100, "never narrows");
    }
}
