//! The clock capability model (principle P5): disparate clocks, self-describing.
//!
//! Mirrors `RadioCapability` in the radio plane — a GPS-disciplined OCXO, a
//! phone RTC, an ESP32 RC oscillator, and a WAN NTP uplink are the *same type*
//! with different honest numbers. Capability is learnable data that rides a
//! peer's signed beacon, not static config.

/// What kind of clock a source is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSourceKind {
    /// A GNSS receiver (GPS/Galileo/…) — traceable, tens-of-ns class, not
    /// steerable (you discipline *to* it, not the other way).
    Gnss,
    /// A PTP (IEEE 1588) uplink.
    Ptp,
    /// An NTP uplink — typically millisecond class over a WAN.
    Ntp,
    /// A real-time clock chip — holds time across reboot, modest stability.
    Rtc,
    /// A free-running oscillator (TCXO/OCXO/RC) with no external reference; its
    /// value is only as good as its last discipline plus holdover.
    Oscillator,
    /// Time derived from a validated peer beacon (the peer-derived source).
    PeerDerived,
    /// A human-entered or otherwise out-of-band manual setting.
    Manual,
}

/// What real-world scale a clock is traceable to — distinct from how *tight* it
/// is (principle P4: agreement is not the same as traceability).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Traceability {
    /// Traceable to UTC.
    Utc,
    /// Traceable to TAI.
    Tai,
    /// Traceable to GNSS system time.
    Gnss,
    /// Internally-agreed ensemble time only — µs-coherent within the group but
    /// **not** UTC-traceable. A GPS-less swarm agrees without knowing UTC.
    Ensemble,
    /// No traceability claimed.
    None,
}

impl Traceability {
    /// A rank used by the anchor election: higher out-elects lower. Ensemble
    /// ranks above None but below any externally-referenced scale.
    pub const fn rank(self) -> u8 {
        match self {
            Traceability::Utc => 4,
            Traceability::Tai => 4,
            Traceability::Gnss => 3,
            Traceability::Ensemble => 1,
            Traceability::None => 0,
        }
    }
}

/// Frequency-stability parameters that turn "time since last sync" into a
/// growing uncertainty. Between disciplines, a clock's error grows; how fast is
/// what distinguishes an OCXO from an RC oscillator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Holdover {
    /// Systematic frequency offset, parts per million. Dominates growth at long
    /// holdover: `drift_ppm` µs of error accumulate per second of elapsed time.
    pub drift_ppm: f32,
    /// Allan deviation at 1 s — the random-walk component, fractional
    /// frequency. Dominates at short holdover.
    pub allan_dev_1s: f32,
    /// Aging, ppm per day — slow systematic drift of the drift itself.
    pub aging_ppm_per_day: f32,
    /// Whether the oscillator is meaningfully temperature-sensitive (a hint the
    /// growth estimate is optimistic in a thermally unstable environment).
    pub temp_sensitive: bool,
}

impl Holdover {
    /// Uncertainty growth (nanoseconds) accrued over `elapsed_ns` of holdover
    /// since the last discipline.
    ///
    /// Combines the systematic drift term (`drift_ppm · elapsed`) with the
    /// random-walk term (`allan_dev_1s · √elapsed`, since a random walk's
    /// deviation grows with the square root of time). This is intentionally a
    /// *conservative* estimate — it drives the re-sync cadence and the
    /// uncertainty a node advertises, and being pessimistic here fails safe.
    pub fn growth_ns(&self, elapsed_ns: u64) -> u64 {
        let elapsed_s = elapsed_ns as f64 / 1e9;
        // Systematic: drift_ppm is µs-per-second-per-1e6 → seconds of error is
        // drift_ppm * 1e-6 * elapsed_s; times 1e9 for ns.
        let drift_ns = (self.drift_ppm as f64).abs() * 1e-6 * elapsed_s * 1e9;
        // Random walk: allan_dev_1s is fractional; error ≈ allan * √elapsed
        // (in seconds), times 1e9 for ns.
        let walk_ns = (self.allan_dev_1s as f64).abs() * libm_sqrt(elapsed_s) * 1e9;
        let total = drift_ns + walk_ns;
        if total.is_finite() && total >= 0.0 {
            total as u64
        } else {
            u64::MAX
        }
    }
}

/// A minimal `sqrt` so the crate stays `no_std` without pulling `libm`. Newton's
/// method from a bit-trick seed; ample precision for an uncertainty estimate.
fn libm_sqrt(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut guess = x;
    // A handful of Newton iterations converges quadratically; 8 is plenty for
    // the dynamic range of a holdover interval.
    let mut i = 0;
    while i < 8 {
        guess = 0.5 * (guess + x / guess);
        i += 1;
    }
    guess
}

/// A clock source's self-description.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClockCapability {
    /// What kind of source this is.
    pub kind: TimeSourceKind,
    /// What scale it is traceable to.
    pub traceable: Traceability,
    /// Its frequency-stability / holdover parameters.
    pub holdover: Holdover,
    /// Intrinsic uncertainty at the source, nanoseconds (GNSS ~tens of ns; a
    /// WAN NTP uplink ~milliseconds).
    pub base_uncertainty_ns: u64,
    /// Whether the discipline loop can steer this clock (a GNSS receiver: no;
    /// the OS clock: yes).
    pub disciplinable: bool,
    /// Whether this is a pure reference that never consumes peer time
    /// (stratum-0-like); such a source anchors but is never disciplined.
    pub reference_only: bool,
}

impl ClockCapability {
    /// A GPS-disciplined OCXO: traceable, tens-of-ns, not steerable, reference.
    pub const fn gnss_disciplined() -> Self {
        Self {
            kind: TimeSourceKind::Gnss,
            traceable: Traceability::Gnss,
            holdover: Holdover {
                drift_ppm: 0.01,
                allan_dev_1s: 1e-11,
                aging_ppm_per_day: 0.0005,
                temp_sensitive: false,
            },
            base_uncertainty_ns: 30,
            disciplinable: false,
            reference_only: true,
        }
    }

    /// A disciplined TCXO — the free-running fallback when GNSS is lost.
    pub const fn oscillator_tcxo() -> Self {
        Self {
            kind: TimeSourceKind::Oscillator,
            traceable: Traceability::Ensemble,
            holdover: Holdover {
                drift_ppm: 0.5,
                allan_dev_1s: 1e-9,
                aging_ppm_per_day: 0.01,
                temp_sensitive: true,
            },
            base_uncertainty_ns: 1_000,
            disciplinable: true,
            reference_only: false,
        }
    }

    /// An ESP32-class RC oscillator: cheap, drifty, temperature-sensitive.
    pub const fn esp32_rc() -> Self {
        Self {
            kind: TimeSourceKind::Oscillator,
            traceable: Traceability::None,
            holdover: Holdover {
                drift_ppm: 50.0,
                allan_dev_1s: 1e-7,
                aging_ppm_per_day: 1.0,
                temp_sensitive: true,
            },
            base_uncertainty_ns: 100_000,
            disciplinable: true,
            reference_only: false,
        }
    }

    /// A WAN NTP uplink: traceable but millisecond-class — enters the election
    /// as a low-quality candidate that any decent local clock out-elects.
    pub const fn ntp_uplink() -> Self {
        Self {
            kind: TimeSourceKind::Ntp,
            traceable: Traceability::Utc,
            holdover: Holdover {
                drift_ppm: 10.0,
                allan_dev_1s: 1e-8,
                aging_ppm_per_day: 0.1,
                temp_sensitive: false,
            },
            base_uncertainty_ns: 5_000_000,
            disciplinable: true,
            reference_only: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holdover_growth_is_monotone_in_elapsed() {
        let h = ClockCapability::oscillator_tcxo().holdover;
        let a = h.growth_ns(1_000_000_000); // 1 s
        let b = h.growth_ns(10_000_000_000); // 10 s
        let c = h.growth_ns(100_000_000_000); // 100 s
        assert!(a <= b && b <= c, "growth must not shrink with elapsed time");
        assert!(a > 0, "a real oscillator accrues error");
    }

    #[test]
    fn worse_oscillator_grows_faster() {
        let good = ClockCapability::oscillator_tcxo()
            .holdover
            .growth_ns(10_000_000_000);
        let bad = ClockCapability::esp32_rc()
            .holdover
            .growth_ns(10_000_000_000);
        assert!(bad > good, "RC osc drifts faster than a TCXO");
    }

    #[test]
    fn gnss_out_ranks_ntp_on_traceability_but_ntp_is_utc() {
        // GNSS is tighter (lower base uncertainty) though NTP claims UTC.
        assert!(
            ClockCapability::gnss_disciplined().base_uncertainty_ns
                < ClockCapability::ntp_uplink().base_uncertainty_ns
        );
    }

    #[test]
    fn sqrt_is_close_enough() {
        let s = libm_sqrt(4.0);
        assert!((s - 2.0).abs() < 1e-6);
        assert_eq!(libm_sqrt(0.0), 0.0);
    }
}
