//! Bearer-agnostic channel observations (named-time **Cut 3**).
//!
//! A positioning/sensing estimator never sees a raw CSI matrix or a chipset's RSSI table — it sees
//! typed [`ChannelObs`], each carrying its own uncertainty. Wi-Fi CSI yields range and (fragile)
//! bearing; UWB yields range directly; a camera on modulated LEDs yields bearing; an M1 round-trip
//! yields coarse range. The coupled time-and-shape estimator consumes `ChannelObs` alongside time
//! samples and is thereby agnostic to which bearer produced them.

/// Speed of light in vacuum, m/s — the time-of-flight ↔ distance constant.
pub const C_M_PER_S: f64 = 299_792_458.0;

/// A single channel observation with an honest one-sigma uncertainty.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChannelObs {
    /// A distance estimate: `m` metres ± `sigma_m`. From UWB (~0.1 m), Wi-Fi FTM/CSI, or an M1 RTT.
    Range {
        /// Distance, metres.
        m: f64,
        /// One-sigma uncertainty, metres.
        sigma_m: f64,
    },
    /// An angle of arrival: azimuth/elevation radians ± `sigma_rad`. From CSI phase (fragile —
    /// per-antenna calibration drifts with temperature) or a camera on modulated LEDs.
    Bearing {
        /// Azimuth, radians.
        az: f64,
        /// Elevation, radians.
        el: f64,
        /// One-sigma uncertainty, radians.
        sigma_rad: f64,
    },
    /// A Doppler shift: `hz` Hz ± `sigma_hz` — range-rate, hence relative velocity.
    Doppler {
        /// Frequency shift, Hz.
        hz: f64,
        /// One-sigma uncertainty, Hz.
        sigma_hz: f64,
    },
}

impl ChannelObs {
    /// A coarse [`Range`](Self::Range) from a two-way round-trip time (named-time M1 yields this for
    /// free): `d = c · rtt / 2`. `rtt_ns` is the measured round trip, `sigma_ns` its jitter.
    ///
    /// This is honest time-of-flight, **not** an adversarial distance *upper bound* (threat T1): a
    /// relay can inflate `rtt`, so a consumer must treat it as a cross-check, never a security bound.
    pub fn range_from_rtt(rtt_ns: f64, sigma_ns: f64) -> Self {
        let scale = C_M_PER_S * 1e-9 / 2.0; // metres per ns of round trip
        ChannelObs::Range {
            m: rtt_ns * scale,
            sigma_m: sigma_ns * scale,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_from_rtt_is_half_light_travel() {
        // 1000 ns round trip -> c * 1000 ns / 2 = 149.896 m; jitter scales the same.
        match ChannelObs::range_from_rtt(1000.0, 100.0) {
            ChannelObs::Range { m, sigma_m } => {
                assert!((m - 149.896_229).abs() < 1e-3, "m = {m}");
                assert!((sigma_m - 14.989_622).abs() < 1e-3, "sigma = {sigma_m}");
            }
            _ => panic!("expected Range"),
        }
    }
}
