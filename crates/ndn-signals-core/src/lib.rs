//! Layer: spec — canonical cross-layer **signal** taxonomy and the
//! `SignalView` / `SignalStore` traits.
//!
//! A *signal* is an external/environmental input to a forwarding decision —
//! radio link quality (RSSI, SNR, congestion), or node-level state (GPS
//! position, heading, battery). This is distinct from **measurements** (RTT,
//! satisfaction ratio) which are *derived from observed NDN traffic* and live
//! in the strategy layer's `MeasurementsTable`.
//!
//! This crate is the security/forwarding-core sibling for cross-layer state:
//! the part that must be byte/contract-identical on every platform. It defines
//! the typed signal structs and the read (`SignalView`) / push (`SignalStore`)
//! traits; the concrete stores are per-engine adapters (native `DashMap`,
//! embedded `heapless`), and the *sources* that fill them are a separate
//! pluggable library. `no_std`, no alloc, no heavy deps.
//!
//! ## Local telemetry, not wire data
//!
//! RSSI / SNR / own-position are **local** cross-layer inputs and never travel
//! on the NDN wire as a side channel. A *neighbor's* position that is
//! legitimately shared arrives as ordinary named, signed Data (via a
//! discovery/neighbor protocol) and is cached under [`SignalView::neighbor`].
//!
//! ## Units (part of the contract)
//!
//! Units are fixed so a LoRa backend and a browser-geolocation backend agree:
//! RSSI/SNR in whole dB(m); rates as `0.0..=1.0`; geographic coordinates as
//! degrees × 1e7 (`*_e7`), altitude in cm; heading in centidegrees; speed in
//! cm/s. Every reading carries a monotonic `updated_ms` stamp for staleness.

#![no_std]
#![forbid(unsafe_code)]

/// Coarse congestion level, aligned with NDNLPv2 congestion marking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CongestionLevel {
    Low,
    Medium,
    High,
}

/// Per-face, hop-local link signals. Every metric is `Option` — a backend
/// provides what it can read. `Copy` (small, fixed) so views return by value.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LinkSignals {
    /// Received signal strength, dBm (e.g. `-67`).
    pub rssi_dbm: Option<i8>,
    /// Signal-to-noise ratio, dB.
    pub snr_db: Option<i8>,
    /// Link retransmit rate over a recent window, `0.0..=1.0`.
    pub retransmit_rate: Option<f32>,
    /// Coarse congestion level (NDNLP-mark aligned).
    pub congestion: Option<CongestionLevel>,
    /// Link-level RTT, ms — distinct from prefix-level `MeasurementsTable` RTT.
    pub observed_rtt_ms: Option<f32>,
    /// Link-level throughput, bits/s.
    pub observed_tput_bps: Option<u32>,
    /// Monotonic millisecond stamp of the last update (staleness).
    pub updated_ms: u32,
}

/// Fixed-point geographic position. Integer-only (no float, no trig) so it is
/// usable on the bare-metal floor and stable across backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoPos {
    /// Latitude in degrees × 1e7.
    pub lat_e7: i32,
    /// Longitude in degrees × 1e7.
    pub lon_e7: i32,
    /// Altitude in centimetres.
    pub alt_cm: i32,
}

impl GeoPos {
    /// A **monotonic planar proxy** for distance: the squared Euclidean
    /// distance in `(lat_e7, lon_e7)` space. Not metres, and it ignores the
    /// cos(latitude) longitude foreshortening — but it is monotonic in true
    /// distance over short ranges, needs no float/trig, and is enough to answer
    /// "which nexthop is geographically closer?" A `libm`-backed great-circle
    /// helper can layer on top later without changing this contract.
    pub fn planar_dist2(&self, other: &GeoPos) -> u64 {
        let dlat = (self.lat_e7 as i64) - (other.lat_e7 as i64);
        let dlon = (self.lon_e7 as i64) - (other.lon_e7 as i64);
        (dlat * dlat + dlon * dlon) as u64
    }
}

/// Node-scoped signals (this node, or a neighbor when learned via NDN data).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NodeSignals {
    /// Geographic position, if known.
    pub position: Option<GeoPos>,
    /// Heading in centidegrees (`0..=35999`), if known.
    pub heading_cdeg: Option<u16>,
    /// Ground speed in cm/s, if known.
    pub speed_cms: Option<u16>,
    /// Battery charge, percent (`0..=100`), if known.
    pub battery_pct: Option<u8>,
    /// Node wall-clock estimate, ms since epoch (0 = unknown).
    pub clock_ms: u64,
    /// Monotonic millisecond stamp of the last update (staleness).
    pub updated_ms: u32,
}

/// Read-only view of cross-layer signals, the platform-neutral **input
/// surface** a strategy decision reads. `F` is the engine's face-id type
/// (`FaceId` on native, `u8` on embedded), matching `ndn_fwd_core::Strategy<F>`.
///
/// Returns are by value (the structs are `Copy`), so a native interior-mutable
/// store can clone out from under its lock without lifetime entanglement.
pub trait SignalView<F: Copy + Eq> {
    /// Hop-local link signals for `face`, if any have been observed.
    fn link(&self, face: F) -> Option<LinkSignals>;
    /// This node's signals (defaults are returned when nothing is known).
    fn node(&self) -> NodeSignals;
    /// A neighbor's node signals reachable via `face`, if learned.
    fn neighbor(&self, face: F) -> Option<NodeSignals>;
}

/// Push side of a signal store. Sources call `set_*` to publish the latest
/// reading; strategies read through [`SignalView`]. `&self` (interior
/// mutability) so a source and the read path can share one store — native via
/// concurrent maps, embedded via a single-threaded cell.
pub trait SignalStore<F: Copy + Eq>: SignalView<F> {
    fn set_link(&self, face: F, signals: LinkSignals);
    fn set_node(&self, signals: NodeSignals);
    fn set_neighbor(&self, face: F, signals: NodeSignals);
}

/// A periodic source of cross-layer signals. The driver loop calls [`Self::poll`]
/// roughly every [`Self::interval`]; `now_ms` is a monotonic millisecond clock
/// used to stamp readings for staleness.
///
/// The trait lives here in the core taxonomy (not in the `ndn-signal-sources`
/// extension) so the **engine depends only on `ndn-signals-core`** — it accepts
/// `Box<dyn SignalSource>`s but never the concrete source framework. Concrete
/// sources (radio metrics, location, …) implement this in `ndn-signal-sources`.
pub trait SignalSource<F: Copy + Eq>: Send + 'static {
    /// Stable identifier (for logs / observability).
    fn name(&self) -> &str;
    /// Desired polling cadence. The driver may poll less often under load.
    fn interval(&self) -> core::time::Duration;
    /// Drain the backend and push the latest readings into `store`.
    fn poll(&mut self, store: &dyn SignalStore<F>, now_ms: u32);
}

/// The zero-cost "no signals" view — the sibling of `NoCs`. Strategies that
/// ignore signals are unaffected, and the engine passes `&NoSignals` by
/// default, keeping no-signal forwarders byte-identical.
pub struct NoSignals;

impl<F: Copy + Eq> SignalView<F> for NoSignals {
    #[inline]
    fn link(&self, _face: F) -> Option<LinkSignals> {
        None
    }
    #[inline]
    fn node(&self) -> NodeSignals {
        NodeSignals::default()
    }
    #[inline]
    fn neighbor(&self, _face: F) -> Option<NodeSignals> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_signals_is_empty() {
        let v = NoSignals;
        assert_eq!(SignalView::<u8>::link(&v, 1), None);
        assert_eq!(SignalView::<u8>::neighbor(&v, 1), None);
        assert_eq!(SignalView::<u8>::node(&v), NodeSignals::default());
    }

    #[test]
    fn planar_dist2_is_monotonic_and_zero_at_identity() {
        let a = GeoPos {
            lat_e7: 377_749_000,
            lon_e7: -1_224_194_000,
            alt_cm: 0,
        };
        let near = GeoPos {
            lat_e7: 377_749_100,
            lon_e7: -1_224_194_000,
            alt_cm: 0,
        };
        let far = GeoPos {
            lat_e7: 377_759_000,
            lon_e7: -1_224_194_000,
            alt_cm: 0,
        };
        assert_eq!(a.planar_dist2(&a), 0);
        assert!(a.planar_dist2(&near) < a.planar_dist2(&far));
    }

    #[test]
    fn link_signals_default_is_all_unknown() {
        let l = LinkSignals::default();
        assert!(l.rssi_dbm.is_none() && l.snr_db.is_none() && l.congestion.is_none());
        assert_eq!(l.updated_ms, 0);
    }

    #[test]
    fn congestion_orders_low_to_high() {
        assert!(CongestionLevel::Low < CongestionLevel::High);
    }
}
