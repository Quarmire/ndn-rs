//! Anchor election — clock quality as the CCLF election weight.
//!
//! The best local clock self-selects to beacon `/<scope>/time/anchor`, using
//! CCLF's forwarder-election mechanism *unchanged* — only the **weight**
//! differs. Content-CCLF weights a node by content-connectivity; named-time
//! weights it by **clock quality**. Everything else (the suppression timer
//! `t = T/w`, the `[0.5t, 1.5t]` jitter, density thinning, and the overhear-
//! cancel seam) is `ndn-strategy-cclf`'s `cclf_elect`, reused verbatim.
//!
//! This module is the adapting piece: [`anchor_weight`] maps a clock's
//! capability and current uncertainty to a weight in `[0, 1]`. Feed that weight
//! to `cclf_elect` as its `ccs` argument and the tightest clock gets the
//! highest weight → the shortest timer → it beacons first; worse clocks overhear
//! and cancel. Because `ndn-time` is `spec`/`no_std` and `cclf_elect` lives in
//! the `extension`-scoped `ndn-strategy-cclf`, the (trivial) call site lives
//! there, not here:
//!
//! ```rust,ignore
//! let w = ndn_time::election::anchor_weight(&cap, uncertainty_ns, stratum, &params);
//! match cclf_elect(w, None, neighbor_count, &cclf_params, &mut rng) {
//!     CclfDecision::ForwardAfter { delay_us } => schedule_anchor_beacon(delay_us),
//!     CclfDecision::Suppress => {} // a denser, better-clocked neighbourhood
//! }
//! ```
//!
//! **Failover is the same mechanism.** A clock that loses its reference (GPS
//! drops, holdover grows) widens its uncertainty; its weight falls, its timer
//! lengthens, and it yields to the next-best — there is no separate failover
//! path. And note the boundary: election is a *liveness/efficiency* mechanism,
//! **not** a Sybil defence — a flood of fabricated candidates is the authority
//! gate's problem (the LVS time schema), not the election's.

use crate::capability::ClockCapability;

/// Tunables for the clock-quality weight.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ElectionParams {
    /// The uncertainty (ns) at which the uncertainty factor equals `0.5`.
    /// Clocks tighter than this score toward 1, looser toward 0 — it sets where
    /// the weight pivots between "trusted anchor" and "poor candidate".
    pub uncertainty_ref_ns: u64,
    /// How much traceability rank boosts the weight, clamped to `[0, 1]`.
    /// `0.0` = uncertainty only; `0.25` = up to a 25 % boost for a UTC/TAI clock
    /// over an untraceable one at equal uncertainty. Kept small so uncertainty
    /// dominates: a *local, tight* GPS must out-elect a *WAN, loose* UTC NTP.
    pub trace_boost: f32,
}

impl Default for ElectionParams {
    fn default() -> Self {
        Self {
            // 100 µs pivot: tighter than a good wireless common-view fix, looser
            // than a WAN NTP uplink, so the two land on opposite sides.
            uncertainty_ref_ns: 100_000,
            trace_boost: 0.25,
        }
    }
}

/// The CCLF election weight for a clock — a value in `[0, 1]`, **monotone in
/// 1/uncertainty** (tighter is higher), boosted by **traceability rank**, and
/// **penalised by `stratum`** (hops from a reference; a source with its own
/// reference is stratum 0).
///
/// The uncertainty factor is a rational, log-free map `ref / (ref + u)`: `1` at
/// zero uncertainty, `0.5` at the reference, decaying toward `0` — chosen so the
/// crate stays `no_std` with no `log`/`exp`.
pub fn anchor_weight(
    cap: &ClockCapability,
    uncertainty_ns: u64,
    stratum: u8,
    params: &ElectionParams,
) -> f32 {
    let refn = params.uncertainty_ref_ns as f32;
    // Monotone-decreasing in uncertainty; in (0, 1].
    let unc = refn / (refn + uncertainty_ns as f32);
    // Traceability in [0, 1] (Utc/Tai → 1.0, Gnss → 0.75, Ensemble → 0.25,
    // None → 0.0), applied as a bounded boost so uncertainty stays dominant.
    let trace = cap.traceable.rank() as f32 / 4.0;
    let boost = params.trace_boost.clamp(0.0, 1.0);
    let base = unc * (1.0 - boost + boost * trace);
    // Stratum penalty: a peer-derived clock N hops from a reference is worth
    // 1/(1+N) of the same quality at the source.
    (base / (1.0 + stratum as f32)).clamp(0.0, 1.0)
}

/// Whether clock `a` out-elects clock `b` as anchor: strictly higher weight
/// wins; an exact tie is broken by the lower `node_id` (deterministic, so two
/// nodes never both believe they won). This is the *ordering* the suppression
/// timer realises; use it directly when comparing known candidates rather than
/// racing timers.
pub fn out_elects(a: (f32, u64), b: (f32, u64)) -> bool {
    let (wa, ida) = a;
    let (wb, idb) = b;
    if wa != wb { wa > wb } else { ida < idb }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::ClockCapability;

    fn p() -> ElectionParams {
        ElectionParams::default()
    }

    #[test]
    fn tighter_clock_gets_higher_weight() {
        let cap = ClockCapability::oscillator_tcxo();
        let tight = anchor_weight(&cap, 1_000, 0, &p());
        let loose = anchor_weight(&cap, 1_000_000, 0, &p());
        assert!(tight > loose, "monotone in 1/uncertainty");
    }

    #[test]
    fn local_gps_out_elects_wan_ntp() {
        // A local GPS (tens of ns, GNSS-traceable) must beat a WAN NTP uplink
        // (milliseconds, UTC-traceable) — the design's headline property.
        let gps = anchor_weight(&ClockCapability::gnss_disciplined(), 30, 0, &p());
        let ntp = anchor_weight(&ClockCapability::ntp_uplink(), 5_000_000, 0, &p());
        assert!(gps > ntp, "gps {gps} must out-elect ntp {ntp}");
        assert!(out_elects((gps, 1), (ntp, 2)));
    }

    #[test]
    fn failover_is_election() {
        // The same GPS clock that loses its fix (uncertainty grows along the
        // holdover curve) yields: its weight falls, so it no longer out-elects
        // the value it had while disciplined.
        let cap = ClockCapability::gnss_disciplined();
        let disciplined = anchor_weight(&cap, 30, 0, &p());
        let holdover = anchor_weight(&cap, 10_000_000, 0, &p()); // 10 ms later
        assert!(
            holdover < disciplined,
            "a clock that loses its reference yields"
        );
    }

    #[test]
    fn stratum_penalises_derived_clocks() {
        let cap = ClockCapability::oscillator_tcxo();
        let at_source = anchor_weight(&cap, 10_000, 0, &p());
        let three_hops = anchor_weight(&cap, 10_000, 3, &p());
        assert!(three_hops < at_source);
    }

    #[test]
    fn traceability_breaks_uncertainty_ties() {
        // Two clocks, equal uncertainty and stratum: the more-traceable one wins.
        let utc = anchor_weight(&ClockCapability::ntp_uplink(), 50_000, 0, &p());
        let none = anchor_weight(&ClockCapability::esp32_rc(), 50_000, 0, &p());
        assert!(utc > none, "traceability boost breaks the tie");
    }

    #[test]
    fn out_elects_breaks_exact_ties_by_id() {
        assert!(out_elects((0.5, 1), (0.5, 2)), "lower id wins an exact tie");
        assert!(!out_elects((0.5, 2), (0.5, 1)));
        assert!(out_elects((0.6, 9), (0.5, 1)), "higher weight always wins");
    }
}
