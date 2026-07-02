//! Link-layer timestamps and clock domains (the bearer-agnostic "Cut 1").
//!
//! These types live here, not in `ndn-frame-io`, for one reason: `ndn-time` is
//! `no_std` and `ndn-frame-io` is `std`+tokio, so the only valid dependency
//! direction is `ndn-frame-io → ndn-time`. `ndn-frame-io`'s `CapturedFrame`
//! gains an `Option<LinkStamp>` by depending on this crate; the stamp *type* is
//! defined here because the generic combiner also consumes it. See ADR 0007.

/// Identifies *which* counter a raw timestamp was read from.
///
/// This is the single most load-bearing field in a [`LinkStamp`]: a TSF
/// counter, a PTP hardware clock (PHC), `CLOCK_MONOTONIC`, and a PIO cycle
/// counter are **different timelines**. A raw value without a domain is a bug
/// generator — you cannot subtract two stamps from different domains until a
/// cross-domain mapping (offset + rate, learned from paired samples) relates
/// them. `ndn-time` owns that mapping; this newtype is the identity it keys on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockDomainId(pub u32);

/// Where in the receive/transmit pipeline a stamp was latched. Earlier latch
/// points remove more software-induced error, so this is a precision hint the
/// generic core reads (it never special-cases a specific backend).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LatchPoint {
    /// At the PHY preamble — earliest, best (e.g. a deterministic PIO edge).
    PhyPreamble,
    /// When the MAC finished the frame (e.g. 802.11 TSFT, ~1 µs class).
    MacDone,
    /// In the host after the transport delivered it (software stamp; the
    /// scheduler/USB/IRQ latency is *inside* this stamp, so it is the coarsest).
    HostRecv,
    /// A scheduled transmit instant (a promise the hardware will emit at this
    /// time), for `TxDiscipline::ScheduledAt` backends.
    ScheduledTx,
}

impl LatchPoint {
    /// A conservative floor on the precision achievable at this latch point,
    /// nanoseconds. A backend may advertise *tighter* than this via
    /// [`LinkStamp::precision_ns`]; it should not advertise looser without
    /// reason. Used to sanity-clamp an over-optimistic backend.
    pub const fn precision_floor_ns(self) -> u32 {
        match self {
            LatchPoint::PhyPreamble => 1,
            LatchPoint::MacDone => 1_000,
            LatchPoint::HostRecv => 1_000_000,
            LatchPoint::ScheduledTx => 1,
        }
    }
}

/// A hardware/link timestamp attached to a captured or transmitted frame.
///
/// Filled per backend: TSFT on monitor-wifi ([`LatchPoint::MacDone`], ~1 µs),
/// `SO_TIMESTAMPING` on Ethernet, an on-chip counter on ESP32, cycle-exact PIO
/// stamps on an optical face (ns-class, better than TSFT), or a plain software
/// stamp with an honestly fat [`Self::precision_ns`] on BLE. The protocol never
/// names the mechanism — it reads `precision_ns` and `domain`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkStamp {
    /// The counter value exactly as latched, in that counter's own units/epoch.
    pub raw: u64,
    /// Which counter `raw` came from. Stamps are only comparable within a
    /// domain (or across domains through a learned mapping).
    pub domain: ClockDomainId,
    /// Honest half-width uncertainty of this stamp, nanoseconds.
    pub precision_ns: u32,
    /// Where in the pipeline it was latched.
    pub latch: LatchPoint,
}

impl LinkStamp {
    /// Construct a stamp, clamping `precision_ns` up to the latch point's floor
    /// so a backend cannot accidentally claim finer precision than its latch
    /// physically allows.
    pub fn new(raw: u64, domain: ClockDomainId, precision_ns: u32, latch: LatchPoint) -> Self {
        Self {
            raw,
            domain,
            precision_ns: precision_ns.max(latch.precision_floor_ns()),
            latch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_is_clamped_to_latch_floor() {
        // A software HostRecv stamp cannot claim 1 ns.
        let s = LinkStamp::new(42, ClockDomainId(1), 1, LatchPoint::HostRecv);
        assert_eq!(s.precision_ns, 1_000_000);
    }

    #[test]
    fn tight_backend_keeps_its_number() {
        // A PIO PhyPreamble stamp claiming 3 ns is honored (above the 1 ns floor).
        let s = LinkStamp::new(42, ClockDomainId(2), 3, LatchPoint::PhyPreamble);
        assert_eq!(s.precision_ns, 3);
    }

    #[test]
    fn domains_are_distinct_identities() {
        assert_ne!(ClockDomainId(1), ClockDomainId(2));
    }
}
