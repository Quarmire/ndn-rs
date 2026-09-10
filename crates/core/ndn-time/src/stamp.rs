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
    /// **A radio peripheral's own hardware edge capture**: the radio asserts a line when it
    /// has a frame, and an MCU capture peripheral (nRF DPPI/GPIOTE→TIMER, an STM32 input
    /// capture, an ESP MCPWM capture) latches a free-running counter on that edge with no
    /// software in the path.
    ///
    /// This is a **different physical event** from [`MacDone`](Self::MacDone), not a relabelling
    /// of it: nothing in the host's MAC pipeline is involved, and the error budget is set by the
    /// capture counter's tick rather than by a microsecond-resolution 802.11 TSF register. It
    /// sits between [`PhyPreamble`](Self::PhyPreamble) (which is the *air* event) and `MacDone`
    /// (which is a host-visible MAC event), because the radio's IRQ line fires after the frame
    /// is demodulated but the capture itself is pure hardware.
    ///
    /// Concretely on this fleet: the nRF54L15+LR2021 bridge captures at 16 MHz — a MEASURED
    /// 62.5 ns tick, crystal-disciplined to +16.7 ppm — and `RadioTime::time_sources` already
    /// advertises 63 ns for it. Stamping those frames `MacDone` clamped every one of them to
    /// 1 000 ns, 16× worse than the hardware, which quietly widened every offset estimate
    /// derived from them.
    RadioCapture,
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
            // 10 ns = one tick of a 100 MHz capture timer. The floor is a *conservative* bound
            // on what the latch can physically resolve, and this class of peripheral is limited
            // by its counter: no MCU capture block in this family clocks above ~100 MHz, so a
            // claim below 10 ns would be finer than the timer can count. It is deliberately NOT
            // 1 ns (the PhyPreamble/PIO figure) — that would make the floor stop guarding — and
            // deliberately NOT 1 000 ns (the TSFT figure), which is a property of 802.11's
            // microsecond TSF register and has nothing to do with a DPPI capture. A backend
            // still declares its own honest `precision_ns` (the LR2021 declares 63); this only
            // says how good a claim will be believed.
            LatchPoint::RadioCapture => 10,
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

    /// E2: a radio-peripheral hardware capture must publish the precision it MEASURED, not
    /// the 802.11 TSFT floor. The LR2021's 16 MHz DPPI capture is 62.5 ns (advertised as 63);
    /// under `MacDone` it was clamped to 1 000 ns — 16x pessimistic — and every offset estimate
    /// built on it inherited that width.
    #[test]
    fn a_radio_capture_stamp_keeps_its_measured_precision() {
        let s = LinkStamp::new(1_234, ClockDomainId(7), 63, LatchPoint::RadioCapture);
        assert_eq!(
            s.precision_ns, 63,
            "the measured 16 MHz tick survives the clamp"
        );
        // The same number under the old latch point is the 16x loss this variant exists to end.
        let old = LinkStamp::new(1_234, ClockDomainId(7), 63, LatchPoint::MacDone);
        assert_eq!(old.precision_ns, 1_000);
    }

    /// ...but the guard is still a guard: widening it must not let a backend claim a precision
    /// finer than a capture peripheral can count.
    #[test]
    fn radio_capture_is_still_clamped_below_its_floor() {
        let s = LinkStamp::new(1, ClockDomainId(7), 1, LatchPoint::RadioCapture);
        assert_eq!(s.precision_ns, 10);
        // Ordered strictly between the air-edge and MAC-register latches.
        assert!(
            LatchPoint::PhyPreamble.precision_floor_ns()
                < LatchPoint::RadioCapture.precision_floor_ns()
        );
        assert!(
            LatchPoint::RadioCapture.precision_floor_ns()
                < LatchPoint::MacDone.precision_floor_ns()
        );
    }

    #[test]
    fn domains_are_distinct_identities() {
        assert_ne!(ClockDomainId(1), ClockDomainId(2));
    }
}
