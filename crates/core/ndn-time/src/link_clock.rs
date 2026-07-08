//! Radio link-clock capability — the RX-stamp / read-now clocks a radio exposes.
//!
//! Distinct from [`ClockCapability`](crate::ClockCapability), which rates a *discipline* source
//! (GNSS/PTP/NTP/oscillator) for anchor election. A [`RadioTimeSource`] describes the *link
//! latch* clocks a radio's hardware exposes: the [`ClockDomainId`] its RX
//! [`LinkStamp`](crate::LinkStamp)s live in, their [`LatchPoint`]/precision, whether the counter
//! is monotonic, and whether it can be read on demand. This is the uniform surface `ndn-time`
//! reads across heterogeneous radios so it never special-cases a backend's timekeeping.
//!
//! The model is grounded in a concrete hardware finding: a Realtek monitor NIC exposes *two*
//! distinct link clocks — an always-on free-running per-frame RX timestamp (RXTSFL), and the
//! 802.11 port/beacon TSF which is readable on demand but gated on an active port and
//! periodically beacon-resynced (so not monotonic). A single "the TSF" abstraction is a bug
//! generator; a radio must enumerate its clocks with honest properties instead.

use crate::{ClockDomainId, LatchPoint};

/// The kind of link clock a [`RadioTimeSource`] exposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadioClockKind {
    /// A free-running per-frame RX timestamp the MAC/PHY latches on every received frame
    /// (e.g. Realtek RXTSFL). Always on and monotonic, but usually latch-only (no read-now).
    FreeRunRxStamp,
    /// The 802.11 port/beacon TSF: 64-bit microseconds, readable on demand, but gated on an
    /// active port and periodically beacon-resynced — so not monotonic while a BSS drives it.
    PortTsf,
    /// A PHY-preamble hardware edge (PIO/PPS class) — the tightest latch, if the board wires it.
    PhyPreamble,
    /// A host software timestamp taken when the transport delivered the frame — always
    /// available, coarsest (scheduler/USB/IRQ latency is inside it).
    HostRecv,
}

/// A single link clock a radio exposes for named-time, with honest properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadioTimeSource {
    /// Which kind of link clock this is.
    pub kind: RadioClockKind,
    /// The domain RX stamps / read-now values from this clock are keyed on. Clocks from
    /// *different* physical counters MUST use different domains (they are not comparable until
    /// `ndn-time` learns a cross-domain mapping).
    pub domain: ClockDomainId,
    /// Where in the pipeline this clock latches.
    pub latch: LatchPoint,
    /// Half-width uncertainty of a stamp from this clock, nanoseconds.
    pub precision_ns: u32,
    /// Nominal tick period, nanoseconds (e.g. 1000 for a 1 MHz microsecond TSF).
    pub tick_ns: u32,
    /// The counter advances continuously with no resync/reset surprises, so two stamps from it
    /// may be subtracted directly. A beacon-resynced TSF is **not** monotonic.
    pub monotonic: bool,
    /// The current value can be read on demand (a "read now"), not only latched per received
    /// frame — required to compute a frame's age against the same clock.
    pub read_now: bool,
}

impl RadioTimeSource {
    /// A free-running per-frame RX-stamp clock: always-on, monotonic, latch-only (no read-now) —
    /// the common case for a monitor-mode NIC (e.g. Realtek RXTSFL, `tick_ns = 1000`).
    pub const fn free_run_rx_stamp(domain: ClockDomainId, tick_ns: u32) -> Self {
        Self {
            kind: RadioClockKind::FreeRunRxStamp,
            domain,
            latch: LatchPoint::MacDone,
            precision_ns: LatchPoint::MacDone.precision_floor_ns(),
            tick_ns,
            monotonic: true,
            read_now: false,
        }
    }

    /// The 802.11 port/beacon TSF: readable on demand (`read_now`), 1 microsecond ticks, but
    /// gated + beacon-resynced, so `monotonic = false`. Give it its **own** domain, distinct
    /// from the free-run RX-stamp clock (they are different physical counters).
    pub const fn port_tsf(domain: ClockDomainId) -> Self {
        Self {
            kind: RadioClockKind::PortTsf,
            domain,
            latch: LatchPoint::MacDone,
            precision_ns: LatchPoint::MacDone.precision_floor_ns(),
            tick_ns: 1_000,
            monotonic: false,
            read_now: true,
        }
    }
}
