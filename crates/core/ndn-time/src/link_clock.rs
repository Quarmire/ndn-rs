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
//!
//! # Two independent axes: where it LATCHES and what it RUNS ON
//!
//! [`RadioClockKind`] and [`LatchPoint`] answer *where in the pipeline the counter is sampled*.
//! [`ClockReference`] answers the other question — *what the counter is counting*. They are
//! independent, and a radio can be excellent on one and useless on the other.
//!
//! ☠ MEASURED, and the reason this axis exists at all. Two receivers stamping the SAME frames
//! from one transmitter, paired by payload, offset and drift removed by least squares (so the
//! transmitter's clock and any fixed rate error cancel, and the residual is the common-view error):
//!
//! | receivers | reference | drift | residual sd | residual vs fit span |
//! |---|---|---|---|---|
//! | 2 x LR2021 (nRF54L15, 16 MHz capture) | HFXO crystal | 1.2-1.6 ppm | 0.81 / 1.55 / 1.86 us | **FLAT** (1.11 -> 1.55 us from 1.4 s to 10.2 s) |
//! | 2 x Waveshare SX1262 (GD32, TIM3 capture) | 8 MHz internal RC | ~ -3100 ppm | 10.5-20.4 us at 1.4 s | **GROWS** (16 -> 130 us) |
//!
//! Both latch in hardware, per frame, on a free-running counter. The latch point does not separate
//! them; the reference does — and the two failures are different in kind, not degree. The flat one
//! is per-frame jitter, which `precision_ns` already describes. The growing one is *reference
//! wander*, which nothing on this type could express until [`ClockReference`] existed. A rate fitted
//! against a crystal stays fitted; a rate fitted against an RC oscillator does not.

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

/// **What a link clock's counter is DERIVED FROM** — the oscillator that sets its rate, as
/// distinct from [`RadioClockKind`], which says where the counter is *latched*.
///
/// Declare the variant the evidence supports, and nothing more. What counts as evidence:
///
/// * [`Crystal`](Self::Crystal) — the driver reads or writes a crystal trim (an efuse crystal cap,
///   an `XO_CTRL` load-capacitance pair), the part's clock tree is gated on a crystal-ready bit,
///   the firmware in this tree *selects* an external crystal, **or** the counter's rate has been
///   MEASURED against a host or peer clock and landed in crystal territory (tens of ppm).
///   That last one is a real inference, not a guess, and this tree's own measurements calibrate it:
///   an RC reference is percent-class — the LR2021's measured **+2253 ppm** and the Waveshare's
///   **~-3100 ppm** — so a counter measured at -10 ppm is not sitting on one.
/// * [`RcOscillator`](Self::RcOscillator) — the part is KNOWN to run on an on-chip RC (its firmware
///   never switches away from it, or it says so over the wire).
/// * [`Unknown`](Self::Unknown) — everything else, including "it is obviously a Wi-Fi part so it
///   must have a crystal". Plausible is not measured, and an unknown reference earns nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockReferenceKind {
    /// A quartz reference: a bare crystal, an HFXO, a TCXO, or a PLL locked to one. Tens of ppm of
    /// rate error at worst, and — the property that matters — it STAYS PUT, so a fitted rate stays
    /// fitted for as long as anyone is fitting.
    Crystal,
    /// An on-chip RC oscillator. Percent-class rate error that WANDERS with temperature and supply,
    /// so a fitted rate does not stay fitted and a common-view residual grows with the fit span.
    /// Resolution is unaffected — a 1 us tick is still a 1 us tick — which is exactly why this
    /// cannot be inferred from `precision_ns` or from the latch point.
    RcOscillator,
    /// The host operating system's own clock (what a [`RadioClockKind::HostRecv`] stamp counts).
    /// Quartz-referenced and usually externally disciplined, so its *rate* is not the problem —
    /// but this crate measures nothing about it, and a host-recv stamp is refused a common view on
    /// the LATCH axis regardless (scheduler/USB/IRQ jitter swamps the inter-receiver offset).
    HostOs,
    /// **Nobody has established what this counter runs on.** The honest default, and deliberately
    /// the one a bare constructor gives you: a reference nobody has witnessed must not be able to
    /// grant a capability by being forgotten about.
    Unknown,
}

impl ClockReferenceKind {
    /// Whether a frequency offset fitted against this reference STAYS fitted — the property a
    /// common view needs from the counter, and the one `precision_ns` (a per-stamp half-width)
    /// cannot express.
    ///
    /// [`Unknown`](Self::Unknown) is `false`: not "probably fine", not "assume the common case".
    pub const fn holds_rate(self) -> bool {
        matches!(self, Self::Crystal | Self::HostOs)
    }
}

/// What a [`RateMeasurement`] was taken **against** — three different claims that are easy to
/// confuse and mean different things to a consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateWitness {
    /// The host's own monotonic clock: bounds the counter's *absolute* rate error, to whatever the
    /// host clock is worth (fine for separating tens of ppm from thousands, useless below ~1 ppm).
    HostClock,
    /// A second unit of the same part: bounds the *relative* rate error, which is precisely what a
    /// common view between two such units has to remove. Says nothing about either unit's absolute
    /// rate — two radios can agree perfectly and both be 50 ppm off UTC.
    PeerUnit,
    /// The node measured and reported its own accuracy over the wire. Believe it exactly as far as
    /// the node's own method deserves, and prefer a figure taken on this side where one exists.
    NodeReported,
}

/// A MEASURED frequency figure for a link clock's reference.
///
/// **Populate this ONLY from a measurement recorded in this tree, with the citation in the comment
/// next to it.** A datasheet tolerance is a guess; a guess written into a struct a discipline loop
/// reads is how an unmeasured correction gets folded into a number. Where a part's rate has never
/// been measured, leave [`ClockReference::measured`] as `None` — "not measured" is a fact worth
/// publishing, and a consumer can tell it from "measured, and it is bad".
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateMeasurement {
    /// The fractional-frequency error the cited measurement produced, parts per million, signed in
    /// that measurement's own convention.
    pub ppm: f32,
    /// The observation span the figure was taken over, seconds. `0.0` means the cited measurement
    /// does not record one — which is itself informative: a ppm without a span bounds a *rate*, and
    /// only a ppm across several spans bounds *wander*.
    pub span_s: f32,
    /// What the counter was measured against.
    pub witness: RateWitness,
}

impl RateMeasurement {
    /// A measured rate figure. `span_s = 0.0` when the cited run does not record a span.
    pub const fn new(ppm: f32, span_s: f32, witness: RateWitness) -> Self {
        Self {
            ppm,
            span_s,
            witness,
        }
    }
}

/// What a link clock's counter runs on: its [`kind`](Self::kind), plus the MEASURED rate figure for
/// it if anyone has taken one.
///
/// Kept as its own type rather than a single "quality" scalar because the two halves answer
/// different questions and degrade differently. `kind` decides whether a fitted rate holds (and so
/// whether the clock may source a common view at all); `measured` is the evidence a reader can
/// check the `kind` against, and the number a discipline loop can size its re-measure cadence from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClockReference {
    /// What the counter is derived from.
    pub kind: ClockReferenceKind,
    /// The MEASURED rate figure for this reference, or `None` when nobody has measured it. Never a
    /// datasheet number.
    pub measured: Option<RateMeasurement>,
}

impl ClockReference {
    /// **Nobody has established what this counter runs on.** The safe default: it holds no rate, so
    /// it earns no common view, and a backend that simply has not looked yet says so by saying
    /// nothing.
    pub const fn unknown() -> Self {
        Self {
            kind: ClockReferenceKind::Unknown,
            measured: None,
        }
    }

    /// A quartz reference. See [`ClockReferenceKind::Crystal`] for what has to be true first.
    pub const fn crystal() -> Self {
        Self {
            kind: ClockReferenceKind::Crystal,
            measured: None,
        }
    }

    /// An on-chip RC oscillator, KNOWN to be one.
    pub const fn rc_oscillator() -> Self {
        Self {
            kind: ClockReferenceKind::RcOscillator,
            measured: None,
        }
    }

    /// The host OS clock — what a [`RadioTimeSource::host_recv`] source counts.
    pub const fn host_os() -> Self {
        Self {
            kind: ClockReferenceKind::HostOs,
            measured: None,
        }
    }

    /// Attach the MEASURED rate figure for this reference. Cite the run in the comment beside it.
    pub const fn measured(mut self, m: RateMeasurement) -> Self {
        self.measured = Some(m);
        self
    }

    /// Whether a rate fitted against this reference stays fitted — see
    /// [`ClockReferenceKind::holds_rate`]. This is the reference half of the common-view test; the
    /// latch half is [`RadioClockKind::FreeRunRxStamp`].
    pub const fn holds_rate(&self) -> bool {
        self.kind.holds_rate()
    }
}

/// A single link clock a radio exposes for named-time, with honest properties.
///
/// ⚠ `PartialEq` but **not** `Eq`: [`reference`](Self::reference) carries a measured ppm figure,
/// and a float has no total equality. Nothing compares these as map keys.
#[derive(Clone, Copy, Debug, PartialEq)]
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
    /// **What this counter is derived from** — the second axis, orthogonal to `kind`/`latch`.
    ///
    /// The constructors default this to [`ClockReference::unknown`], which is the safe direction: a
    /// backend that has not looked at its reference cannot accidentally claim one. State a known
    /// reference with [`with_reference`](Self::with_reference), and put the evidence in the comment
    /// beside the call.
    pub reference: ClockReference,
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
            // Unknown until a backend says otherwise: latching in hardware says nothing about the
            // oscillator underneath, and this constructor cannot know.
            reference: ClockReference::unknown(),
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
            reference: ClockReference::unknown(),
        }
    }

    /// A host software clock (nanosecond, monotonic, always readable) used when the radio has no
    /// hardware timestamp and the frame is stamped when the transport delivered it — the coarsest
    /// latch, but honestly labelled. The domain is per host process (shared by all host-stamped
    /// backends on it), not per device.
    pub const fn host_recv(domain: ClockDomainId) -> Self {
        Self {
            kind: RadioClockKind::HostRecv,
            domain,
            latch: LatchPoint::HostRecv,
            precision_ns: LatchPoint::HostRecv.precision_floor_ns(),
            tick_ns: 1,
            monotonic: true,
            read_now: true,
            // This one IS known: it is the host's own clock by construction.
            reference: ClockReference::host_os(),
        }
    }

    /// State what this clock's counter is derived from — see [`ClockReference`].
    ///
    /// Separate from the constructors on purpose. The default is [`ClockReference::unknown`], so
    /// forgetting to call this WITHHOLDS a capability rather than granting one, and every backend
    /// that does claim a reference has a call site to hang the evidence off.
    pub const fn with_reference(mut self, reference: ClockReference) -> Self {
        self.reference = reference;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClockDomainId;

    /// The whole point of the default: a backend that has not looked at its reference must not be
    /// able to claim one by omission. Both hardware constructors start at `Unknown`, and `Unknown`
    /// holds no rate.
    #[test]
    fn a_bare_hardware_stamp_claims_no_reference() {
        let s = RadioTimeSource::free_run_rx_stamp(ClockDomainId(1), 1_000);
        assert_eq!(s.reference.kind, ClockReferenceKind::Unknown);
        assert!(!s.reference.holds_rate());
        assert!(
            !RadioTimeSource::port_tsf(ClockDomainId(2))
                .reference
                .holds_rate()
        );
    }

    /// The host clock is the one reference this crate knows by construction — and it is still not a
    /// common-view source, because it fails on the LATCH axis, not this one.
    #[test]
    fn the_host_clock_knows_its_own_reference() {
        let s = RadioTimeSource::host_recv(ClockDomainId(0));
        assert_eq!(s.reference.kind, ClockReferenceKind::HostOs);
        assert_eq!(s.kind, RadioClockKind::HostRecv);
    }

    /// An RC reference holds no rate however tight its latch is: the Waveshare stamps 95/95 frames
    /// in silicon at 1 us and still cannot hold a common view.
    #[test]
    fn an_rc_reference_holds_no_rate_however_good_the_latch() {
        let rc = ClockReference::rc_oscillator().measured(RateMeasurement::new(
            -3100.0,
            0.0,
            RateWitness::PeerUnit,
        ));
        assert!(!rc.holds_rate());
        assert!(ClockReference::crystal().holds_rate());
        let s = RadioTimeSource::free_run_rx_stamp(ClockDomainId(3), 1_000).with_reference(rc);
        assert_eq!(s.kind, RadioClockKind::FreeRunRxStamp);
        assert_eq!(s.latch, LatchPoint::MacDone);
        assert!(!s.reference.holds_rate());
    }

    /// `None` ("nobody measured it") and `Some` ("measured, and here it is") are different facts and
    /// the type keeps them apart.
    #[test]
    fn not_measured_is_distinguishable_from_measured() {
        assert_eq!(ClockReference::crystal().measured, None);
        let m = RateMeasurement::new(-35.0, 20.06, RateWitness::HostClock);
        assert_eq!(ClockReference::crystal().measured(m).measured, Some(m));
    }
}
