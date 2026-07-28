//! A disciplined single-radio hardware clock, fed from [`LinkStamp`]s.
//!
//! This is the **degenerate, single-node case** of the full [`crate::discipline`] servo: it
//! disciplines a local *hardware*-domain clock from the RX hardware timestamps a radio already
//! latches (e.g. the Realtek free-run RX TSF, `RXTSFL`), using the host monotonic clock only for
//! continuity *between* frames. Every hardware stamp re-phases the offset to the µs-precise
//! hardware value; until the first stamp — and for software-timestamped backends (loopback, coarse
//! LoRa) that never populate a stamp — it falls through to the plain host clock, so nothing
//! regresses.
//!
//! It lives here, next to [`LinkStamp`] and [`crate::discipline`], deliberately: the disciplined
//! hardware clock is a **shared substrate**, not a property of any one face. NAN's DiscoveryWindow
//! was historically the only consumer (its runtime carried a private copy of this logic); the
//! named-radio time-slice / FHSS scheduler, cognition, and the cross-node common-view pool are the
//! other consumers this generalization unblocks. Feed it `CapturedFrame.stamp`; read `now()`.
//!
//! For cross-node agreement (two receivers of one shared beacon → an inter-receiver offset) and for
//! fusing multiple wall/relative sources, graduate to [`crate::discipline::Discipline`] +
//! [`crate::domain_map::DomainMap`]; this type deliberately stays single-domain and single-radio.

use crate::stamp::{ClockDomainId, LinkStamp};

/// The wrap period of a Realtek free-run RX TSF (`RXTSFL`): a 32-bit **microsecond** counter that
/// rolls over about every 71 minutes. We unwrap it against the continuous host clock so a consumer's
/// 64-bit modular TSF arithmetic stays consistent across the wrap.
pub const RXTSF_PERIOD_US: i64 = 1 << 32;

/// A disciplined hardware clock for a single radio's stamp domain.
///
/// `hw_now = host_now + offset`, where `offset` is re-phased to the hardware counter on every stamp.
/// `None` offset ⇒ no hardware stamp seen yet ⇒ the host clock passes through unchanged.
#[derive(Clone, Debug)]
pub struct RadioHwClock {
    /// `hw_now = host_now + offset` (µs). `None` until the first hardware stamp arrives.
    offset: Option<i64>,
    /// The domain of the stamps this clock disciplines on. Locked to the first stamp's domain;
    /// stamps from any other domain are ignored (multi-domain fusion is [`DomainMap`]'s job, not
    /// this single-radio clock's — mixing them here would corrupt the offset).
    ///
    /// [`DomainMap`]: crate::domain_map::DomainMap
    domain: Option<ClockDomainId>,
    /// Counter wrap period in the counter's own units (µs for Realtek). `0` ⇒ a full-width 64-bit
    /// counter that never wraps in practice (no unwrapping applied).
    period: i64,
}

impl Default for RadioHwClock {
    /// The Realtek free-run RX TSF default (32-bit µs). Use [`RadioHwClock::with_period`] for a
    /// wider counter.
    fn default() -> Self {
        Self { offset: None, domain: None, period: RXTSF_PERIOD_US }
    }
}

impl RadioHwClock {
    /// A clock for the Realtek free-run RX TSF (`RXTSFL`, 32-bit µs). Same as [`Default`].
    pub fn realtek() -> Self {
        Self::default()
    }

    /// A clock for a counter with an explicit wrap `period` (counter units). Pass `0` for a
    /// full-width 64-bit counter that is not unwrapped.
    pub fn with_period(period: u64) -> Self {
        Self { offset: None, domain: None, period: period as i64 }
    }

    /// Re-phase from a hardware `stamp` captured at `host_now` (µs); returns the disciplined hardware
    /// time. The first stamp locks the domain; later stamps from a *different* domain are ignored and
    /// this returns the extrapolated `now()` instead of re-phasing on foreign counter units.
    pub fn on_stamp(&mut self, stamp: &LinkStamp, host_now: u64) -> u64 {
        match self.domain {
            None => self.domain = Some(stamp.domain),
            Some(d) if d == stamp.domain => {}
            Some(_) => return self.now(host_now), // foreign domain: don't corrupt the offset
        }
        let phase = self.phase(stamp.raw, host_now);
        self.offset = Some(phase);
        (host_now as i64 + phase) as u64
    }

    /// Convenience for callers holding a bare counter value in this clock's (already-locked or
    /// default) domain — e.g. tests, or a backend that hands out raw `RXTSFL` without a full stamp.
    pub fn on_raw(&mut self, raw: u64, host_now: u64) -> u64 {
        let phase = self.phase(raw, host_now);
        self.offset = Some(phase);
        (host_now as i64 + phase) as u64
    }

    /// Hardware time now (µs), extrapolated from the last stamp via the host clock. Falls through to
    /// `host_now` until the first stamp — so an un-stamped backend rides the software clock unchanged.
    pub fn now(&self, host_now: u64) -> u64 {
        match self.offset {
            Some(o) => (host_now as i64 + o) as u64,
            None => host_now,
        }
    }

    /// Map a hardware-domain instant back to the host-elapsed domain (for a host-clock sleep/timer).
    /// Inverse of the extrapolation in [`now`](Self::now).
    pub fn to_host(&self, hw_usec: u64) -> u64 {
        match self.offset {
            Some(o) => (hw_usec as i64 - o) as u64,
            None => hw_usec,
        }
    }

    /// Whether the clock has locked onto hardware time yet (`false` ⇒ still on the software fallback).
    pub fn is_disciplined(&self) -> bool {
        self.offset.is_some()
    }

    /// The current `hw = host + offset` offset in µs, if disciplined.
    pub fn offset_us(&self) -> Option<i64> {
        self.offset
    }

    /// The domain this clock has locked onto, if any stamp has been seen.
    pub fn domain(&self) -> Option<ClockDomainId> {
        self.domain
    }

    /// The centered phase `(raw - host_now) mod period`, in `[-period/2, period/2)`, so the unwrapped
    /// offset stays near zero across a counter wrap. With `period == 0` the counter is treated as
    /// full-width and the raw difference is used directly.
    fn phase(&self, raw: u64, host_now: u64) -> i64 {
        let diff = (raw as i64).wrapping_sub(host_now as i64);
        if self.period == 0 {
            return diff;
        }
        let mut phase = diff.rem_euclid(self.period);
        if phase > self.period / 2 {
            phase -= self.period;
        }
        phase
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stamp::LatchPoint;

    fn stamp(raw: u64, domain: u32) -> LinkStamp {
        LinkStamp { raw, domain: ClockDomainId(domain), precision_ns: 1000, latch: LatchPoint::MacDone }
    }

    #[test]
    fn software_fallback_until_first_stamp() {
        let c = RadioHwClock::realtek();
        assert!(!c.is_disciplined());
        assert_eq!(c.now(12_345), 12_345); // passes host time through
    }

    #[test]
    fn disciplines_and_extrapolates() {
        let mut c = RadioHwClock::realtek();
        // hardware counter is 1_000_000 µs ahead of the host clock at host_now = 500.
        let hw = c.on_stamp(&stamp(1_000_500, 1), 500);
        assert_eq!(hw, 1_000_500);
        assert!(c.is_disciplined());
        assert_eq!(c.offset_us(), Some(1_000_000));
        // later, host advanced to 1500 with no new stamp → extrapolated hw time.
        assert_eq!(c.now(1_500), 1_001_500);
        // round-trips back to host domain for a timer.
        assert_eq!(c.to_host(1_001_500), 1_500);
    }

    #[test]
    fn unwraps_across_the_32bit_boundary() {
        let mut c = RadioHwClock::realtek();
        // host clock far past the 32-bit counter's range; counter has wrapped many times.
        let host = 5 * RXTSF_PERIOD_US as u64 + 700;
        let raw = 200u64; // small counter value = just wrapped
        let hw = c.on_stamp(&stamp(raw, 1), host);
        // disciplined hw time stays near the host clock (small negative offset), not 5 wraps off.
        let off = c.offset_us().unwrap();
        assert!(off.abs() < RXTSF_PERIOD_US / 2, "offset {off} should be centered, not a full wrap");
        assert_eq!(hw, (host as i64 + off) as u64);
    }

    #[test]
    fn foreign_domain_is_ignored() {
        let mut c = RadioHwClock::realtek();
        c.on_stamp(&stamp(1_000_500, 1), 500);
        let off = c.offset_us();
        // a stamp from a different radio's counter must not re-phase this single-radio clock.
        c.on_stamp(&stamp(42, 2), 600);
        assert_eq!(c.offset_us(), off, "foreign-domain stamp corrupted the offset");
        assert_eq!(c.domain(), Some(ClockDomainId(1)));
    }
}
