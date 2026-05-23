//! Content Store freshness predicate.
//!
//! Two NDN forwarders, two clocks: the native CS stores an *absolute* stale-at
//! instant (a 64-bit monotonic ns deadline), while the constrained CS stores a
//! *relative* freshness period against a 32-bit ms clock that wraps (~49.7 days).
//! The underlying rule is the same — "is this Data still fresh at `now`?" — so
//! both forms live here, defined once, with the wrap correctness in one place.

/// Absolute-deadline freshness (native CS): fresh while `now` has not reached
/// the stored stale-at instant. Both arguments share one monotonic unit.
///
/// `stale_at == 0` is always stale; `stale_at == u64::MAX` is effectively
/// always fresh.
#[inline]
pub fn fresh_until(now: u64, stale_at: u64) -> bool {
    now < stale_at
}

/// Relative-period freshness (constrained CS): fresh while the time elapsed
/// since `stored` is below `period`. All three share one unit (e.g. ms).
///
/// Uses wrapping subtraction so a wrapping monotonic clock stays correct across
/// the wrap, *provided* the true age is below the clock's half-range. A
/// `period` of 0 means "never fresh" (a `MustBeFresh` consumer always misses),
/// matching NFD's treatment of a zero FreshnessPeriod.
#[inline]
pub fn fresh_for(now: u32, stored: u32, period: u32) -> bool {
    if period == 0 {
        return false;
    }
    now.wrapping_sub(stored) < period
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn until_deadline() {
        assert!(fresh_until(5, 10));
        assert!(!fresh_until(10, 10)); // at the deadline → stale
        assert!(!fresh_until(11, 10));
        assert!(!fresh_until(1, 0)); // stale_at 0 → always stale
        assert!(fresh_until(u64::MAX - 1, u64::MAX));
    }

    #[test]
    fn for_period() {
        assert!(fresh_for(50, 0, 100)); // age 50 < 100
        assert!(!fresh_for(100, 0, 100)); // age == period → stale
        assert!(!fresh_for(150, 0, 100));
        assert!(!fresh_for(0, 0, 0)); // zero period → never fresh
    }

    #[test]
    fn for_period_survives_clock_wrap() {
        // stored just before u32 wrap, now just after: true age is 10ms.
        let stored = u32::MAX - 4;
        let now = 5u32; // wrapped past 0
        assert!(fresh_for(now, stored, 100));
        assert!(!fresh_for(now, stored, 5)); // age 10 >= period 5
    }
}
