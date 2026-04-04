//! Monotonic clock abstraction for PIT expiry.
//!
//! Embedded targets don't have `std::time::Instant`. The forwarder accepts
//! any type implementing [`Clock`] so the application can supply whatever
//! timer peripheral is available (SysTick, TIM2, embassy_time, etc.).

/// Monotonic millisecond counter.
///
/// Implement this trait for your MCU's timer peripheral, then pass the
/// implementor to [`Forwarder::new`](crate::Forwarder::new).
///
/// The counter is allowed to wrap (u32 overflows after ~49 days at 1 kHz).
/// The forwarder uses wrapping subtraction for expiry checks, so short
/// Interest lifetimes (up to ~24 days) work correctly across wrap-around.
pub trait Clock {
    /// Returns milliseconds elapsed since an arbitrary epoch.
    fn now_ms(&self) -> u32;
}

/// A clock that always returns 0.
///
/// Use this when no timer is available or when PIT expiry is not required
/// (entries are evicted by other means, e.g. fixed-size PIT with LRU).
#[derive(Clone, Copy, Default)]
pub struct NoOpClock;

impl Clock for NoOpClock {
    #[inline]
    fn now_ms(&self) -> u32 {
        0
    }
}

/// A clock backed by a user-supplied function pointer.
///
/// ```rust,ignore
/// static fn my_timer() -> u32 { /* read hardware register */ 42 }
/// let clock = FnClock(my_timer);
/// ```
pub struct FnClock(pub fn() -> u32);

impl Clock for FnClock {
    #[inline]
    fn now_ms(&self) -> u32 {
        (self.0)()
    }
}
