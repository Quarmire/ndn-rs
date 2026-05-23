//! Token-bucket primitive, wrapping `governor::RateLimiter` (GCRA)
//! with the ndn-rs error type. Supports variable cost — one Interest
//! = 1 token, one Data packet = N bytes of token.

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

use crate::policy::BucketSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketOutcome {
    Permit,
    /// Caller applies the cell's overflow action.
    Deny,
}

/// One token bucket per policy cell with optional Interest-pps and
/// Data-bps sub-buckets; `None` means that dimension is unlimited.
pub struct TokenBucket {
    interest_pps: Option<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    data_bps: Option<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    /// Surfaced by mgmt `list` so operators can see which cells are hot.
    pub overflow_events: AtomicU64,
}

impl TokenBucket {
    pub fn from_spec(spec: &BucketSpec) -> Result<Self, &'static str> {
        if spec.interest_pps.is_none() && spec.data_bps.is_none() {
            return Err("BucketSpec must set at least one limit");
        }
        let interest_pps = match (spec.interest_pps, spec.interest_burst) {
            (Some(r), b) => {
                let rate = NonZeroU32::new(r).ok_or("interest_pps must be > 0")?;
                let burst = NonZeroU32::new(b.unwrap_or(r).max(1)).expect("burst > 0 by max(1)");
                Some(RateLimiter::direct(
                    Quota::per_second(rate).allow_burst(burst),
                ))
            }
            (None, _) => None,
        };
        let data_bps = match (spec.data_bps, spec.data_burst_bytes) {
            (Some(r), b) => {
                let r_u32 = u32::try_from(r).map_err(|_| "data_bps > u32::MAX is not supported")?;
                let rate = NonZeroU32::new(r_u32).ok_or("data_bps must be > 0")?;
                let burst_u32 = u32::try_from(b.unwrap_or(r))
                    .map_err(|_| "data_burst_bytes > u32::MAX is not supported")?;
                let burst = NonZeroU32::new(burst_u32.max(1)).expect("burst > 0 by max(1)");
                Some(RateLimiter::direct(
                    Quota::per_second(rate).allow_burst(burst),
                ))
            }
            (None, _) => None,
        };
        Ok(Self {
            interest_pps,
            data_bps,
            overflow_events: AtomicU64::new(0),
        })
    }

    /// `interest_cost` is 1 per Interest (0 for Data); `data_bytes` is
    /// the wire length for Data (0 for Interest). Both may be non-zero
    /// when a cell limits a mixed flow.
    pub fn try_consume(&self, interest_cost: u32, data_bytes: u32) -> BucketOutcome {
        if let (Some(lim), Some(n)) = (&self.interest_pps, NonZeroU32::new(interest_cost))
            && lim.check_n(n).map(|r| r.is_err()).unwrap_or(true)
        {
            self.overflow_events.fetch_add(1, Ordering::Relaxed);
            return BucketOutcome::Deny;
        }
        if let (Some(lim), Some(n)) = (&self.data_bps, NonZeroU32::new(data_bytes))
            && lim.check_n(n).map(|r| r.is_err()).unwrap_or(true)
        {
            self.overflow_events.fetch_add(1, Ordering::Relaxed);
            return BucketOutcome::Deny;
        }
        BucketOutcome::Permit
    }

    pub fn overflow_count(&self) -> u64 {
        self.overflow_events.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pps(rate: u32, burst: u32) -> BucketSpec {
        BucketSpec::pps(rate, burst)
    }

    #[test]
    fn rejects_empty_spec() {
        let spec = BucketSpec {
            interest_pps: None,
            interest_burst: None,
            data_bps: None,
            data_burst_bytes: None,
        };
        assert!(TokenBucket::from_spec(&spec).is_err());
    }

    #[test]
    fn interest_burst_passes_then_denies() {
        let b = TokenBucket::from_spec(&pps(1, 5)).unwrap();
        for _ in 0..5 {
            assert_eq!(b.try_consume(1, 0), BucketOutcome::Permit);
        }
        assert_eq!(b.try_consume(1, 0), BucketOutcome::Deny);
        assert_eq!(b.overflow_count(), 1);
    }

    #[test]
    fn data_bps_charges_by_size() {
        let spec = BucketSpec::bps(1_000_000, 100_000);
        let b = TokenBucket::from_spec(&spec).unwrap();
        assert_eq!(b.try_consume(0, 80_000), BucketOutcome::Permit);
        assert_eq!(b.try_consume(0, 80_000), BucketOutcome::Deny);
    }

    #[test]
    fn mixed_cell_blocks_on_either_dimension() {
        let spec = BucketSpec {
            interest_pps: Some(10),
            interest_burst: Some(2),
            data_bps: Some(1_000_000),
            data_burst_bytes: Some(50_000),
        };
        let b = TokenBucket::from_spec(&spec).unwrap();
        assert_eq!(b.try_consume(1, 0), BucketOutcome::Permit);
        assert_eq!(b.try_consume(1, 0), BucketOutcome::Permit);
        assert_eq!(b.try_consume(1, 0), BucketOutcome::Deny);
        let _ = b.try_consume(0, 49_000);
        assert_eq!(b.try_consume(0, 2_000), BucketOutcome::Deny);
    }

    #[test]
    #[ignore]
    fn bench_bucket() {
        const ITERS: u32 = 5_000_000;
        let b = TokenBucket::from_spec(&BucketSpec::pps(u32::MAX, u32::MAX)).unwrap();
        let t0 = std::time::Instant::now();
        let mut permits = 0u64;
        for _ in 0..ITERS {
            if b.try_consume(1, 0) == BucketOutcome::Permit {
                permits += 1;
            }
        }
        let elapsed = t0.elapsed();
        let ns_per = elapsed.as_nanos() as f64 / ITERS as f64;
        println!(
            "\nbucket microbench (iters={ITERS}, permits={permits}): \
             {elapsed:?} ({ns_per:.1} ns/op = {:.1} M ops/s)",
            ITERS as f64 / elapsed.as_secs_f64() / 1e6
        );
    }

    #[test]
    fn refills_over_time() {
        let b = TokenBucket::from_spec(&pps(1000, 10)).unwrap();
        for _ in 0..10 {
            assert_eq!(b.try_consume(1, 0), BucketOutcome::Permit);
        }
        assert_eq!(b.try_consume(1, 0), BucketOutcome::Deny);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(b.try_consume(1, 0), BucketOutcome::Permit);
    }
}
