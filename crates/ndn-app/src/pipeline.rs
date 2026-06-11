//! Consumer-side **congestion-controlled fetch pipeline** primitives.
//!
//! A pluggable [`CongestionControl`] decides how many segment Interests a
//! pipelined fetch keeps in flight, growing on delivered segments and shrinking
//! on a congestion signal (a timeout/loss or an NDNLPv2 `CongestionMark`). This
//! is the same separation ndn-tools' `ndncatchunks` uses — a pipeline driver
//! plus interchangeable strategies (`fixed`, `aimd`, `cubic`) — so the object
//! fetch ([`Consumer::fetch_object`](crate::Consumer::fetch_object)), a future
//! throughput/`iperf` tool, and the sync fetcher can share one implementation
//! and one set of tunables instead of each hardcoding a window.
//!
//! [`AimdCongestionControl`] is the default (additive-increase / multiplicative-
//! decrease with slow-start). [`FixedWindow`] is a constant window for
//! benchmarking and A/B comparison.

/// How many segment Interests to keep in flight, adapted from delivery and
/// congestion signals. Implementors are the interchangeable strategies behind a
/// pipelined fetch.
pub trait CongestionControl {
    /// The in-flight Interest target right now.
    fn window(&self) -> usize;
    /// A segment was delivered (an "ack") — the controller may grow.
    fn on_ack(&mut self);
    /// A congestion signal — a fetch stall/timeout or a received `CongestionMark`.
    /// The controller backs off.
    fn on_congestion(&mut self);
}

/// Default upper bound on the AIMD window — caps in-flight Interests so memory
/// and the forwarder's PIT stay bounded on a fat link.
pub const DEFAULT_MAX_CWND: usize = 512;
/// Initial congestion window (slow-start start).
pub const INIT_CWND: f64 = 2.0;

/// AIMD congestion control with slow-start — the ndncatchunks `aimd` model.
/// `cwnd` grows by one segment per RTT in slow-start (doubling) then additively
/// in congestion-avoidance, and halves on a congestion signal.
#[derive(Debug, Clone)]
pub struct AimdCongestionControl {
    cwnd: f64,
    ssthresh: f64,
    slow_start: bool,
    max_cwnd: usize,
}

impl AimdCongestionControl {
    pub fn new() -> Self {
        Self {
            cwnd: INIT_CWND,
            ssthresh: f64::INFINITY,
            slow_start: true,
            max_cwnd: DEFAULT_MAX_CWND,
        }
    }

    /// Override the in-flight cap (default [`DEFAULT_MAX_CWND`]).
    pub fn with_max(mut self, max_cwnd: usize) -> Self {
        self.max_cwnd = max_cwnd.max(1);
        self
    }

    /// Whether the controller is still in slow-start (exposed for tests/metrics).
    pub fn in_slow_start(&self) -> bool {
        self.slow_start
    }
}

impl Default for AimdCongestionControl {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionControl for AimdCongestionControl {
    fn window(&self) -> usize {
        (self.cwnd as usize).clamp(1, self.max_cwnd)
    }

    fn on_ack(&mut self) {
        if self.slow_start {
            self.cwnd += 1.0; // doubles per RTT
            if self.cwnd >= self.ssthresh {
                self.slow_start = false;
            }
        } else {
            self.cwnd += 1.0 / self.cwnd; // ~+1 segment per RTT
        }
    }

    fn on_congestion(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(INIT_CWND);
        self.cwnd = self.ssthresh;
        self.slow_start = false;
    }
}

/// A constant window — no adaptation. For benchmarking against AIMD and for
/// callers that want a fixed pipeline depth.
#[derive(Debug, Clone, Copy)]
pub struct FixedWindow(pub usize);

impl CongestionControl for FixedWindow {
    fn window(&self) -> usize {
        self.0.max(1)
    }
    fn on_ack(&mut self) {}
    fn on_congestion(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aimd_slow_start_doubles_then_caps() {
        let mut cc = AimdCongestionControl::new();
        assert_eq!(cc.window(), 2);
        // Slow-start: +1 per ack → window grows ~geometrically as acks land.
        for _ in 0..10 {
            cc.on_ack();
        }
        assert!(cc.window() >= 12, "slow-start should ramp fast: {}", cc.window());
        assert!(cc.in_slow_start());
    }

    #[test]
    fn aimd_backoff_halves_and_leaves_slow_start() {
        let mut cc = AimdCongestionControl::new();
        for _ in 0..30 {
            cc.on_ack();
        }
        let before = cc.window();
        cc.on_congestion();
        assert!(!cc.in_slow_start(), "congestion exits slow-start");
        assert!(
            cc.window() <= before / 2 + 1 && cc.window() >= 2,
            "multiplicative decrease: {before} -> {}",
            cc.window()
        );
        // After backoff, increase is additive (≈ +1 per RTT), not doubling.
        let after_backoff = cc.window();
        for _ in 0..after_backoff {
            cc.on_ack();
        }
        assert!(
            cc.window() <= after_backoff + 2,
            "congestion-avoidance is additive, not geometric"
        );
    }

    #[test]
    fn aimd_window_never_below_one() {
        let mut cc = AimdCongestionControl::new();
        for _ in 0..20 {
            cc.on_congestion();
        }
        assert!(cc.window() >= 1);
    }

    #[test]
    fn aimd_respects_max() {
        let mut cc = AimdCongestionControl::new().with_max(8);
        for _ in 0..100 {
            cc.on_ack();
        }
        assert_eq!(cc.window(), 8);
    }

    #[test]
    fn fixed_window_is_constant() {
        let mut cc = FixedWindow(16);
        cc.on_ack();
        cc.on_congestion();
        assert_eq!(cc.window(), 16);
    }
}
