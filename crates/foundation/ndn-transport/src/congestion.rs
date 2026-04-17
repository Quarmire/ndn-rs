//! Consumer-side congestion control for NDN.
//!
//! Provides window-based algorithms that react to Data arrivals, congestion
//! marks (NDNLPv2 CongestionMark), and timeouts.  Consumers use these to
//! regulate how many Interests are in flight.
//!
//! # Design
//!
//! `CongestionController` is an enum (not a trait) — avoids dynamic dispatch
//! and matches the `RtoStrategy`/`ReliabilityConfig` pattern used elsewhere.
//! All state is internal; callers only see `window()` and the event methods.
//!
//! # Example
//!
//! ```rust
//! use ndn_transport::CongestionController;
//!
//! let mut cc = CongestionController::default(); // AIMD
//! assert_eq!(cc.window(), 2.0);
//!
//! // Data arrived successfully — grow window.
//! cc.on_data();
//! assert!(cc.window() > 2.0);
//!
//! // Congestion mark received — cut window.
//! cc.on_congestion_mark();
//! assert!(cc.window() < 3.0);
//! ```

/// Consumer-side congestion control algorithm.
///
/// Each variant carries its own internal state.  The caller drives events
/// (`on_data`, `on_congestion_mark`, `on_timeout`) and reads the current
/// window via `window()`.
///
/// # Variants
///
/// | Algorithm | Best for | Behaviour |
/// |-----------|----------|-----------|
/// | `Aimd`    | General-purpose, matches NFD consumers | Linear increase, multiplicative decrease |
/// | `Cubic`   | High-bandwidth, long-RTT links | Cubic function ramp-up after loss |
/// | `Fixed`   | Benchmarks, known-capacity links | Constant window, no adaptation |
#[derive(Debug, Clone)]
pub enum CongestionController {
    /// Additive-Increase Multiplicative-Decrease.
    ///
    /// Standard algorithm used by `ndncatchunks`.  Window grows by
    /// `additive_increase / window` per ack (≈ +1 per RTT) and is
    /// multiplied by `multiplicative_decrease` on congestion/timeout.
    Aimd {
        window: f64,
        min_window: f64,
        max_window: f64,
        additive_increase: f64,
        multiplicative_decrease: f64,
        /// Slow-start threshold. While `window < ssthresh`, window grows
        /// by 1.0 per ack (exponential); above it, grows additively.
        ssthresh: f64,
    },
    /// CUBIC (RFC 8312).
    ///
    /// Concave/convex window growth based on time since last loss event.
    /// More aggressive ramp-up than AIMD on high-bandwidth links.
    Cubic {
        window: f64,
        min_window: f64,
        max_window: f64,
        /// Window size at last loss event.
        w_max: f64,
        /// Ack count since last loss event (proxy for time).
        acks_since_loss: u64,
        /// CUBIC scaling constant (default: 0.4).
        c: f64,
        /// Multiplicative decrease factor (default: 0.7).
        beta: f64,
        ssthresh: f64,
    },
    /// Fixed window — no adaptation.
    Fixed { window: f64 },
}

const DEFAULT_INITIAL_WINDOW: f64 = 2.0;
const DEFAULT_MIN_WINDOW: f64 = 2.0;
const DEFAULT_MAX_WINDOW: f64 = 65536.0;
const DEFAULT_SSTHRESH: f64 = f64::MAX;

const AIMD_ADDITIVE_INCREASE: f64 = 1.0;
const AIMD_MULTIPLICATIVE_DECREASE: f64 = 0.5;

// RFC 8312 defaults.
const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;

impl Default for CongestionController {
    fn default() -> Self {
        Self::aimd()
    }
}

impl CongestionController {
    /// AIMD with `ndncatchunks`-compatible parameters.
    pub fn aimd() -> Self {
        Self::Aimd {
            window: DEFAULT_INITIAL_WINDOW,
            min_window: DEFAULT_MIN_WINDOW,
            max_window: DEFAULT_MAX_WINDOW,
            additive_increase: AIMD_ADDITIVE_INCREASE,
            multiplicative_decrease: AIMD_MULTIPLICATIVE_DECREASE,
            ssthresh: DEFAULT_SSTHRESH,
        }
    }

    /// CUBIC with RFC 8312 parameters.
    pub fn cubic() -> Self {
        Self::Cubic {
            window: DEFAULT_INITIAL_WINDOW,
            min_window: DEFAULT_MIN_WINDOW,
            max_window: DEFAULT_MAX_WINDOW,
            w_max: DEFAULT_INITIAL_WINDOW,
            acks_since_loss: 0,
            c: CUBIC_C,
            beta: CUBIC_BETA,
            ssthresh: DEFAULT_SSTHRESH,
        }
    }

    pub fn fixed(window: f64) -> Self {
        Self::Fixed { window }
    }

    /// Set the initial and current window size.
    ///
    /// For Cubic, also updates `w_max` so the cubic formula's recovery
    /// target reflects the caller's intent rather than the default 2.0.
    /// See `cubic_does_not_collapse_at_large_initial_window` regression test.
    pub fn with_window(mut self, w: f64) -> Self {
        match &mut self {
            Self::Aimd { window, .. } | Self::Fixed { window } => *window = w,
            Self::Cubic { window, w_max, .. } => {
                *window = w;
                if *w_max < w {
                    *w_max = w;
                }
            }
        }
        self
    }

    /// Set the minimum window (floor after decrease).
    pub fn with_min_window(mut self, w: f64) -> Self {
        match &mut self {
            Self::Aimd { min_window, .. } | Self::Cubic { min_window, .. } => *min_window = w,
            Self::Fixed { .. } => {}
        }
        self
    }

    /// Set the maximum window.
    pub fn with_max_window(mut self, w: f64) -> Self {
        match &mut self {
            Self::Aimd { max_window, .. } | Self::Cubic { max_window, .. } => *max_window = w,
            Self::Fixed { .. } => {}
        }
        self
    }

    /// Set AIMD additive increase per RTT (default: 1.0).
    pub fn with_additive_increase(mut self, ai: f64) -> Self {
        if let Self::Aimd {
            additive_increase, ..
        } = &mut self
        {
            *additive_increase = ai;
        }
        self
    }

    /// Set AIMD/CUBIC multiplicative decrease factor (default: 0.5 for AIMD, 0.7 for CUBIC).
    pub fn with_decrease_factor(mut self, md: f64) -> Self {
        match &mut self {
            Self::Aimd {
                multiplicative_decrease,
                ..
            } => *multiplicative_decrease = md,
            Self::Cubic { beta, .. } => *beta = md,
            Self::Fixed { .. } => {}
        }
        self
    }

    /// Set CUBIC scaling constant C (default: 0.4, RFC 8312).
    pub fn with_cubic_c(mut self, c_val: f64) -> Self {
        if let Self::Cubic { c, .. } = &mut self {
            *c = c_val;
        }
        self
    }

    /// Set the slow-start threshold.
    ///
    /// By default ssthresh is `f64::MAX` (unbounded slow start).  Setting
    /// this to the initial window size prevents the exponential ramp from
    /// overshooting the link capacity on the first flow.
    pub fn with_ssthresh(mut self, ss: f64) -> Self {
        match &mut self {
            Self::Aimd { ssthresh, .. } | Self::Cubic { ssthresh, .. } => *ssthresh = ss,
            Self::Fixed { .. } => {}
        }
        self
    }

    /// Current window size. Use `window().floor() as usize` for the actual limit.
    pub fn window(&self) -> f64 {
        match self {
            Self::Aimd { window, .. } | Self::Cubic { window, .. } | Self::Fixed { window } => {
                *window
            }
        }
    }

    /// A Data packet was received without a congestion mark.
    pub fn on_data(&mut self) {
        match self {
            Self::Aimd {
                window,
                additive_increase,
                ssthresh,
                max_window,
                ..
            } => {
                if *window < *ssthresh {
                    *window += 1.0;
                } else {
                    *window += *additive_increase / *window;
                }
                *window = window.min(*max_window);
            }
            Self::Cubic {
                window,
                w_max,
                acks_since_loss,
                c,
                beta,
                ssthresh,
                max_window,
                ..
            } => {
                *acks_since_loss += 1;
                if *window < *ssthresh {
                    *window += 1.0;
                } else {
                    // CUBIC function: W(t) = C*(t - K)^3 + W_max
                    // where K = (W_max * (1-beta) / C)^(1/3)
                    // We approximate t by acks_since_loss / window (RTTs elapsed).
                    let t = *acks_since_loss as f64 / *window;
                    let k = ((*w_max * (1.0 - *beta)) / *c).cbrt();
                    let w_cubic = *c * (t - k).powi(3) + *w_max;
                    // TCP-friendly region (RFC 8312 section 4.3).
                    let w_tcp = *w_max * *beta
                        + (3.0 * (1.0 - *beta) / (1.0 + *beta))
                            * (*acks_since_loss as f64 / *window);
                    // RFC 8312: "cwnd SHOULD be set to max(cwnd, W_cubic, W_est)".
                    *window = w_cubic.max(w_tcp).max(*window);
                }
                *window = window.min(*max_window);
            }
            Self::Fixed { .. } => {}
        }
    }

    /// A CongestionMark was received. Reduces window but not retransmission.
    pub fn on_congestion_mark(&mut self) {
        self.decrease("mark");
    }

    /// An Interest timed out.
    pub fn on_timeout(&mut self) {
        self.decrease("timeout");
    }

    fn decrease(&mut self, _reason: &str) {
        match self {
            Self::Aimd {
                window,
                multiplicative_decrease,
                min_window,
                ssthresh,
                ..
            } => {
                *ssthresh = (*window * *multiplicative_decrease).max(*min_window);
                *window = *ssthresh;
            }
            Self::Cubic {
                window,
                w_max,
                acks_since_loss,
                beta,
                min_window,
                ssthresh,
                ..
            } => {
                *w_max = *window;
                *ssthresh = (*window * *beta).max(*min_window);
                *window = *ssthresh;
                *acks_since_loss = 0;
            }
            Self::Fixed { .. } => {}
        }
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        match self {
            Self::Aimd {
                window, ssthresh, ..
            } => {
                *window = DEFAULT_INITIAL_WINDOW;
                *ssthresh = DEFAULT_SSTHRESH;
            }
            Self::Cubic {
                window,
                w_max,
                acks_since_loss,
                ssthresh,
                ..
            } => {
                *window = DEFAULT_INITIAL_WINDOW;
                *w_max = DEFAULT_INITIAL_WINDOW;
                *acks_since_loss = 0;
                *ssthresh = DEFAULT_SSTHRESH;
            }
            Self::Fixed { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aimd_slow_start() {
        let mut cc = CongestionController::aimd();
        assert_eq!(cc.window(), 2.0);
        cc.on_data();
        assert_eq!(cc.window(), 3.0);
        cc.on_data();
        assert_eq!(cc.window(), 4.0);
    }

    #[test]
    fn aimd_congestion_avoidance() {
        let mut cc = CongestionController::aimd();
        cc.on_congestion_mark();
        assert_eq!(cc.window(), DEFAULT_MIN_WINDOW);

        let w_before = cc.window();
        cc.on_data();
        let expected = w_before + 1.0 / w_before;
        assert!((cc.window() - expected).abs() < 1e-9);
    }

    #[test]
    fn aimd_multiplicative_decrease() {
        let mut cc = CongestionController::aimd();
        for _ in 0..10 {
            cc.on_data();
        }
        let w_before = cc.window();
        cc.on_congestion_mark();
        assert!((cc.window() - w_before * 0.5).abs() < 1e-9);
    }

    #[test]
    fn aimd_timeout_reduces_window() {
        let mut cc = CongestionController::aimd();
        for _ in 0..10 {
            cc.on_data();
        }
        let w_before = cc.window();
        cc.on_timeout();
        assert!(cc.window() < w_before);
    }

    #[test]
    fn aimd_respects_min_window() {
        let mut cc = CongestionController::aimd();
        for _ in 0..20 {
            cc.on_timeout();
        }
        assert!(cc.window() >= DEFAULT_MIN_WINDOW);
    }

    #[test]
    fn cubic_slow_start() {
        let mut cc = CongestionController::cubic();
        assert_eq!(cc.window(), 2.0);
        cc.on_data();
        assert_eq!(cc.window(), 3.0);
    }

    #[test]
    fn cubic_recovers_after_loss() {
        let mut cc = CongestionController::cubic();
        for _ in 0..50 {
            cc.on_data();
        }
        let w_peak = cc.window();
        cc.on_congestion_mark();
        let w_after_loss = cc.window();
        assert!(w_after_loss < w_peak);
        assert!((w_after_loss - w_peak * CUBIC_BETA).abs() < 1.0);
        for _ in 0..500 {
            cc.on_data();
        }
        assert!(cc.window() >= w_peak * 0.9);
    }

    #[test]
    fn cubic_respects_min_window() {
        let mut cc = CongestionController::cubic();
        for _ in 0..20 {
            cc.on_timeout();
        }
        assert!(cc.window() >= DEFAULT_MIN_WINDOW);
    }

    /// Regression: `cubic().with_window(64).with_ssthresh(64)` collapsed
    /// the window to ~1.4 on first `on_data()` because `with_window`
    /// didn't update `w_max` (stayed at default 2.0). Fixed by syncing
    /// `w_max` in `with_window` and clamping to `max(cwnd, W_cubic, W_est)`.
    #[test]
    fn cubic_does_not_collapse_at_large_initial_window() {
        let mut cc = CongestionController::cubic()
            .with_window(64.0)
            .with_ssthresh(64.0);
        assert_eq!(cc.window(), 64.0);

        // First on_data must not shrink.
        cc.on_data();
        assert!(
            cc.window() >= 64.0,
            "first on_data shrank window to {} (cubic collapse bug)",
            cc.window()
        );

        // Many subsequent on_data calls must not shrink either.
        for i in 0..1000 {
            cc.on_data();
            assert!(
                cc.window() >= 64.0,
                "on_data iteration {i} shrank window to {}",
                cc.window()
            );
        }
        assert!(cc.window() >= 64.0);
    }

    /// Same regression at the other end of the parameter space.
    #[test]
    fn cubic_does_not_collapse_at_initial_window_256() {
        let mut cc = CongestionController::cubic()
            .with_window(256.0)
            .with_ssthresh(256.0);
        cc.on_data();
        assert!(
            cc.window() >= 256.0,
            "cubic collapsed at init_window=256: now {}",
            cc.window()
        );
    }

    /// `with_window` updates `w_max` for Cubic.
    #[test]
    fn cubic_with_window_updates_w_max() {
        let cc = CongestionController::cubic().with_window(100.0);
        match cc {
            CongestionController::Cubic { w_max, window, .. } => {
                assert_eq!(window, 100.0);
                assert_eq!(w_max, 100.0);
            }
            _ => panic!("expected Cubic"),
        }
    }

    /// `with_window` must not lower `w_max` — that would erase loss history.
    #[test]
    fn cubic_with_window_never_shrinks_w_max() {
        let cc = CongestionController::cubic()
            .with_window(500.0)
            .with_window(10.0);
        match cc {
            CongestionController::Cubic { w_max, window, .. } => {
                assert_eq!(window, 10.0);
                assert_eq!(
                    w_max, 500.0,
                    "w_max must not shrink when caller passes smaller window"
                );
            }
            _ => panic!("expected Cubic"),
        }
    }

    #[test]
    fn fixed_never_changes() {
        let mut cc = CongestionController::fixed(64.0);
        assert_eq!(cc.window(), 64.0);
        cc.on_data();
        assert_eq!(cc.window(), 64.0);
        cc.on_congestion_mark();
        assert_eq!(cc.window(), 64.0);
        cc.on_timeout();
        assert_eq!(cc.window(), 64.0);
    }

    #[test]
    fn reset_returns_to_initial() {
        let mut cc = CongestionController::aimd();
        for _ in 0..20 {
            cc.on_data();
        }
        assert!(cc.window() > DEFAULT_INITIAL_WINDOW);
        cc.reset();
        assert_eq!(cc.window(), DEFAULT_INITIAL_WINDOW);
    }

    #[test]
    fn default_is_aimd() {
        let cc = CongestionController::default();
        assert!(matches!(cc, CongestionController::Aimd { .. }));
    }
}
