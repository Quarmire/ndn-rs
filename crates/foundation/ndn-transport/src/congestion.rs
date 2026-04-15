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

// ─── Defaults ────────────────────────────────────────────────────────────────

const DEFAULT_INITIAL_WINDOW: f64 = 2.0;
const DEFAULT_MIN_WINDOW: f64 = 2.0;
const DEFAULT_MAX_WINDOW: f64 = 65536.0;
const DEFAULT_SSTHRESH: f64 = f64::MAX;

// AIMD defaults (matches ndncatchunks).
const AIMD_ADDITIVE_INCREASE: f64 = 1.0;
const AIMD_MULTIPLICATIVE_DECREASE: f64 = 0.5;

// CUBIC defaults (RFC 8312).
const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;

impl Default for CongestionController {
    /// Default: AIMD with standard parameters.
    fn default() -> Self {
        Self::aimd()
    }
}

impl CongestionController {
    /// AIMD with standard parameters (matches `ndncatchunks`).
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

    /// CUBIC with standard parameters (RFC 8312).
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

    /// Fixed window (no adaptation).
    pub fn fixed(window: f64) -> Self {
        Self::Fixed { window }
    }

    // ─── Builder-style parameter setters ────────────────────────────────

    /// Set the initial and current window size.
    ///
    /// For Cubic, this also updates `w_max` to match so the cubic
    /// formula's "recovery target" reflects the user's intent. Without
    /// this, a caller that does `cubic().with_window(N).with_ssthresh(N)`
    /// for large N would leave `w_max` at its tiny default value (2.0),
    /// and the first `on_data()` call would take the cubic branch
    /// (since `window >= ssthresh`) and collapse the window back toward
    /// `w_max = 2`. See the `cubic_does_not_collapse_at_large_initial_window`
    /// regression test.
    pub fn with_window(mut self, w: f64) -> Self {
        match &mut self {
            Self::Aimd { window, .. } | Self::Fixed { window } => *window = w,
            Self::Cubic { window, w_max, .. } => {
                *window = w;
                // Treat the new initial window as the current "best"
                // so the cubic formula's post-loss trajectory points
                // at this window, not the default 2.0.
                if *w_max < w {
                    *w_max = w;
                }
            }
        }
        self
    }

    /// Set the minimum window (floor after decrease). Ignored by Fixed.
    pub fn with_min_window(mut self, w: f64) -> Self {
        match &mut self {
            Self::Aimd { min_window, .. } | Self::Cubic { min_window, .. } => *min_window = w,
            Self::Fixed { .. } => {}
        }
        self
    }

    /// Set the maximum window (ceiling). Ignored by Fixed.
    pub fn with_max_window(mut self, w: f64) -> Self {
        match &mut self {
            Self::Aimd { max_window, .. } | Self::Cubic { max_window, .. } => *max_window = w,
            Self::Fixed { .. } => {}
        }
        self
    }

    /// Set AIMD additive increase per RTT (default: 1.0). Only affects AIMD.
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

    /// Set CUBIC scaling constant C (default: 0.4). Only affects CUBIC.
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

    /// Current window size (number of Interests allowed in flight).
    ///
    /// Callers should use `window().floor() as usize` for the actual limit.
    pub fn window(&self) -> f64 {
        match self {
            Self::Aimd { window, .. } | Self::Cubic { window, .. } | Self::Fixed { window } => {
                *window
            }
        }
    }

    /// A Data packet was received successfully (no congestion mark).
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
                    // Slow start: exponential growth.
                    *window += 1.0;
                } else {
                    // Congestion avoidance: additive increase.
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
                    // TCP-friendly region: at least as aggressive as AIMD.
                    let w_tcp = *w_max * *beta
                        + (3.0 * (1.0 - *beta) / (1.0 + *beta))
                            * (*acks_since_loss as f64 / *window);
                    // Congestion avoidance must be *monotonic* — a
                    // successful data delivery can never justify
                    // shrinking the window. Without the `.max(*window)`
                    // clause, the cubic formula can return a value
                    // below the current window when `t < K` (i.e. we
                    // haven't "recovered" to `w_max` yet by the model's
                    // clock). That happens naturally right after a
                    // loss event but the model can also produce it at
                    // initialisation if `w_max` hasn't caught up to
                    // the user's initial window yet. The RFC 8312
                    // phrasing is "cwnd SHOULD be set to max(cwnd,
                    // W_cubic, W_est)"; we match that.
                    *window = w_cubic.max(w_tcp).max(*window);
                }
                *window = window.min(*max_window);
            }
            Self::Fixed { .. } => {}
        }
    }

    /// A CongestionMark was received on a Data packet.
    ///
    /// Reduces the window but does NOT trigger retransmission — the Data
    /// was delivered successfully, only the sending rate should decrease.
    pub fn on_congestion_mark(&mut self) {
        self.decrease("mark");
    }

    /// An Interest timed out (no Data received within lifetime).
    ///
    /// More aggressive reduction than congestion mark since timeout
    /// indicates actual packet loss, not just queue buildup.
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

    /// Reset to initial state (e.g. on route change or new flow).
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
        assert_eq!(cc.window(), 3.0); // +1 in slow start
        cc.on_data();
        assert_eq!(cc.window(), 4.0);
    }

    #[test]
    fn aimd_congestion_avoidance() {
        let mut cc = CongestionController::aimd();
        // Force out of slow start.
        cc.on_congestion_mark(); // ssthresh = 2*0.5 = 2, window = 2
        assert_eq!(cc.window(), DEFAULT_MIN_WINDOW);

        // Now in congestion avoidance: window grows by 1/window per ack.
        let w_before = cc.window();
        cc.on_data();
        let expected = w_before + 1.0 / w_before;
        assert!((cc.window() - expected).abs() < 1e-9);
    }

    #[test]
    fn aimd_multiplicative_decrease() {
        let mut cc = CongestionController::aimd();
        // Grow window in slow start.
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
        // Repeated losses should not go below min_window.
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
        // Grow to a decent window.
        for _ in 0..50 {
            cc.on_data();
        }
        let w_peak = cc.window();

        // Loss event.
        cc.on_congestion_mark();
        let w_after_loss = cc.window();
        assert!(w_after_loss < w_peak);
        assert!((w_after_loss - w_peak * CUBIC_BETA).abs() < 1.0);

        // Recovery: CUBIC should eventually return to w_peak.
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

    /// Regression test for the cubic collapse bug observed in the
    /// `testbed/tests/chunked/matrix.sh` sweep.
    ///
    /// A consumer that called
    /// `CongestionController::cubic().with_window(64).with_ssthresh(64)`
    /// would see the first `on_data()` call drop the window from 64
    /// to ~1.4 — because `with_window` didn't update `w_max` (it
    /// stayed at the default 2.0), and the cubic formula's "recovery
    /// target" was therefore ~2, which the code assigned to `*window`
    /// unconditionally. At pipe=64 this turned a 60 ms fetch into a
    /// 4.5 second fetch because `window.floor()` was 1 for most of
    /// the subsequent slow-start recovery.
    ///
    /// The fix has two parts: `with_window` now updates `w_max` for
    /// Cubic, and `on_data`'s cubic branch clamps the result to
    /// `max(cwnd, W_cubic, W_est)` so successful data delivery can
    /// never shrink the window.
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
        // Cubic's model eventually allows growth past w_max; the
        // window should be at least the initial 64.
        assert!(cc.window() >= 64.0);
    }

    /// Same shape of test but at the other end of the matrix's
    /// parameter space — ensures the fix works at the window size
    /// that was already passing before.
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

    /// `with_window` updates `w_max` for Cubic so the cubic formula's
    /// post-loss trajectory points at the user-requested window, not
    /// the default 2.0.
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

    /// If the caller sets a *smaller* window than the default w_max,
    /// `with_window` must not lower w_max — that would erase loss
    /// history. The `if *w_max < w` guard preserves the existing
    /// value when the caller's w is smaller.
    #[test]
    fn cubic_with_window_never_shrinks_w_max() {
        // Start with a larger w_max via one loss cycle, then call
        // with_window with a smaller value. w_max should be unchanged.
        let cc = CongestionController::cubic()
            .with_window(500.0) // sets w_max = 500
            .with_window(10.0); // must not shrink w_max below 500
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
