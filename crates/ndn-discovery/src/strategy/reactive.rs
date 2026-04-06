//! Event-driven (reactive) probe scheduler.
//!
//! No periodic timer in the steady state.  A probe is sent only when a
//! [`TriggerEvent`] is received:
//!
//! - Face comes up — bootstrap the neighbor table immediately.
//! - Forwarding failure — verify the affected face is still alive.
//! - Neighbor goes stale — re-probe before declaring it absent.
//!
//! [`PassiveDetection`](TriggerEvent::PassiveDetection) is ignored; use
//! [`PassiveScheduler`](super::PassiveScheduler) for that case.
//!
//! ## Rate limiting
//!
//! To prevent a storm of hellos after a flap, a minimum interval is enforced.
//! No probe is emitted within [`DiscoveryConfig::hello_interval_base`] of the
//! previous one.  The implementation collapses multiple queued triggers into
//! one probe when they arrive within the minimum interval.

use std::time::{Duration, Instant};

use crate::config::DiscoveryConfig;
use crate::strategy::{NeighborProbeStrategy, ProbeRequest, TriggerEvent};

// ─── ReactiveScheduler ───────────────────────────────────────────────────────

/// Probe scheduler that sends only on topology events, with rate limiting.
pub struct ReactiveScheduler {
    /// Minimum gap between consecutive probes.
    min_interval: Duration,
    /// When the last probe was sent (`None` = never sent).
    last_sent: Option<Instant>,
    /// A probe has been requested but not yet emitted (rate-limited).
    pending: bool,
}

impl ReactiveScheduler {
    /// Build from the relevant fields of a [`DiscoveryConfig`].
    pub fn from_discovery_config(cfg: &DiscoveryConfig) -> Self {
        Self {
            min_interval: cfg.hello_interval_base,
            last_sent: None,
            pending: true, // fire on the first tick to bootstrap
        }
    }
}

impl NeighborProbeStrategy for ReactiveScheduler {
    fn on_tick(&mut self, now: Instant) -> Vec<ProbeRequest> {
        if !self.pending {
            return Vec::new();
        }

        // Enforce minimum interval.
        if let Some(last) = self.last_sent
            && now.duration_since(last) < self.min_interval
        {
            return Vec::new(); // still rate-limited; keep pending
        }

        self.pending = false;
        self.last_sent = Some(now);
        vec![ProbeRequest::Broadcast]
    }

    fn on_probe_success(&mut self, _rtt: Duration) {
        // Nothing to reset; the next probe fires only on a trigger.
    }

    fn on_probe_timeout(&mut self) {
        // Timed out — re-trigger to verify.
        self.pending = true;
    }

    fn trigger(&mut self, event: TriggerEvent) {
        match event {
            TriggerEvent::PassiveDetection => {
                // Not applicable to this scheduler; ignore.
            }
            TriggerEvent::FaceUp
            | TriggerEvent::ForwardingFailure
            | TriggerEvent::NeighborStale => {
                self.pending = true;
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::{DiscoveryConfig, DiscoveryProfile};

    fn mobile_sched() -> ReactiveScheduler {
        ReactiveScheduler::from_discovery_config(
            &DiscoveryConfig::for_profile(&DiscoveryProfile::Mobile),
        )
    }

    #[test]
    fn fires_on_first_tick() {
        let mut s = mobile_sched();
        let reqs = s.on_tick(Instant::now());
        assert_eq!(reqs, vec![ProbeRequest::Broadcast]);
    }

    #[test]
    fn does_not_fire_without_trigger() {
        let mut s = mobile_sched();
        let now = Instant::now();
        s.on_tick(now); // initial bootstrap probe

        // No trigger — subsequent ticks are silent.
        let reqs = s.on_tick(now + Duration::from_secs(1));
        assert!(reqs.is_empty());
    }

    #[test]
    fn fires_after_trigger() {
        let mut s = mobile_sched();
        let now = Instant::now();
        s.on_tick(now); // initial

        s.trigger(TriggerEvent::ForwardingFailure);
        let reqs = s.on_tick(now + Duration::from_secs(1));
        assert_eq!(reqs, vec![ProbeRequest::Broadcast]);
    }

    #[test]
    fn rate_limits_rapid_triggers() {
        let mut s = mobile_sched();
        let now = Instant::now();
        s.on_tick(now); // initial probe; sets last_sent

        // Trigger immediately — still within min_interval.
        s.trigger(TriggerEvent::NeighborStale);
        let reqs = s.on_tick(now); // same instant — still rate-limited
        assert!(reqs.is_empty(), "should be rate-limited");

        // After min_interval has elapsed, the pending probe fires.
        let later = now + s.min_interval + Duration::from_millis(1);
        let reqs = s.on_tick(later);
        assert_eq!(reqs, vec![ProbeRequest::Broadcast]);
    }

    #[test]
    fn passive_detection_is_ignored() {
        let mut s = mobile_sched();
        let now = Instant::now();
        s.on_tick(now); // initial

        s.trigger(TriggerEvent::PassiveDetection);
        let reqs = s.on_tick(now + Duration::from_secs(10));
        assert!(reqs.is_empty());
    }
}
