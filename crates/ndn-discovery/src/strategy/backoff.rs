//! Exponential-backoff probe scheduler.
//!
//! Starts at [`DiscoveryConfig::hello_interval_base`] and doubles on each tick
//! where no probe is needed, up to [`DiscoveryConfig::hello_interval_max`].
//! Jitter of ±[`DiscoveryConfig::hello_jitter`] × interval is applied to
//! each computed deadline to desynchronise nodes that started simultaneously.
//!
//! # Reset behaviour
//!
//! Any [`TriggerEvent`] resets the interval to the base and sets
//! `pending_immediate = true` so that the very next [`on_tick`] call emits
//! a [`ProbeRequest::Broadcast`] without waiting for the deadline.  A
//! successful probe ([`on_probe_success`]) similarly resets the interval; a
//! probe timeout ([`on_probe_timeout`]) advances to the next (doubled) level.

use std::time::{Duration, Instant};

use crate::backoff::{BackoffConfig, BackoffState};
use crate::config::DiscoveryConfig;
use crate::strategy::{NeighborProbeStrategy, ProbeRequest, TriggerEvent};

// ─── BackoffScheduler ────────────────────────────────────────────────────────

/// Probe scheduler that uses exponential back-off with jitter.
pub struct BackoffScheduler {
    cfg: BackoffConfig,
    state: BackoffState,
    /// When the next probe should be sent.
    next_probe_at: Option<Instant>,
    /// Set to `true` by trigger events so the next `on_tick` fires immediately.
    pending_immediate: bool,
}

impl BackoffScheduler {
    /// Build from the relevant fields of a [`DiscoveryConfig`].
    pub fn from_discovery_config(cfg: &DiscoveryConfig) -> Self {
        let backoff_cfg = BackoffConfig {
            initial_interval: cfg.hello_interval_base,
            max_interval: cfg.hello_interval_max,
            jitter_fraction: cfg.hello_jitter as f64,
        };
        Self {
            cfg: backoff_cfg,
            state: BackoffState::new(seed_from_now()),
            next_probe_at: None,
            pending_immediate: true, // send on the very first tick
        }
    }

    /// Schedule a deadline `interval` from `now`.
    fn schedule_next(&mut self, now: Instant, interval: Duration) {
        self.next_probe_at = Some(now + interval);
    }
}

impl NeighborProbeStrategy for BackoffScheduler {
    fn on_tick(&mut self, now: Instant) -> Vec<ProbeRequest> {
        let fire = self.pending_immediate || self.next_probe_at.map(|t| now >= t).unwrap_or(true);

        if !fire {
            return Vec::new();
        }

        self.pending_immediate = false;
        // Advance to next backoff level.
        let interval = self.state.next_failure(&self.cfg);
        self.schedule_next(now, interval);

        vec![ProbeRequest::Broadcast]
    }

    fn on_probe_success(&mut self, _rtt: Duration) {
        self.state.reset(&self.cfg);
        // Schedule next probe at base interval.
        let next = self.cfg.initial_interval;
        self.schedule_next(Instant::now(), next);
    }

    fn on_probe_timeout(&mut self) {
        // Advance backoff on next on_tick via the existing state; no change
        // needed here — next_failure will be called from on_tick.
    }

    fn trigger(&mut self, _event: TriggerEvent) {
        // Reset to base and fire immediately.
        self.state.reset(&self.cfg);
        self.pending_immediate = true;
    }
}

// ─── RNG seed ────────────────────────────────────────────────────────────────

fn seed_from_now() -> u32 {
    let ns = Instant::now().elapsed().subsec_nanos();
    if ns == 0 { 0xdeadbeef } else { ns }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::{DiscoveryConfig, DiscoveryProfile};

    fn lan_sched() -> BackoffScheduler {
        BackoffScheduler::from_discovery_config(&DiscoveryConfig::for_profile(
            &DiscoveryProfile::Lan,
        ))
    }

    #[test]
    fn fires_on_first_tick() {
        let mut s = lan_sched();
        let now = Instant::now();
        let reqs = s.on_tick(now);
        assert_eq!(reqs, vec![ProbeRequest::Broadcast]);
    }

    #[test]
    fn no_fire_before_deadline() {
        let mut s = lan_sched();
        let now = Instant::now();
        s.on_tick(now); // consume the immediate probe
        // Immediately after — still within interval.
        let reqs = s.on_tick(now);
        assert!(reqs.is_empty());
    }

    #[test]
    fn trigger_causes_immediate_probe() {
        let mut s = lan_sched();
        let now = Instant::now();
        s.on_tick(now); // consume initial
        s.on_tick(now); // still within deadline

        s.trigger(TriggerEvent::FaceUp);
        let reqs = s.on_tick(now);
        assert_eq!(reqs, vec![ProbeRequest::Broadcast]);
    }

    #[test]
    fn success_resets_interval() {
        let mut s = lan_sched();
        let now = Instant::now();
        // Advance state by failing a few times.
        s.on_tick(now);
        s.on_probe_timeout();
        s.on_tick(now + Duration::from_secs(100));
        // After success the next deadline should be at base interval.
        s.on_probe_success(Duration::from_millis(10));
        assert_eq!(s.state.current(), Duration::ZERO);
    }
}
