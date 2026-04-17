//! Passive neighbor-detection probe scheduler.
//!
//! Emits unicast hellos when unknown MACs are observed; falls back to
//! backoff probing when the link is quiet.

use std::time::{Duration, Instant};

use ndn_transport::FaceId;

use crate::backoff::{BackoffConfig, BackoffState};
use crate::config::DiscoveryConfig;
use crate::strategy::{NeighborProbeStrategy, ProbeRequest, TriggerEvent};


pub struct PassiveScheduler {
    backoff_cfg: BackoffConfig,
    backoff_state: BackoffState,
    next_fallback_at: Option<Instant>,
    passive_idle_timeout: Duration,
    last_passive: Option<Instant>,
    pending_unicast: Vec<FaceId>,
    pending_broadcast: bool,
}

impl PassiveScheduler {
    pub fn from_discovery_config(cfg: &DiscoveryConfig) -> Self {
        let backoff_cfg = BackoffConfig {
            initial_interval: cfg.hello_interval_base,
            max_interval: cfg.hello_interval_max,
            jitter_fraction: cfg.hello_jitter as f64,
        };
        let passive_idle_timeout = cfg.hello_interval_max * 3;
        Self {
            backoff_state: BackoffState::new(seed_from_now()),
            backoff_cfg,
            next_fallback_at: None,
            passive_idle_timeout,
            last_passive: None,
            pending_unicast: Vec::new(),
            pending_broadcast: true, // bootstrap probe on first tick
        }
    }

    fn is_passive_active(&self, now: Instant) -> bool {
        match self.last_passive {
            None => false,
            Some(t) => now.duration_since(t) < self.passive_idle_timeout,
        }
    }
}

impl NeighborProbeStrategy for PassiveScheduler {
    fn on_tick(&mut self, now: Instant) -> Vec<ProbeRequest> {
        let mut reqs: Vec<ProbeRequest> = Vec::new();

        for face_id in self.pending_unicast.drain(..) {
            reqs.push(ProbeRequest::Unicast(face_id));
        }

        if self.pending_broadcast {
            self.pending_broadcast = false;
            reqs.push(ProbeRequest::Broadcast);
        }

        if !self.is_passive_active(now) {
            let fire_fallback = self.next_fallback_at.map(|t| now >= t).unwrap_or(true);
            if fire_fallback {
                let interval = self.backoff_state.next_failure(&self.backoff_cfg);
                self.next_fallback_at = Some(now + interval);
                reqs.push(ProbeRequest::Broadcast);
            }
        }

        reqs
    }

    fn on_probe_success(&mut self, _rtt: Duration) {
        self.backoff_state.reset(&self.backoff_cfg);
        let next = self.backoff_cfg.initial_interval;
        self.next_fallback_at = Some(Instant::now() + next);
    }

    fn on_probe_timeout(&mut self) {
    }

    fn trigger(&mut self, event: TriggerEvent) {
        match event {
            TriggerEvent::PassiveDetection => {
                self.last_passive = Some(Instant::now());
            }
            TriggerEvent::FaceUp => {
                self.pending_broadcast = true;
            }
            TriggerEvent::ForwardingFailure | TriggerEvent::NeighborStale => {
                self.pending_broadcast = true;
                self.backoff_state.reset(&self.backoff_cfg);
            }
        }
    }
}

impl PassiveScheduler {
    pub fn enqueue_unicast(&mut self, face_id: FaceId) {
        if !self.pending_unicast.contains(&face_id) {
            self.pending_unicast.push(face_id);
        }
    }
}


fn seed_from_now() -> u32 {
    let ns = Instant::now().elapsed().subsec_nanos();
    if ns == 0 { 0xdeadbeef } else { ns }
}


#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ndn_transport::FaceId;

    use super::*;
    use crate::config::{DiscoveryConfig, DiscoveryProfile};

    fn high_mob_sched() -> PassiveScheduler {
        PassiveScheduler::from_discovery_config(&DiscoveryConfig::for_profile(
            &DiscoveryProfile::HighMobility,
        ))
    }

    #[test]
    fn fires_broadcast_on_first_tick() {
        let mut s = high_mob_sched();
        let reqs = s.on_tick(Instant::now());
        assert!(reqs.contains(&ProbeRequest::Broadcast));
    }

    #[test]
    fn unicast_after_passive_detection_enqueue() {
        let mut s = high_mob_sched();
        let now = Instant::now();
        s.on_tick(now); // initial broadcast

        s.trigger(TriggerEvent::PassiveDetection);
        s.enqueue_unicast(FaceId(3));
        let reqs = s.on_tick(now + Duration::from_millis(10));
        assert!(reqs.contains(&ProbeRequest::Unicast(FaceId(3))));
    }

    #[test]
    fn fallback_fires_when_passive_idle() {
        let mut s = high_mob_sched();
        let now = Instant::now();
        s.on_tick(now); // initial

        // Far in the future — no passive activity, fallback should fire.
        let future = now + Duration::from_secs(3600);
        let reqs = s.on_tick(future);
        assert!(reqs.contains(&ProbeRequest::Broadcast));
    }

    #[test]
    fn fallback_suppressed_when_passive_active() {
        let mut s = high_mob_sched();
        let now = Instant::now();
        s.on_tick(now); // initial broadcast consumed

        // Record recent passive detection.
        s.trigger(TriggerEvent::PassiveDetection);
        // Advance by less than passive_idle_timeout.
        let soon = now + Duration::from_millis(100);
        let reqs = s.on_tick(soon);
        // No fallback broadcast (passive is still active); no pending_broadcast.
        let broadcasts: Vec<_> = reqs
            .iter()
            .filter(|r| **r == ProbeRequest::Broadcast)
            .collect();
        assert!(
            broadcasts.is_empty(),
            "fallback should be suppressed: {reqs:?}"
        );
    }

    #[test]
    fn face_up_trigger_broadcasts() {
        let mut s = high_mob_sched();
        let now = Instant::now();
        s.on_tick(now); // initial

        s.trigger(TriggerEvent::FaceUp);
        let reqs = s.on_tick(now + Duration::from_millis(10));
        assert!(reqs.contains(&ProbeRequest::Broadcast));
    }
}
