//! Passive neighbor-detection probe scheduler.
//!
//! Zero-overhead discovery for mesh networks where traffic flows continuously.
//! The multicast face receives packets from all on-link nodes; the face layer
//! surfaces each sender's MAC via [`recv_with_source`].  When an unknown MAC
//! appears, the protocol emits a targeted unicast hello; no broadcast is needed.
//!
//! ## Fallback to backoff
//!
//! When the link is quiet (no passive detections within `passive_idle_timeout`)
//! the scheduler falls back to [`BackoffScheduler`] probing to catch nodes
//! that are present but not sending any traffic.  Once passive activity
//! resumes, the backoff fallback is suppressed again.
//!
//! ## Unicast vs broadcast
//!
//! On `PassiveDetection` the scheduler emits a [`ProbeRequest::Unicast`] for
//! the detected face.  The fallback path emits [`ProbeRequest::Broadcast`].

use std::time::{Duration, Instant};

use ndn_transport::FaceId;

use crate::backoff::{BackoffConfig, BackoffState};
use crate::config::DiscoveryConfig;
use crate::strategy::{NeighborProbeStrategy, ProbeRequest, TriggerEvent};

// ─── PassiveScheduler ────────────────────────────────────────────────────────

/// Probe scheduler that uses passive MAC overhearing with backoff fallback.
pub struct PassiveScheduler {
    /// Backoff config used for the fallback path.
    backoff_cfg: BackoffConfig,
    /// Mutable backoff state for the fallback path.
    backoff_state: BackoffState,
    /// When the next fallback probe should fire (`None` = not yet scheduled).
    next_fallback_at: Option<Instant>,
    /// How long without a passive detection before the fallback is activated.
    passive_idle_timeout: Duration,
    /// When we last saw a passive detection.
    last_passive: Option<Instant>,
    /// Unicast probes requested by passive detections, not yet emitted.
    pending_unicast: Vec<FaceId>,
    /// Whether a broadcast probe is pending (from a non-passive trigger).
    pending_broadcast: bool,
}

impl PassiveScheduler {
    /// Build from the relevant fields of a [`DiscoveryConfig`].
    pub fn from_discovery_config(cfg: &DiscoveryConfig) -> Self {
        let backoff_cfg = BackoffConfig {
            initial_interval: cfg.hello_interval_base,
            max_interval: cfg.hello_interval_max,
            jitter_fraction: cfg.hello_jitter as f64,
        };
        // Idle timeout = 3× max interval; if no passive traffic for this long
        // we fall back to probing.
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

        // Emit any queued unicast probes from passive detections.
        for face_id in self.pending_unicast.drain(..) {
            reqs.push(ProbeRequest::Unicast(face_id));
        }

        // Emit a pending broadcast (from a non-passive trigger).
        if self.pending_broadcast {
            self.pending_broadcast = false;
            reqs.push(ProbeRequest::Broadcast);
        }

        // Fallback backoff path: only when passive detection is idle.
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
        // Backoff advances on next fallback tick; nothing extra needed.
    }

    fn trigger(&mut self, event: TriggerEvent) {
        match event {
            TriggerEvent::PassiveDetection => {
                // Update passive activity timestamp.
                self.last_passive = Some(Instant::now());
                // The caller is expected to call trigger with the detected
                // face ID separately if a unicast probe is desired.  Here
                // we just suppress the backoff fallback.
            }
            TriggerEvent::FaceUp => {
                self.pending_broadcast = true;
            }
            TriggerEvent::ForwardingFailure | TriggerEvent::NeighborStale => {
                self.pending_broadcast = true;
                // Reset backoff so re-probe is fast.
                self.backoff_state.reset(&self.backoff_cfg);
            }
        }
    }
}

/// Enqueue a unicast probe toward a specific face detected passively.
///
/// Call this after [`trigger`]`(TriggerEvent::PassiveDetection)` when the
/// detected MAC maps to an existing [`FaceId`] that needs a hello.
impl PassiveScheduler {
    pub fn enqueue_unicast(&mut self, face_id: FaceId) {
        if !self.pending_unicast.contains(&face_id) {
            self.pending_unicast.push(face_id);
        }
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
