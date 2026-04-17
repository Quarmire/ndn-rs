//! Composite probe scheduler — runs multiple strategies simultaneously,
//! deduplicating broadcast and unicast requests per tick.

use std::time::{Duration, Instant};

use ndn_transport::FaceId;

use crate::strategy::{NeighborProbeStrategy, ProbeRequest, TriggerEvent};


pub struct CompositeStrategy {
    members: Vec<Box<dyn NeighborProbeStrategy>>,
}

impl CompositeStrategy {
    pub fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    pub fn with(mut self, strategy: Box<dyn NeighborProbeStrategy>) -> Self {
        self.members.push(strategy);
        self
    }

    pub fn push(&mut self, strategy: Box<dyn NeighborProbeStrategy>) {
        self.members.push(strategy);
    }
}

impl Default for CompositeStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl NeighborProbeStrategy for CompositeStrategy {
    fn on_tick(&mut self, now: Instant) -> Vec<ProbeRequest> {
        let mut broadcast = false;
        let mut unicasts: Vec<FaceId> = Vec::new();

        for s in &mut self.members {
            for req in s.on_tick(now) {
                match req {
                    ProbeRequest::Broadcast => {
                        broadcast = true;
                    }
                    ProbeRequest::Unicast(fid) => {
                        if !unicasts.contains(&fid) {
                            unicasts.push(fid);
                        }
                    }
                }
            }
        }

        let mut result: Vec<ProbeRequest> =
            unicasts.into_iter().map(ProbeRequest::Unicast).collect();
        if broadcast {
            result.push(ProbeRequest::Broadcast);
        }
        result
    }

    fn on_probe_success(&mut self, rtt: Duration) {
        for s in &mut self.members {
            s.on_probe_success(rtt);
        }
    }

    fn on_probe_timeout(&mut self) {
        for s in &mut self.members {
            s.on_probe_timeout();
        }
    }

    fn trigger(&mut self, event: TriggerEvent) {
        for s in &mut self.members {
            s.trigger(event.clone());
        }
    }
}


#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::config::{DiscoveryConfig, DiscoveryProfile};
    use crate::strategy::{BackoffScheduler, ReactiveScheduler};

    #[test]
    fn deduplicates_broadcast() {
        // Both backoff and reactive want to broadcast on the first tick.
        let mut composite = CompositeStrategy::new()
            .with(Box::new(BackoffScheduler::from_discovery_config(
                &DiscoveryConfig::for_profile(&DiscoveryProfile::Lan),
            )))
            .with(Box::new(ReactiveScheduler::from_discovery_config(
                &DiscoveryConfig::for_profile(&DiscoveryProfile::Mobile),
            )));

        let reqs = composite.on_tick(Instant::now());
        let broadcasts = reqs
            .iter()
            .filter(|r| **r == ProbeRequest::Broadcast)
            .count();
        assert_eq!(broadcasts, 1, "broadcasts should be deduplicated: {reqs:?}");
    }

    #[test]
    fn forwards_success_to_all() {
        let mut composite = CompositeStrategy::new()
            .with(Box::new(BackoffScheduler::from_discovery_config(
                &DiscoveryConfig::for_profile(&DiscoveryProfile::Lan),
            )))
            .with(Box::new(ReactiveScheduler::from_discovery_config(
                &DiscoveryConfig::for_profile(&DiscoveryProfile::Mobile),
            )));
        let now = Instant::now();
        composite.on_tick(now);
        // Should not panic; success forwarded to both.
        composite.on_probe_success(Duration::from_millis(12));
    }

    #[test]
    fn trigger_forwarded_to_all() {
        let mut composite = CompositeStrategy::new()
            .with(Box::new(BackoffScheduler::from_discovery_config(
                &DiscoveryConfig::for_profile(&DiscoveryProfile::Lan),
            )))
            .with(Box::new(ReactiveScheduler::from_discovery_config(
                &DiscoveryConfig::for_profile(&DiscoveryProfile::Mobile),
            )));
        let now = Instant::now();
        composite.on_tick(now); // consume initial probes

        composite.trigger(TriggerEvent::FaceUp);
        let reqs = composite.on_tick(now + Duration::from_secs(1));
        let broadcasts = reqs
            .iter()
            .filter(|r| **r == ProbeRequest::Broadcast)
            .count();
        // At least one broadcast expected (from the trigger).
        assert!(broadcasts >= 1);
    }

    #[test]
    fn empty_composite_returns_no_probes() {
        let mut composite = CompositeStrategy::new();
        let reqs = composite.on_tick(Instant::now());
        assert!(reqs.is_empty());
    }
}
