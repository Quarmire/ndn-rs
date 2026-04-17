//! Probe-scheduling strategies for neighbor discovery.
//!
//! Controls **when** hellos are sent; the state machine (face creation, FIB,
//! neighbor table) is independent.

pub mod backoff;
pub mod composite;
pub mod passive;
pub mod reactive;
pub mod swim;

pub use backoff::BackoffScheduler;
pub use composite::CompositeStrategy;
pub use passive::PassiveScheduler;
pub use reactive::ReactiveScheduler;
pub use swim::SwimScheduler;

use std::time::{Duration, Instant};

use ndn_transport::FaceId;

use crate::config::{DiscoveryConfig, HelloStrategyKind};


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeRequest {
    Broadcast,
    Unicast(FaceId),
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TriggerEvent {
    FaceUp,
    ForwardingFailure,
    NeighborStale,
    /// Only meaningful for [`PassiveScheduler`].
    PassiveDetection,
}


/// Controls the *when* of hello/probe scheduling.
pub trait NeighborProbeStrategy: Send + 'static {
    fn on_tick(&mut self, now: Instant) -> Vec<ProbeRequest>;
    fn on_probe_success(&mut self, rtt: Duration);
    fn on_probe_timeout(&mut self);
    fn trigger(&mut self, event: TriggerEvent);
}


pub fn build_strategy(cfg: &DiscoveryConfig) -> Box<dyn NeighborProbeStrategy> {
    match cfg.hello_strategy {
        HelloStrategyKind::Backoff => Box::new(BackoffScheduler::from_discovery_config(cfg)),
        HelloStrategyKind::Swim => Box::new(SwimScheduler::from_discovery_config(cfg)),
        HelloStrategyKind::Reactive => Box::new(ReactiveScheduler::from_discovery_config(cfg)),
        HelloStrategyKind::Passive => Box::new(PassiveScheduler::from_discovery_config(cfg)),
    }
}
