//! Probe-scheduling strategies for neighbor discovery.
//!
//! A [`NeighborProbeStrategy`] controls **when** hellos and liveness probes are
//! sent.  The state machine (face creation, FIB wiring, neighbor table
//! mutations) lives in the protocol implementation (`EtherND`, `UdpND`, …) and
//! is completely independent.
//!
//! ## Strategy types
//!
//! | Module | Type | Profile |
//! |--------|------|---------|
//! | [`backoff`] | [`BackoffScheduler`] | LAN, Campus, Static |
//! | [`reactive`] | [`ReactiveScheduler`] | Mobile, low-traffic nodes |
//! | [`passive`] | [`PassiveScheduler`] | HighMobility, dense mesh |
//!
//! ## Factory
//!
//! [`build_strategy`] constructs the right scheduler from a [`DiscoveryConfig`].
//! Pass the result as `Box<dyn NeighborProbeStrategy>` into the protocol
//! constructor; swap it at runtime without restarting the protocol.

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

// ─── ProbeRequest ────────────────────────────────────────────────────────────

/// An action returned by [`NeighborProbeStrategy::on_tick`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeRequest {
    /// Send a hello Interest on the multicast / broadcast face.
    Broadcast,
    /// Send a unicast hello Interest directly to this face.
    Unicast(FaceId),
}

// ─── TriggerEvent ────────────────────────────────────────────────────────────

/// An out-of-band event that informs the strategy and may cause an early probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TriggerEvent {
    /// A new face came up; send a hello immediately to bootstrap the neighbor
    /// table.
    FaceUp,
    /// A forwarding failure occurred (Nack received or no FIB match); re-probe
    /// to verify the affected face is still alive.
    ForwardingFailure,
    /// A neighbor's liveness deadline expired without a hello response; switch
    /// to fast re-probing (`ESTABLISHED → STALE`).
    NeighborStale,
    /// A packet was passively observed from an unknown source MAC.  Only
    /// meaningful for [`PassiveScheduler`].
    PassiveDetection,
}

// ─── NeighborProbeStrategy ───────────────────────────────────────────────────

/// Controls the *when* of hello/probe scheduling.
///
/// # Contract
///
/// - [`on_tick`] is called at a regular interval set by
///   [`DiscoveryConfig::hello_interval_base`].  It returns zero or more
///   [`ProbeRequest`]s to execute this tick.
/// - [`on_probe_success`] is called when a probe response is received.  The
///   strategy may use this to reset its backoff interval or annotate quality
///   measurements.
/// - [`on_probe_timeout`] is called when a pending probe times out.  The
///   strategy advances its failure counter and may escalate the probe rate.
/// - [`trigger`] is called for out-of-band topology events.  The strategy may
///   schedule an immediate probe on the next [`on_tick`] call.
///
/// All methods take `&mut self`; the protocol wraps the strategy in
/// `Mutex<Box<dyn NeighborProbeStrategy>>` so it can be replaced at runtime.
pub trait NeighborProbeStrategy: Send + 'static {
    /// Advance the scheduler's clock to `now`.
    ///
    /// Returns the set of probes that should be sent this tick.  An empty
    /// `Vec` means "nothing to do yet"; the protocol should call this again
    /// on the next tick interval.
    fn on_tick(&mut self, now: Instant) -> Vec<ProbeRequest>;

    /// A probe response was received with the given round-trip time.
    ///
    /// Reset failure counters and back-off intervals.  `rtt` may be used by
    /// adaptive schedulers to tune the next probe interval.
    fn on_probe_success(&mut self, rtt: Duration);

    /// A probe timed out (no response within `probe_timeout`).
    ///
    /// Advance failure counters; escalate probe rate if appropriate.
    fn on_probe_timeout(&mut self);

    /// An external topology event occurred.
    ///
    /// The strategy should arrange for a probe to be scheduled (typically on
    /// the next [`on_tick`]) unless rate-limiting applies.
    fn trigger(&mut self, event: TriggerEvent);
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/// Construct the appropriate [`NeighborProbeStrategy`] for the given config.
///
/// The mapping follows [`HelloStrategyKind`]:
///
/// | Kind | Scheduler |
/// |------|-----------|
/// | `Backoff` | [`BackoffScheduler`] |
/// | `Reactive` | [`ReactiveScheduler`] |
/// | `Passive` | [`PassiveScheduler`] (falls back to backoff when idle) |
/// | `Swim` | [`BackoffScheduler`] (SWIM strategy not yet implemented) |
pub fn build_strategy(cfg: &DiscoveryConfig) -> Box<dyn NeighborProbeStrategy> {
    match cfg.hello_strategy {
        HelloStrategyKind::Backoff => Box::new(BackoffScheduler::from_discovery_config(cfg)),
        HelloStrategyKind::Swim => Box::new(SwimScheduler::from_discovery_config(cfg)),
        HelloStrategyKind::Reactive => Box::new(ReactiveScheduler::from_discovery_config(cfg)),
        HelloStrategyKind::Passive => Box::new(PassiveScheduler::from_discovery_config(cfg)),
    }
}
