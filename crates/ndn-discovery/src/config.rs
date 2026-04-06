//! Discovery configuration — deployment profiles and per-parameter tuning.
//!
//! [`DiscoveryProfile`] captures deployment intent; [`DiscoveryConfig`] holds
//! the concrete numeric parameters.  Callers pick a profile and optionally
//! override individual fields.

use std::time::Duration;

use ndn_packet::Name;

// ─── HelloStrategyKind ────────────────────────────────────────────────────────

/// Which probe-scheduling algorithm a discovery protocol builds when
/// constructed from a [`DiscoveryConfig`].
///
/// This controls *when* hellos are sent; the state machine (face creation,
/// FIB wiring, neighbor table) is independent and stays in the protocol impl.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelloStrategyKind {
    /// Exponential backoff with jitter.  Default for most deployments.
    Backoff,
    /// Event-driven only — no timer.  Sends hellos only on topology events
    /// (face up, forwarding failure, neighbor going stale).
    Reactive,
    /// Passive MAC overhearing.  Sends hellos only when unknown source MACs
    /// are observed; falls back to occasional backoff probing when quiet.
    Passive,
    /// SWIM-style direct + indirect probing.  Not yet fully implemented;
    /// falls back to [`Backoff`](Self::Backoff) until `strategy/swim.rs` is complete.
    Swim,
}

// ─── PrefixAnnouncementMode ───────────────────────────────────────────────────

/// How this node announces its own prefixes to neighbours.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixAnnouncementMode {
    /// Static configuration only; no automatic announcements.
    Static,
    /// Prefix list carried in the `SERVED-PREFIX` fields of every Hello Data.
    InHello,
    /// LSA-style routing (NLSR adapter, future work).
    NlsrLsa,
}

// ─── DiscoveryConfig ──────────────────────────────────────────────────────────

/// Concrete discovery parameters.
///
/// Obtain via [`DiscoveryConfig::for_profile`] and adjust as needed,
/// or construct from scratch for fully custom deployments.
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Probe-scheduling algorithm.
    pub hello_strategy: HelloStrategyKind,
    /// Initial hello interval (fast bootstrap).
    pub hello_interval_base: Duration,
    /// Maximum hello interval after full exponential backoff.
    pub hello_interval_max: Duration,
    /// Fractional jitter applied to each hello interval (0.0–0.5).
    /// `0.25` means ±25 % of the current interval is added as random noise.
    pub hello_jitter: f32,
    /// How long without a hello response before `Established → Stale`.
    pub liveness_timeout: Duration,
    /// Consecutive missed hellos before `Stale → Absent` (face/FIB removal).
    pub liveness_miss_count: u32,
    /// How long to wait for a hello response before declaring a probe lost.
    pub probe_timeout: Duration,
    /// SWIM indirect-probe fanout K (0 = SWIM disabled).
    pub swim_indirect_fanout: u32,
    /// Emergency gossip-broadcast fanout K (0 = disabled).
    /// When a neighbor goes Stale, K unicast hellos are sent to other
    /// established peers so they can independently verify the failure.
    pub gossip_fanout: u32,
    /// Prefix announcement mode.
    pub prefix_announcement: PrefixAnnouncementMode,
    /// Automatically create unicast faces for discovered peers.
    pub auto_create_faces: bool,
    /// How often the engine calls `DiscoveryProtocol::on_tick`.
    /// Smaller values improve responsiveness at the cost of CPU overhead.
    /// Default: 100 ms.
    pub tick_interval: Duration,
}

impl DiscoveryConfig {
    /// Build the default config for the given deployment profile.
    pub fn for_profile(profile: &DiscoveryProfile) -> Self {
        match profile {
            DiscoveryProfile::Static => Self::static_routes(),
            DiscoveryProfile::Lan => Self::lan(),
            DiscoveryProfile::Campus => Self::campus(),
            DiscoveryProfile::Mobile => Self::mobile(),
            DiscoveryProfile::HighMobility => Self::high_mobility(),
            DiscoveryProfile::Asymmetric => Self::asymmetric(),
            DiscoveryProfile::Custom(c) => c.clone(),
        }
    }

    /// Static routing — no hello traffic at all.
    fn static_routes() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Backoff,
            hello_interval_base: Duration::from_secs(3600),
            hello_interval_max: Duration::from_secs(3600),
            hello_jitter: 0.0,
            liveness_timeout: Duration::MAX,
            liveness_miss_count: u32::MAX,
            probe_timeout: Duration::from_secs(5),
            swim_indirect_fanout: 0,
            gossip_fanout: 0,
            prefix_announcement: PrefixAnnouncementMode::Static,
            auto_create_faces: false,
            tick_interval: Duration::from_secs(1),
        }
    }

    /// Link-local LAN: stable topology, low overhead.
    ///
    /// # Liveness invariant
    ///
    /// `liveness_timeout` (30 s) must exceed `hello_interval_max × (1 + jitter)`
    /// so that a healthy peer at full backoff never triggers a false Stale
    /// transition.  With `hello_interval_max = 20 s` and `jitter = 0.25`:
    /// `20 × 1.25 = 25 s < 30 s` ✓
    ///
    /// Failure detection: `liveness_timeout × liveness_miss_count = 90 s`
    /// from the last received hello.
    fn lan() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Backoff,
            hello_interval_base: Duration::from_secs(5),
            hello_interval_max: Duration::from_secs(20),
            hello_jitter: 0.25,
            liveness_timeout: Duration::from_secs(30),
            liveness_miss_count: 3,
            probe_timeout: Duration::from_secs(5),
            swim_indirect_fanout: 0,
            gossip_fanout: 0,
            prefix_announcement: PrefixAnnouncementMode::InHello,
            auto_create_faces: true,
            tick_interval: Duration::from_millis(500),
        }
    }

    /// Campus / enterprise: mix of stable and dynamic peers.
    ///
    /// # Liveness invariant
    ///
    /// `liveness_timeout` (120 s) must exceed `hello_interval_max × (1 + jitter)`.
    /// With `hello_interval_max = 100 s` and `jitter = 0.10`:
    /// `100 × 1.10 = 110 s < 120 s` ✓
    ///
    /// Failure detection: `120 s × 3 = 360 s` (~6 min).
    fn campus() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Backoff,
            hello_interval_base: Duration::from_secs(30),
            hello_interval_max: Duration::from_secs(100),
            hello_jitter: 0.10,
            liveness_timeout: Duration::from_secs(120),
            liveness_miss_count: 3,
            probe_timeout: Duration::from_secs(10),
            swim_indirect_fanout: 3,
            gossip_fanout: 3,
            prefix_announcement: PrefixAnnouncementMode::NlsrLsa,
            auto_create_faces: true,
            tick_interval: Duration::from_millis(500),
        }
    }

    /// Mobile / vehicular: topology changes at human-movement timescales.
    ///
    /// # Liveness invariant
    ///
    /// `liveness_timeout` (3 s) must exceed `hello_interval_max × (1 + jitter)`.
    /// With `hello_interval_max = 2 s` and `jitter = 0.15`:
    /// `2 × 1.15 = 2.3 s < 3 s` ✓
    ///
    /// Failure detection: `3 s × 5 = 15 s`.
    fn mobile() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Reactive,
            hello_interval_base: Duration::from_millis(200),
            hello_interval_max: Duration::from_secs(2),
            hello_jitter: 0.15,
            liveness_timeout: Duration::from_secs(3),
            liveness_miss_count: 5,
            probe_timeout: Duration::from_millis(500),
            swim_indirect_fanout: 3,
            gossip_fanout: 5,
            prefix_announcement: PrefixAnnouncementMode::InHello,
            auto_create_faces: true,
            tick_interval: Duration::from_millis(50),
        }
    }

    /// High-mobility (drones, V2X): sub-second topology changes.
    ///
    /// # Liveness invariant
    ///
    /// `liveness_timeout` (750 ms) must exceed `hello_interval_max × (1 + jitter)`.
    /// With `hello_interval_max = 500 ms` and `jitter = 0.10`:
    /// `500 × 1.10 = 550 ms < 750 ms` ✓
    ///
    /// Failure detection: `750 ms × 3 = 2.25 s`.
    fn high_mobility() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Passive,
            hello_interval_base: Duration::from_millis(50),
            hello_interval_max: Duration::from_millis(500),
            hello_jitter: 0.10,
            liveness_timeout: Duration::from_millis(750),
            liveness_miss_count: 3,
            probe_timeout: Duration::from_millis(200),
            swim_indirect_fanout: 5,
            gossip_fanout: 5,
            prefix_announcement: PrefixAnnouncementMode::InHello,
            auto_create_faces: true,
            tick_interval: Duration::from_millis(20),
        }
    }

    /// Asymmetric / unidirectional link (Wifibroadcast, satellite downlink).
    fn asymmetric() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Passive,
            hello_interval_base: Duration::from_secs(5),
            hello_interval_max: Duration::from_secs(30),
            hello_jitter: 0.10,
            liveness_timeout: Duration::from_secs(60),
            liveness_miss_count: 3,
            probe_timeout: Duration::from_secs(10),
            swim_indirect_fanout: 0,
            gossip_fanout: 0,
            prefix_announcement: PrefixAnnouncementMode::Static,
            auto_create_faces: false,
            tick_interval: Duration::from_millis(500),
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self::lan()
    }
}

// ─── DiscoveryProfile ─────────────────────────────────────────────────────────

/// High-level deployment profiles mapping to tuned [`DiscoveryConfig`] sets.
#[derive(Clone, Debug, Default)]
pub enum DiscoveryProfile {
    /// No discovery.  FIB and faces configured statically.
    Static,
    /// Link-local LAN (home, small office).
    #[default]
    Lan,
    /// Campus or enterprise network.
    Campus,
    /// Mobile / vehicular network.
    Mobile,
    /// High-mobility (drones, V2X).
    HighMobility,
    /// Asymmetric unidirectional link (Wifibroadcast, satellite downlink).
    Asymmetric,
    /// Fully custom parameters.
    Custom(DiscoveryConfig),
}

// ─── ServiceDiscoveryConfig ───────────────────────────────────────────────────

/// Scope at which service records are consumed or propagated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryScope {
    /// `/ndn/local/` — never forwarded beyond the local link.
    LinkLocal,
    /// `/ndn/site/` — distributed within an administrative domain.
    Site,
    /// `/ndn/global/` — federated global registry.
    Global,
}

/// Validation policy for incoming service records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceValidationPolicy {
    /// No validation.  Accept any record.  Fast; for closed networks.
    Skip,
    /// Log unsigned/unverified records but act on them anyway.
    WarnOnly,
    /// Drop unsigned records; only auto-populate FIB from verified Data.
    Required,
}

/// Configuration for the service-discovery layer (`/ndn/local/sd/`).
#[derive(Clone, Debug)]
pub struct ServiceDiscoveryConfig {
    /// Automatically add FIB entries when service records arrive.
    pub auto_populate_fib: bool,
    /// Restrict auto-population to this scope.
    pub auto_populate_scope: DiscoveryScope,
    /// Route cost for auto-populated FIB entries (should exceed manual routes).
    pub auto_fib_cost: u32,
    /// Auto-populated entries expire after `freshness_period × multiplier`.
    pub auto_fib_ttl_multiplier: f32,
    /// Only auto-populate for these prefixes (empty = accept any).
    pub auto_populate_prefix_filter: Vec<Name>,
    /// Maximum service records per scope prefix.
    pub max_records_per_scope: usize,
    /// Max registrations per producer per time window (rate limiting).
    pub max_registrations_per_producer: u32,
    /// Time window for the per-producer rate limit.
    pub max_registrations_window: Duration,
    /// Whether to relay service records received from peers.
    pub relay_records: bool,
    /// Validation policy for incoming service records.
    pub validation: ServiceValidationPolicy,
}

impl Default for ServiceDiscoveryConfig {
    fn default() -> Self {
        Self {
            auto_populate_fib: true,
            auto_populate_scope: DiscoveryScope::LinkLocal,
            auto_fib_cost: 100,
            auto_fib_ttl_multiplier: 2.0,
            auto_populate_prefix_filter: Vec::new(),
            max_records_per_scope: 1000,
            max_registrations_per_producer: 10,
            max_registrations_window: Duration::from_secs(60),
            relay_records: false,
            validation: ServiceValidationPolicy::Skip,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_profile_has_backoff() {
        let cfg = DiscoveryConfig::for_profile(&DiscoveryProfile::Lan);
        assert_eq!(cfg.hello_strategy, HelloStrategyKind::Backoff);
        assert!(cfg.auto_create_faces);
        assert!(cfg.hello_interval_base < cfg.hello_interval_max);
    }

    #[test]
    fn mobile_profile_is_reactive() {
        let cfg = DiscoveryConfig::for_profile(&DiscoveryProfile::Mobile);
        assert_eq!(cfg.hello_strategy, HelloStrategyKind::Reactive);
        assert!(cfg.hello_interval_base < Duration::from_secs(1));
    }

    #[test]
    fn custom_profile_roundtrips() {
        let mut custom = DiscoveryConfig::for_profile(&DiscoveryProfile::Lan);
        custom.liveness_miss_count = 7;
        let profile = DiscoveryProfile::Custom(custom.clone());
        let out = DiscoveryConfig::for_profile(&profile);
        assert_eq!(out.liveness_miss_count, 7);
    }

    #[test]
    fn static_profile_never_expires() {
        let cfg = DiscoveryConfig::for_profile(&DiscoveryProfile::Static);
        assert!(!cfg.auto_create_faces);
        assert_eq!(cfg.liveness_miss_count, u32::MAX);
    }
}
