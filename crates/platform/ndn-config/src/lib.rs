//! TOML forwarder configuration and the NFD-compatible management
//! protocol (faces, routes, strategies).
//!
//! Key types: [`ForwarderConfig`], [`ControlParameters`],
//! [`nfd_command::ParsedCommand`]. Runtime-mutable fields use
//! `Arc<RwLock<T>>` per the workspace convention.

#![allow(missing_docs)]

// `ndn_engine::EngineConfig` / `EngineBuilder` are native-only.
#[cfg(all(feature = "boot", not(target_arch = "wasm32")))]
pub mod boot;
#[cfg(feature = "ca-policy")]
pub mod ca_policy;
pub mod config;
pub mod error;
pub mod mgmt;
#[cfg(feature = "mgmt")]
mod mgmt_config_impl;
pub mod notifications;

// The NFD management WIRE codecs (ControlParameters / ControlResponse / the
// command + dataset formats) moved to ndn-mgmt-wire (spec), so the spec crates
// that consume them depend on a spec crate, not this forwarder-TOML extension.
// Re-exported here — modules and types — so existing `ndn_config::` consumers
// keep compiling unchanged.
pub use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, FaceStatus, FibEntry, NextHopRecord, ParsedCommand,
    RibEntry, Route, StrategyChoice, command_name, dataset_name, parse_cert_sha256_hex,
    parse_command_name,
};
pub use ndn_mgmt_wire::{control_parameters, control_response, nfd_command, nfd_dataset};

pub use config::{
    AcmeTomlConfig, CaRelayConfig, CaTomlConfig, CertSourceConfig, CertValidityDays,
    ChallengeConfig, CsConfig, DirectConfig, DiscoveryTomlConfig, EngineConfig, FaceConfig,
    FaceKind, ForwarderConfig, LinkModeConfig, LinksConfig, ListenersConfig, LoggingConfig,
    ManagementConfig, MgmtSecurityConfig, NlsrNeighborConfig, NlsrTomlConfig,
    ObservabilityTomlConfig, PeerConfig, QuotasConfig, RadioDeviceConfig, ReflexiveTomlConfig,
    RelayConfig, RelayServiceConfig, RelaysConfig, RenewBeforeConfig, RequireAttestationConfig,
    RouteConfig, RoutingTomlConfig, SecurityConfig, SelfSignedDevConfig, ServeConfig, SmtpConfig,
    StrategyConfig, TrustRuleConfig, WebRtcListenerConfig, WebTransportListenerConfig,
    WtIceServers, WtTurnServer,
};
pub use error::ConfigError;
pub use notifications::NotificationStream;
