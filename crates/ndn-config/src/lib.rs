//! TOML forwarder configuration and the NFD-compatible management
//! protocol (faces, routes, strategies).
//!
//! Key types: [`ForwarderConfig`], [`ControlParameters`],
//! [`nfd_command::ParsedCommand`]. Runtime-mutable fields use
//! `Arc<RwLock<T>>` per the workspace convention.

#![allow(missing_docs)]

pub mod config;
pub mod control_parameters;
pub mod control_response;
pub mod error;
pub mod mgmt;
pub mod nfd_command;
pub mod nfd_dataset;
pub mod notifications;

pub use config::{
    ChallengeConfig, CsConfig, DemoCaConfig, DiscoveryTomlConfig, EngineConfig, FaceConfig,
    FaceKind, SmtpConfig,
    ForwarderConfig, ListenersConfig, LoggingConfig, ManagementConfig, MgmtSecurityConfig,
    NlsrNeighborConfig, NlsrTomlConfig, ObservabilityTomlConfig, ReflexiveTomlConfig,
    QuicListenerConfig, RequireAttestationConfig, RouteConfig, RoutingTomlConfig, SecurityConfig,
    TrustRuleConfig, WebRtcListenerConfig, WebTransportListenerConfig, WtAcmeConfig, WtCertSource,
    WtIceServers, WtSelfSignedDev, WtTurnServer, parse_cert_sha256_hex,
};
pub use control_parameters::ControlParameters;
pub use control_response::ControlResponse;
pub use error::ConfigError;
pub use nfd_command::{ParsedCommand, command_name, dataset_name, parse_command_name};
pub use nfd_dataset::{FaceStatus, FibEntry, NextHopRecord, RibEntry, Route, StrategyChoice};
pub use notifications::NotificationStream;
