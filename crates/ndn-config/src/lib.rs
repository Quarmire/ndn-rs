//! # ndn-config -- Configuration and management protocol
//!
//! Parses TOML-based forwarder configuration and implements the NFD-compatible
//! management protocol for runtime control of faces, routes, and strategies.
//!
//! ## Key types
//!
//! - [`ForwarderConfig`] -- top-level TOML configuration (faces, routes, CS, logging)
//! - [`ControlParameters`] -- structured parameters for NFD management commands
//! - [`ParsedCommand`] -- result of parsing an NFD command name

#![allow(missing_docs)]

pub mod config;
pub mod control_parameters;
pub mod control_response;
pub mod error;
pub mod mgmt;
pub mod nfd_command;

pub use config::{
    CsConfig, DiscoveryTomlConfig, EngineConfig, FaceConfig, FaceKind, ForwarderConfig,
    LoggingConfig, ManagementConfig, RouteConfig, SecurityConfig,
};
pub use control_parameters::ControlParameters;
pub use control_response::ControlResponse;
pub use error::ConfigError;
pub use nfd_command::{ParsedCommand, command_name, dataset_name, parse_command_name};
