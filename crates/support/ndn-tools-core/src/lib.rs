//! `ndn-tools-core` — embeddable NDN tool logic.
//!
//! Each tool is gated behind a Cargo feature of the same name.
//! Enable only the tools you need; the dashboard enables a subset,
//! while the standalone `ndn-tools` binary enables all of them.
//!
//! ## Usage
//!
//! ```toml
//! [dependencies]
//! ndn-tools-core = { version = "0.1", features = ["ping", "iperf"] }
//! ```
//!
//! All tool functions share the same streaming API:
//! - Accept typed `*Params` structs
//! - Emit [`ToolEvent`]s over a `tokio::sync::mpsc::Sender`
//! - Return `anyhow::Result<()>` when done (or on error)
//! - Cancel cleanly when the task is aborted or the sender is dropped

pub mod common;
pub use common::{ConnectConfig, EventLevel, ToolData, ToolEvent};

#[cfg(feature = "ping")]
pub mod ping;

#[cfg(feature = "iperf")]
pub mod iperf;

#[cfg(feature = "peek")]
pub mod peek;

#[cfg(feature = "put")]
pub mod put;

