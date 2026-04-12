//! NDN dataset synchronisation protocols.
//!
//! Provides both the low-level data structures ([`svs::SvsNode`], [`psync::PSyncNode`])
//! and the high-level network protocol layer ([`svs_sync::join_svs_group`]) that
//! wires them to actual Interest/Data exchange.
//!
//! # Architecture
//!
//! ```text
//! Application
//!   └── SyncHandle (recv updates, publish names)
//!         └── svs_sync / psync_sync (background task)
//!               └── SvsNode / PSyncNode (pure data structure)
//! ```

#![allow(missing_docs)]

/// Sync protocol abstraction — [`SyncHandle`](protocol::SyncHandle),
/// [`SyncUpdate`](protocol::SyncUpdate), [`SyncError`](protocol::SyncError).
pub mod protocol;

/// State Vector Sync (SVS) — pure data structure.
pub mod svs;

/// SVS network protocol — wires `SvsNode` to Interest/Data exchange.
pub mod svs_sync;

/// Partial Sync (PSync) — IBF-based dataset synchronisation (pure data structure).
pub mod psync;

/// PSync network protocol — wires `PSyncNode` + `Ibf` to Interest/Data exchange.
pub mod psync_sync;

pub use protocol::{SyncError, SyncHandle, SyncUpdate};
pub use psync_sync::{PSyncConfig, join_psync_group};
pub use svs_sync::{RetryPolicy, SvsConfig, fetch_with_retry, join_svs_group};
