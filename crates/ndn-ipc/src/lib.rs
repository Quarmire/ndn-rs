//! # ndn-ipc -- Inter-process communication transport
//!
//! Connects application processes to the NDN router over Unix sockets and
//! (optionally) shared-memory ring buffers. Handles chunked transfer for
//! large objects and service discovery via a local registry.
//!
//! ## Key types
//!
//! - [`IpcClient`] / [`IpcServer`] -- Unix-socket connection endpoints
//! - [`ForwarderClient`] -- ergonomic client for app-to-router communication
//! - [`MgmtClient`] -- management/control-plane client
//! - [`ChunkedProducer`] / [`ChunkedConsumer`] -- segmented object transfer
//! - [`ServiceRegistry`] -- local service advertisement and lookup
//!
//! ## Feature flags
//!
//! - **`spsc-shm`** (default) -- enables SPSC shared-memory ring-buffer transport

#![allow(missing_docs)]

pub mod chunked;
pub mod client;
pub mod mgmt_client;
pub mod registry;
pub mod forwarder_client;
pub mod server;

pub use chunked::{ChunkedConsumer, ChunkedProducer};
pub use client::IpcClient;
pub use mgmt_client::MgmtClient;
pub use registry::ServiceRegistry;
pub use forwarder_client::ForwarderClient;
pub use server::IpcServer;
