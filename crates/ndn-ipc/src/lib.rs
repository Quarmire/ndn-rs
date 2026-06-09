//! App ↔ router IPC over Unix sockets (and optional SPSC shared-memory
//! rings via `spsc-shm`).
//!
//! [`IpcClient`] / [`IpcServer`] are the Unix-socket endpoints;
//! [`ForwarderClient`] and [`MgmtClient`] are the ergonomic data and
//! control-plane clients; [`ChunkedProducer`] / [`ChunkedConsumer`]
//! handle segmented object transfer; [`ServiceRegistry`] is a local
//! discovery table.

#![allow(missing_docs)]

pub mod blocking;
pub mod chunked;
pub mod client;
// Single-reader demux for the management+data seam (ForwarderClient::from_raw_fd).
mod face_mux;
pub mod forwarder_client;
pub mod mgmt_client;
pub mod registry;
pub mod server;

pub use blocking::BlockingForwarderClient;
pub use chunked::{ChunkedConsumer, ChunkedProducer, NDN_DEFAULT_SEGMENT_SIZE};
pub use client::IpcClient;
pub use forwarder_client::{ForwarderClient, ForwarderError};
pub use mgmt_client::MgmtClient;
pub use registry::ServiceRegistry;
pub use server::IpcServer;
