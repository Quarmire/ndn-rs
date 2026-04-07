//! # ndn-face-local — Local and IPC faces for NDN
//!
//! Provides face implementations for communication between applications and
//! the NDN forwarder on the same machine.
//!
//! ## Key types
//!
//! - [`AppFace`] / [`AppHandle`] — in-process channel pair for library-embedded use
//! - [`UnixFace`] — Unix domain socket face (unix only)
//! - [`IpcFace`] / [`IpcListener`] — cross-platform IPC (Unix sockets on unix, named pipes on Windows)
//! - [`ShmFace`] / [`ShmHandle`] — shared-memory face for zero-copy local transport (requires `spsc-shm` feature)
//!
//! ## Features
//!
//! - **`spsc-shm`** (optional) — enables [`ShmFace`] for high-throughput shared-memory communication.

#![allow(missing_docs)]

pub mod app;
pub mod ipc;

#[cfg(unix)]
pub mod unix;

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios")), feature = "spsc-shm"))]
pub mod shm;

pub use app::{AppFace, AppHandle};
pub use ipc::{IpcFace, IpcListener, ipc_face_connect};

#[cfg(unix)]
pub use unix::{
    UnixFace, unix_face_connect, unix_face_from_stream, unix_management_face_from_stream,
};

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios")), feature = "spsc-shm"))]
pub use shm::{ShmError, ShmFace, ShmHandle};
