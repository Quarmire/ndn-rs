//! # `ndn_faces::local` — Local and IPC faces
//!
//! Face implementations for communication between applications and the NDN
//! forwarder on the same machine.
//!
//! ## Key types
//!
//! - [`InProcFace`] / [`InProcHandle`] — in-process channel pair for library-embedded use
//! - [`UnixFace`] — Unix domain socket face (unix only)
//! - [`IpcFace`] / [`IpcListener`] — cross-platform IPC (Unix sockets on unix,
//!   named pipes on Windows)
//! - [`ShmFace`] / [`ShmHandle`] — shared-memory face for zero-copy local
//!   transport (requires `spsc-shm` feature)

#![allow(missing_docs)]

pub mod in_proc;
pub mod ipc;

#[cfg(unix)]
pub mod unix;

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios")), feature = "spsc-shm"))]
pub mod shm;

pub use in_proc::{InProcFace, InProcHandle};

/// Alias for [`InProcFace`]: the in-process app-to-engine face backed by
/// `tokio::sync::mpsc` (zero syscalls, same-thread or cross-thread).
pub type AppFace = InProcFace;
pub use ipc::{IpcFace, IpcListener, ipc_face_connect};

#[cfg(unix)]
pub use unix::{
    UnixFace, unix_face_connect, unix_face_from_stream, unix_management_face_from_stream,
};

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios")), feature = "spsc-shm"))]
pub use shm::{ShmError, ShmFace, ShmHandle};
