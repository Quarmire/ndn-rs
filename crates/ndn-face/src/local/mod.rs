//! Local and IPC NDN faces: [`InProcFace`] / [`InProcHandle`] (in-process
//! channel pair), [`UnixFace`], [`IpcFace`] / [`IpcListener`] (Unix sockets
//! or Windows named pipes), and [`ShmFace`] / [`ShmHandle`] (zero-copy
//! shared memory; `spsc-shm` feature, unique to ndn-rs).

#![allow(missing_docs)]

// `in_proc` lives in the standalone `ndn-face-local` crate so wasm32
// consumers can depend on the channel-based face without pulling in
// `ndn-face-native`'s OS-socket transports.
pub use ndn_face_local as in_proc;
pub mod ipc;

#[cfg(unix)]
pub mod unix;

#[cfg(all(
    unix,
    not(any(target_os = "android", target_os = "ios")),
    feature = "spsc-shm"
))]
pub mod shm;

pub use in_proc::{InProcFace, InProcHandle};

pub type AppFace = InProcFace;
pub use ipc::{IpcFace, IpcListener, ipc_face_connect};
#[cfg(unix)]
pub use ipc::ipc_face_from_raw_fd;

#[cfg(unix)]
pub use unix::{
    UnixFace, unix_face_connect, unix_face_from_stream, unix_management_face_from_stream,
};

#[cfg(all(
    unix,
    not(any(target_os = "android", target_os = "ios")),
    feature = "spsc-shm"
))]
pub use shm::{ShmError, ShmFace, ShmHandle};
