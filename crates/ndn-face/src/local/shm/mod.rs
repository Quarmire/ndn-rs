//! Shared-memory NDN faces (Unix, `spsc-shm` feature) — unique to ndn-rs
//! among NDN implementations. A POSIX `shm_open` region carries a lock-free
//! SPSC ring per direction; named FIFOs drive the wakeup path.
//!
//! `ShmFace` is the engine side (register with `ForwarderEngine::add_face`);
//! `ShmHandle` is the application side.
//!
//! ```no_run
//! # use ndn_face::local::shm::{ShmFace, ShmHandle};
//! # use ndn_transport::FaceId;
//! let face = ShmFace::create(FaceId(5), "myapp").unwrap();
//! let handle = ShmHandle::connect("myapp").unwrap();
//! ```

#[cfg(all(unix, feature = "spsc-shm"))]
pub mod spsc;

/// Re-export of [`spsc::slot_size_for_mtu`] for callers that don't depend
/// on the `spsc` submodule directly.
#[cfg(all(unix, feature = "spsc-shm"))]
pub fn slot_size_for_mtu(mtu: usize) -> u32 {
    spsc::slot_size_for_mtu(mtu)
}

#[derive(Debug, thiserror::Error)]
pub enum ShmError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SHM name contains an interior NUL byte")]
    InvalidName,
    #[error("SHM region has wrong magic number (stale or wrong name?)")]
    InvalidMagic,
    #[error("packet exceeds the SHM slot size")]
    PacketTooLarge,
    #[error("SHM face closed (peer died or cancelled)")]
    Closed,
}

#[cfg(all(unix, feature = "spsc-shm"))]
pub type ShmFace = spsc::SpscFace;

#[cfg(all(unix, feature = "spsc-shm"))]
pub type ShmHandle = spsc::SpscHandle;
