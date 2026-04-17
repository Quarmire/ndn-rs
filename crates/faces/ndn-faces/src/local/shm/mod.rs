//! Shared-memory NDN faces.
//!
//! The `spsc-shm` feature (Unix only, enabled by default on Unix targets)
//! provides a custom lock-free SPSC ring buffer in a POSIX `shm_open` region,
//! with Unix datagram sockets for wakeup.
//!
//! Both types expose the same pair of types: `ShmFace` (engine side) and
//! `ShmHandle` (application side).  The engine registers `ShmFace` via
//! `ForwarderEngine::add_face`; the application uses `ShmHandle` to send and
//! receive NDN packets over shared memory.
//!
//! # Quick start
//!
//! ```no_run
//! # use ndn_faces::local::shm::{ShmFace, ShmHandle};
//! # use ndn_transport::FaceId;
//! // ── Engine process ────────────────────────────────────────────────────────
//! let face = ShmFace::create(FaceId(5), "myapp").unwrap();
//! // engine.add_face(face, cancel);
//!
//! // ── Application process ───────────────────────────────────────────────────
//! let handle = ShmHandle::connect("myapp").unwrap();
//! // handle.send(interest_bytes).await?;
//! // let data = handle.recv().await?;
//! ```

#[cfg(all(unix, feature = "spsc-shm"))]
pub mod spsc;

/// Compute the slot_size required to carry a Data packet whose content
/// can be up to `mtu` bytes. Mirrors [`spsc::slot_size_for_mtu`] so
/// callers that don't depend on the `spsc` submodule can still derive
/// a correct SHM ring sizing.
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

/// Engine-side SHM face — register with `ForwarderEngine::add_face`.
#[cfg(all(unix, feature = "spsc-shm"))]
pub type ShmFace = spsc::SpscFace;

/// Application-side SHM handle.
#[cfg(all(unix, feature = "spsc-shm"))]
pub type ShmHandle = spsc::SpscHandle;
