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
//! # use ndn_face_local::shm::{ShmFace, ShmHandle};
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

// ─── Unified error type ───────────────────────────────────────────────────────

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
}

// ─── Type aliases ─────────────────────────────────────────────────────────────

/// Engine-side SHM face — register with `ForwarderEngine::add_face`.
#[cfg(all(unix, feature = "spsc-shm"))]
pub type ShmFace = spsc::SpscFace;

/// Application-side SHM handle.
#[cfg(all(unix, feature = "spsc-shm"))]
pub type ShmHandle = spsc::SpscHandle;
