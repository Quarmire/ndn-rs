//! Shared-memory NDN faces.
//!
//! Two backends are available, selected at compile time by Cargo features:
//!
//! - **`spsc-shm`** (Unix only, default): a custom lock-free SPSC ring buffer
//!   in a POSIX `shm_open` region, with Unix datagram sockets for wakeup.
//! - **`iceoryx2-shm`**: iceoryx2 publish-subscribe; cross-platform, zero-copy.
//!
//! Both backends expose the same pair of types: `ShmFace` (engine side) and
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

#[cfg(feature = "iceoryx2-shm")]
pub mod iox2;

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
    #[error("iceoryx2 error: {0}")]
    Iox2(String),
}

// ─── Backend dispatch ─────────────────────────────────────────────────────────
//
// When iceoryx2-shm is enabled it takes precedence; the SPSC backend is still
// accessible as `spsc::SpscFace` / `spsc::SpscHandle` when spsc-shm is also on.

/// Engine-side SHM face — register with `ForwarderEngine::add_face`.
///
/// The backend is selected by the active Cargo feature:
/// - `iceoryx2-shm` → `iox2::Iox2Face`
/// - `spsc-shm` (default) → `spsc::SpscFace`
#[cfg(feature = "iceoryx2-shm")]
pub type ShmFace = iox2::Iox2Face;

#[cfg(all(unix, feature = "spsc-shm", not(feature = "iceoryx2-shm")))]
pub type ShmFace = spsc::SpscFace;

/// Application-side SHM handle.
#[cfg(feature = "iceoryx2-shm")]
pub type ShmHandle = iox2::Iox2Handle;

#[cfg(all(unix, feature = "spsc-shm", not(feature = "iceoryx2-shm")))]
pub type ShmHandle = spsc::SpscHandle;
