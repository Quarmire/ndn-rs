pub mod app;

#[cfg(unix)]
pub mod unix;

#[cfg(any(feature = "spsc-shm", feature = "iceoryx2-shm"))]
pub mod shm;

pub use app::{AppFace, AppHandle};

#[cfg(unix)]
pub use unix::UnixFace;

#[cfg(any(feature = "spsc-shm", feature = "iceoryx2-shm"))]
pub use shm::{ShmError, ShmFace, ShmHandle};
