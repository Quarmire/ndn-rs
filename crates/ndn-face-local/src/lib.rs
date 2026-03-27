pub mod app;

#[cfg(unix)]
pub mod unix;

#[cfg(all(unix, feature = "spsc-shm"))]
pub mod shm;

pub use app::{AppFace, AppHandle};

#[cfg(unix)]
pub use unix::UnixFace;

#[cfg(all(unix, feature = "spsc-shm"))]
pub use shm::{ShmError, ShmFace, ShmHandle};
