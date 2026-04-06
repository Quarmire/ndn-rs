pub mod app;

#[cfg(unix)]
pub mod unix;

#[cfg(all(unix, feature = "spsc-shm"))]
pub mod shm;

pub use app::{AppFace, AppHandle};

#[cfg(unix)]
pub use unix::{UnixFace, unix_face_connect, unix_face_from_stream, unix_management_face_from_stream};

#[cfg(all(unix, feature = "spsc-shm"))]
pub use shm::{ShmError, ShmFace, ShmHandle};
