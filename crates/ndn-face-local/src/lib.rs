pub mod app;

pub use app::{AppFace, AppHandle};

// Unix domain socket face — only available on Unix-family targets.
// On Windows and WASM this module is not compiled at all.
#[cfg(unix)]
pub mod unix;

#[cfg(unix)]
pub use unix::UnixFace;
