//! IndexedDB-backed PIB for browser-tier ndn-rs. Stores SafeBags
//! (cert + PBES2-encrypted private key) and trust anchors, both
//! keyed by the NDN name URI; per-origin isolation comes from
//! IndexedDB's origin scoping. Native builds compile to a stub —
//! native targets use `FilePib`.

#![deny(rust_2018_idioms)]

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::{IdbPib, IdbPibError};

#[cfg(not(target_arch = "wasm32"))]
mod native_stub;
#[cfg(not(target_arch = "wasm32"))]
pub use native_stub::{IdbPib, IdbPibError};
