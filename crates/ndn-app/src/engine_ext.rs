//! Ergonomic in-process registration on an embedded [`ForwarderEngine`].
//!
//! The engine's `faces()` / `fib()` accessors are deliberately low-level (a
//! real forwarder needs them), so embedding an app means a multi-step ritual:
//! allocate a face id, build an [`InProcFace`], add it, install a FIB route
//! with the *matching* id, then wrap the handle in a [`Producer`]. This trait
//! collapses that to one call and keeps face ids out of application code —
//! callers work in prefixes, not plumbing.
//!
//! Lives in `ndn-app` rather than `ndn-engine` because `InProcFace` is a
//! concrete face (in `ndn-face-native`) layered above the core engine; pulling it
//! into `ndn-engine` would invert the dependency.
//!
//! ```no_run
//! use ndn_app::{EngineAppExt, EngineBuilder};
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn ex() -> anyhow::Result<()> {
//! let (engine, _shutdown) = EngineBuilder::new(Default::default()).build().await?;
//! let cancel = CancellationToken::new();
//! let producer = engine.register_producer("/ndn/ble/test", cancel.child_token());
//! # Ok(()) }
//! ```

use ndn_engine::ForwarderEngine;
// Same `InProcFace` type on both targets; the wasm path imports it straight
// from `ndn-face-local` to avoid `ndn-face-native`'s OS-socket transports.
#[cfg(target_arch = "wasm32")]
use ndn_face_local::InProcFace;
#[cfg(not(target_arch = "wasm32"))]
use ndn_face_native::local::InProcFace;
use ndn_packet::Name;
use tokio_util::sync::CancellationToken;

use crate::{Consumer, Producer};

/// Per-app in-process face buffer depth. Matches `MobileEngine`'s default.
const APP_FACE_BUFFER: usize = 256;

/// In-process producer/consumer registration for an embedded engine.
pub trait EngineAppExt {
    /// Allocate an in-process app face, install a FIB route for `prefix`, and
    /// return a [`Producer`] bound to it. `cancel` ties the face's lifetime to
    /// the caller — pass a child of the engine's shutdown token so the face
    /// goes away on shutdown.
    fn register_producer(&self, prefix: impl Into<Name>, cancel: CancellationToken) -> Producer;

    /// Allocate an in-process app face and return a [`Consumer`] over it.
    /// No FIB route is installed (consumers originate Interests, they don't
    /// answer them).
    fn app_consumer(&self, cancel: CancellationToken) -> Consumer;
}

impl EngineAppExt for ForwarderEngine {
    fn register_producer(&self, prefix: impl Into<Name>, cancel: CancellationToken) -> Producer {
        let prefix = prefix.into();
        let face_id = self.faces().alloc_id();
        let (face, handle) = InProcFace::new(face_id, APP_FACE_BUFFER);
        self.add_face(face, cancel);
        self.fib().add_nexthop(&prefix, face_id, 0);
        Producer::from_handle(handle, prefix)
    }

    fn app_consumer(&self, cancel: CancellationToken) -> Consumer {
        let face_id = self.faces().alloc_id();
        let (face, handle) = InProcFace::new(face_id, APP_FACE_BUFFER);
        self.add_face(face, cancel);
        Consumer::from_handle(handle)
    }
}
