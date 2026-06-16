//! [`FaceSink`] — the seam between face *provisioning* (interface enumeration,
//! auto-multicast, hotplug) and the *engine* that owns the face table.
//!
//! Provisioning logic lives in `ndn-face-native` (it owns the concrete
//! multicast faces and the OS interface watcher) but must add faces to, and
//! remove them from, whatever engine is hosting it. Rather than couple the
//! provisioner to a concrete `ForwarderEngine`, it is written against this
//! trait, which `ForwarderEngine` (and therefore any engine embedding one —
//! the native forwarder, the mobile engine, the in-browser engine) implements.
//!
//! `install_transport` is generic rather than `dyn`-erased so it can accept any
//! [`Transport`] without boxing through the (async, non-object-safe) trait;
//! the trait as a whole is consumed by generic provisioner code, never as a
//! trait object.

use tokio_util::sync::CancellationToken;

use crate::{FaceId, FacePersistency, Transport};

/// An engine that can have faces installed into and removed from its face
/// table by an external provisioner. See the module docs.
pub trait FaceSink: Clone + Send + Sync + 'static {
    /// Allocate a fresh, never-recycled face id (monotonic, mirrors NFD).
    fn alloc_face_id(&self) -> FaceId;

    /// Install a transport as a managed face: compose its default link
    /// service, spawn its reader/writer tasks, and publish lifecycle events.
    /// Equivalent to the engine's `add_face_with_persistency`.
    fn install_transport<T: Transport + 'static>(
        &self,
        face: T,
        cancel: CancellationToken,
        persistency: FacePersistency,
    );

    /// Currently-installed face ids (for hotplug teardown).
    fn installed_face_ids(&self) -> Vec<FaceId>;

    /// The face's local URI, e.g. `dev://eth0` for an interface-bound face.
    fn face_local_uri(&self, id: FaceId) -> Option<String>;

    /// Cancel a face's tasks, tearing it down (used when its interface goes
    /// away). No-op if the id is unknown.
    fn cancel_face(&self, id: FaceId);
}
