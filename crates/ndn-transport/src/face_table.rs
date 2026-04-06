use dashmap::DashMap;
use std::sync::{Arc, Mutex};

use crate::{Face, FaceId};

/// Concurrent map from `FaceId` to a type-erased face handle.
///
/// Pipeline stages clone the `Arc<dyn ErasedFace>` out of the table and
/// release the table reference before calling `send()`, so no lock is held
/// during I/O.
///
/// Face IDs are recycled: when a face is removed its ID is returned to a free
/// list and reused by the next `alloc_id()` call.  Reserved IDs
/// (`>= 0xFFFF_0000`) are never allocated by `alloc_id()` and are used for
/// internal engine faces (e.g. the management `AppFace`).
pub struct FaceTable {
    faces: DashMap<FaceId, Arc<dyn ErasedFace>>,
    next_id: std::sync::atomic::AtomicU32,
    free: Mutex<Vec<u32>>,
}

/// Object-safe wrapper around the `Face` trait so it can be stored in a `DashMap`.
pub trait ErasedFace: Send + Sync + 'static {
    fn id(&self) -> FaceId;
    fn kind(&self) -> crate::face::FaceKind;
    fn remote_uri(&self) -> Option<String>;
    fn local_uri(&self) -> Option<String>;
    fn send_bytes(
        &self,
        pkt: bytes::Bytes,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::face::FaceError>> + Send + '_>,
    >;
    fn recv_bytes(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<bytes::Bytes, crate::face::FaceError>>
                + Send
                + '_,
        >,
    >;

    /// Object-safe version of [`Face::recv_with_addr`].
    ///
    /// Returns the raw packet together with the link-layer sender address
    /// when the face type exposes it (e.g. multicast UDP). Returns `None`
    /// for faces that receive from a single known peer.
    fn recv_bytes_with_addr(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(bytes::Bytes, Option<std::net::SocketAddr>), crate::face::FaceError>,
                > + Send
                + '_,
        >,
    >;
}

impl<F: Face> ErasedFace for F {
    fn id(&self) -> FaceId {
        Face::id(self)
    }

    fn kind(&self) -> crate::face::FaceKind {
        Face::kind(self)
    }

    fn remote_uri(&self) -> Option<String> {
        Face::remote_uri(self)
    }

    fn local_uri(&self) -> Option<String> {
        Face::local_uri(self)
    }

    fn send_bytes(
        &self,
        pkt: bytes::Bytes,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::face::FaceError>> + Send + '_>,
    > {
        Box::pin(Face::send(self, pkt))
    }

    fn recv_bytes(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<bytes::Bytes, crate::face::FaceError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(Face::recv(self))
    }

    fn recv_bytes_with_addr(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(bytes::Bytes, Option<std::net::SocketAddr>), crate::face::FaceError>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(Face::recv_with_addr(self))
    }
}

/// Snapshot of a face's metadata for reporting/display.
#[derive(Debug, Clone)]
pub struct FaceInfo {
    pub id: FaceId,
    pub kind: crate::face::FaceKind,
    pub remote_uri: Option<String>,
    pub local_uri: Option<String>,
}

/// Reserved face ID range used for internal engine faces (management AppFace, etc.).
/// IDs in this range are never allocated by `alloc_id()`.
pub const RESERVED_FACE_ID_MIN: u32 = 0xFFFF_0000;

impl FaceTable {
    pub fn new() -> Self {
        Self {
            faces: DashMap::new(),
            next_id: std::sync::atomic::AtomicU32::new(1),
            free: Mutex::new(Vec::new()),
        }
    }

    /// Allocate the next available `FaceId`, reusing a recycled ID if possible.
    ///
    /// Never returns an ID in the reserved range (`>= RESERVED_FACE_ID_MIN`).
    pub fn alloc_id(&self) -> FaceId {
        // Prefer a recycled ID.
        if let Ok(mut free) = self.free.lock() {
            if let Some(id) = free.pop() {
                return FaceId(id);
            }
        }
        // Otherwise allocate a fresh one, skipping over the reserved range.
        loop {
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if id < RESERVED_FACE_ID_MIN {
                return FaceId(id);
            }
            // Wrap back to 1 and retry.
            let _ = self.next_id.compare_exchange(
                id.wrapping_add(1),
                1,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    /// Register a face. Returns the assigned `FaceId`.
    pub fn insert<F: Face>(&self, face: F) -> FaceId {
        let id = face.id();
        self.faces.insert(id, Arc::new(face));
        id
    }

    /// Register a pre-wrapped erased face (e.g. a face accepted from a listener
    /// that is already stored in an `Arc`).  Returns the face's `FaceId`.
    pub fn insert_arc(&self, face: Arc<dyn ErasedFace>) -> FaceId {
        let id = face.id();
        self.faces.insert(id, face);
        id
    }

    /// Look up a face handle. Returns `None` if the face has been removed.
    pub fn get(&self, id: FaceId) -> Option<Arc<dyn ErasedFace>> {
        self.faces.get(&id).map(|r| Arc::clone(&*r))
    }

    /// Remove a face from the table, recycling its ID for future `alloc_id()` calls.
    pub fn remove(&self, id: FaceId) {
        self.faces.remove(&id);
        // Return dynamic IDs to the free list for reuse.
        if id.0 < RESERVED_FACE_ID_MIN {
            if let Ok(mut free) = self.free.lock() {
                free.push(id.0);
            }
        }
    }

    /// Number of registered faces.
    pub fn len(&self) -> usize {
        self.faces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.faces.is_empty()
    }

    /// Iterate over all registered face IDs.
    pub fn face_ids(&self) -> Vec<FaceId> {
        self.faces.iter().map(|r| *r.key()).collect()
    }

    /// Return all registered faces as `(FaceId, FaceKind)` pairs.
    pub fn face_entries(&self) -> Vec<(FaceId, crate::face::FaceKind)> {
        self.faces.iter().map(|r| (r.id(), r.kind())).collect()
    }

    /// Return detailed info for all registered faces.
    pub fn face_info(&self) -> Vec<FaceInfo> {
        self.faces
            .iter()
            .map(|r| FaceInfo {
                id: r.id(),
                kind: r.kind(),
                remote_uri: r.remote_uri(),
                local_uri: r.local_uri(),
            })
            .collect()
    }
}

impl Default for FaceTable {
    fn default() -> Self {
        Self::new()
    }
}
