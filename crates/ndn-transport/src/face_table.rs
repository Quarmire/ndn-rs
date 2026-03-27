use std::sync::Arc;
use dashmap::DashMap;

use crate::{Face, FaceId};

/// Concurrent map from `FaceId` to a type-erased face handle.
///
/// Pipeline stages clone the `Arc<dyn ErasedFace>` out of the table and
/// release the table reference before calling `send()`, so no lock is held
/// during I/O.
pub struct FaceTable {
    faces: DashMap<FaceId, Arc<dyn ErasedFace>>,
    next_id: std::sync::atomic::AtomicU32,
}

/// Object-safe wrapper around the `Face` trait so it can be stored in a `DashMap`.
pub trait ErasedFace: Send + Sync + 'static {
    fn id(&self) -> FaceId;
    fn send_bytes(
        &self,
        pkt: bytes::Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), crate::face::FaceError>> + Send + '_>>;
    fn recv_bytes(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bytes::Bytes, crate::face::FaceError>> + Send + '_>>;
}

impl<F: Face> ErasedFace for F {
    fn id(&self) -> FaceId {
        Face::id(self)
    }

    fn send_bytes(
        &self,
        pkt: bytes::Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), crate::face::FaceError>> + Send + '_>> {
        Box::pin(Face::send(self, pkt))
    }

    fn recv_bytes(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bytes::Bytes, crate::face::FaceError>> + Send + '_>> {
        Box::pin(Face::recv(self))
    }
}

impl FaceTable {
    pub fn new() -> Self {
        Self {
            faces: DashMap::new(),
            next_id: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Allocate the next sequential `FaceId`.
    pub fn alloc_id(&self) -> FaceId {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        FaceId(id)
    }

    /// Register a face. Returns the assigned `FaceId`.
    pub fn insert<F: Face>(&self, face: F) -> FaceId {
        let id = face.id();
        self.faces.insert(id, Arc::new(face));
        id
    }

    /// Look up a face handle. Returns `None` if the face has been removed.
    pub fn get(&self, id: FaceId) -> Option<Arc<dyn ErasedFace>> {
        self.faces.get(&id).map(|r| Arc::clone(&*r))
    }

    /// Remove a face from the table.
    pub fn remove(&self, id: FaceId) {
        self.faces.remove(&id);
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
}

impl Default for FaceTable {
    fn default() -> Self {
        Self::new()
    }
}
