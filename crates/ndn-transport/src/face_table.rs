#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;
use std::sync::Arc;
#[cfg(target_arch = "wasm32")]
use std::sync::Mutex;

use crate::FaceId;
use crate::face::Face;
use crate::transport::Transport;

/// Concurrent map from `FaceId` to a composed [`Face`].
///
/// Pipeline stages clone the `Arc<Face>` out of the table before calling
/// `send_bytes()`, so no lock is held during I/O.
///
/// Face IDs are monotonic and never recycled — `alloc_id()` does
/// `fetch_add` on a `u64` counter, closing the ABA hazard for stamped
/// face-ids like NDNLPv2 `IncomingFaceId`.
pub struct FaceTable {
    #[cfg(not(target_arch = "wasm32"))]
    faces: DashMap<FaceId, Arc<Face>>,
    #[cfg(target_arch = "wasm32")]
    faces: Mutex<std::collections::HashMap<FaceId, Arc<Face>>>,
    next_id: std::sync::atomic::AtomicU64,
}

/// Snapshot of a face's metadata.
#[derive(Debug, Clone)]
pub struct FaceInfo {
    pub id: FaceId,
    pub kind: crate::face::FaceKind,
    pub remote_uri: Option<String>,
    pub local_uri: Option<String>,
}

impl FaceTable {
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            faces: DashMap::new(),
            #[cfg(target_arch = "wasm32")]
            faces: Mutex::new(std::collections::HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Allocate the next `FaceId`. Monotonic, never recycled.
    pub fn alloc_id(&self) -> FaceId {
        FaceId(
            self.next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Insert a `Transport`, wrapping it with the default `LinkService` for
    /// its `FaceKind`. Returns the face id.
    pub fn insert<T: Transport>(&self, transport: T) -> FaceId {
        let face = Face::from_transport(transport);
        self.insert_face(face)
    }

    pub fn insert_face(&self, face: Face) -> FaceId {
        self.insert_arc(Arc::new(face))
    }

    pub fn insert_arc(&self, face: Arc<Face>) -> FaceId {
        let id = face.id();
        #[cfg(not(target_arch = "wasm32"))]
        self.faces.insert(id, face);
        #[cfg(target_arch = "wasm32")]
        self.faces.lock().unwrap().insert(id, face);
        id
    }

    pub fn get(&self, id: FaceId) -> Option<Arc<Face>> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.faces.get(&id).map(|r| Arc::clone(&*r));
        #[cfg(target_arch = "wasm32")]
        return self.faces.lock().unwrap().get(&id).map(Arc::clone);
    }

    /// Remove a face. The id is not recycled.
    pub fn remove(&self, id: FaceId) {
        #[cfg(not(target_arch = "wasm32"))]
        self.faces.remove(&id);
        #[cfg(target_arch = "wasm32")]
        self.faces.lock().unwrap().remove(&id);
    }

    pub fn len(&self) -> usize {
        #[cfg(not(target_arch = "wasm32"))]
        return self.faces.len();
        #[cfg(target_arch = "wasm32")]
        return self.faces.lock().unwrap().len();
    }

    pub fn is_empty(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        return self.faces.is_empty();
        #[cfg(target_arch = "wasm32")]
        return self.faces.lock().unwrap().is_empty();
    }

    pub fn face_ids(&self) -> Vec<FaceId> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.faces.iter().map(|r| *r.key()).collect();
        #[cfg(target_arch = "wasm32")]
        return self.faces.lock().unwrap().keys().copied().collect();
    }

    pub fn face_entries(&self) -> Vec<(FaceId, crate::face::FaceKind)> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.faces.iter().map(|r| (r.id(), r.kind())).collect();
        #[cfg(target_arch = "wasm32")]
        return self
            .faces
            .lock()
            .unwrap()
            .values()
            .map(|f| (f.id(), f.kind()))
            .collect();
    }

    pub fn face_info(&self) -> Vec<FaceInfo> {
        #[cfg(not(target_arch = "wasm32"))]
        return self
            .faces
            .iter()
            .map(|r| FaceInfo {
                id: r.id(),
                kind: r.kind(),
                remote_uri: r.remote_uri(),
                local_uri: r.local_uri(),
            })
            .collect();
        #[cfg(target_arch = "wasm32")]
        return self
            .faces
            .lock()
            .unwrap()
            .values()
            .map(|f| FaceInfo {
                id: f.id(),
                kind: f.kind(),
                remote_uri: f.remote_uri(),
                local_uri: f.local_uri(),
            })
            .collect();
    }
}

impl Default for FaceTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_never_recycle() {
        let t = FaceTable::new();
        let a = t.alloc_id();
        let b = t.alloc_id();
        assert_ne!(a, b, "fresh ids must differ");
        t.remove(a);
        let c = t.alloc_id();
        assert_ne!(c, a, "id of closed face must not be reused");
        assert_ne!(c, b);
    }
}
