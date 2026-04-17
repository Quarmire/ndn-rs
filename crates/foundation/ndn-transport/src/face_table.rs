#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;
use std::sync::{Arc, Mutex};

use crate::{Face, FaceId};

type RecvWithAddrResult =
    Result<(bytes::Bytes, Option<crate::face::FaceAddr>), crate::face::FaceError>;

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
    #[cfg(not(target_arch = "wasm32"))]
    faces: DashMap<FaceId, Arc<dyn ErasedFace>>,
    #[cfg(target_arch = "wasm32")]
    faces: Mutex<std::collections::HashMap<FaceId, Arc<dyn ErasedFace>>>,
    next_id: std::sync::atomic::AtomicU32,
    free: Mutex<Vec<u32>>,
}

/// Object-safe wrapper around the `Face` trait so it can be stored in the face table.
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
    fn recv_bytes_with_addr(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = RecvWithAddrResult> + Send + '_>>;
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
                    Output = Result<
                        (bytes::Bytes, Option<crate::face::FaceAddr>),
                        crate::face::FaceError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(Face::recv_with_addr(self))
    }
}

/// Snapshot of a face's metadata.
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
            #[cfg(not(target_arch = "wasm32"))]
            faces: DashMap::new(),
            #[cfg(target_arch = "wasm32")]
            faces: Mutex::new(std::collections::HashMap::new()),
            next_id: std::sync::atomic::AtomicU32::new(1),
            free: Mutex::new(Vec::new()),
        }
    }

    /// Allocate the next available `FaceId`, reusing a recycled ID if possible.
    pub fn alloc_id(&self) -> FaceId {
        if let Ok(mut free) = self.free.lock()
            && let Some(id) = free.pop()
        {
            return FaceId(id);
        }
        loop {
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if id < RESERVED_FACE_ID_MIN {
                return FaceId(id);
            }
            let _ = self.next_id.compare_exchange(
                id.wrapping_add(1),
                1,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    pub fn insert<F: Face>(&self, face: F) -> FaceId {
        let id = face.id();
        let arc: Arc<dyn ErasedFace> = Arc::new(face);
        #[cfg(not(target_arch = "wasm32"))]
        self.faces.insert(id, arc);
        #[cfg(target_arch = "wasm32")]
        self.faces.lock().unwrap().insert(id, arc);
        id
    }

    /// Register a pre-wrapped erased face.
    pub fn insert_arc(&self, face: Arc<dyn ErasedFace>) -> FaceId {
        let id = face.id();
        #[cfg(not(target_arch = "wasm32"))]
        self.faces.insert(id, face);
        #[cfg(target_arch = "wasm32")]
        self.faces.lock().unwrap().insert(id, face);
        id
    }

    pub fn get(&self, id: FaceId) -> Option<Arc<dyn ErasedFace>> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.faces.get(&id).map(|r| Arc::clone(&*r));
        #[cfg(target_arch = "wasm32")]
        return self.faces.lock().unwrap().get(&id).map(Arc::clone);
    }

    /// Remove a face, recycling its ID for future `alloc_id()` calls.
    pub fn remove(&self, id: FaceId) {
        #[cfg(not(target_arch = "wasm32"))]
        self.faces.remove(&id);
        #[cfg(target_arch = "wasm32")]
        self.faces.lock().unwrap().remove(&id);
        if id.0 < RESERVED_FACE_ID_MIN
            && let Ok(mut free) = self.free.lock()
        {
            free.push(id.0);
        }
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
