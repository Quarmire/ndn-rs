use crate::FaceId;

/// Lifecycle events emitted by face tasks. On `Closed`, the engine cleans up
/// any PIT `OutRecord` entries for the face.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaceEvent {
    Opened(FaceId),
    Closed(FaceId),
}

impl FaceEvent {
    pub fn face_id(&self) -> FaceId {
        match self {
            FaceEvent::Opened(id) | FaceEvent::Closed(id) => *id,
        }
    }
}

/// Per-face lifecycle sink installed on the engine. Mgmt publishes the
/// transitions on `/localhost/nfd/faces/notifications`.
pub trait FaceLifecycleSink: Send + Sync {
    /// Called once when the face's I/O tasks start. Idempotent.
    fn on_up(&self, face_id: FaceId);
    /// Called when the face is removed (I/O error on non-permanent face or
    /// explicit `faces/destroy`).
    fn on_down(&self, face_id: FaceId);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn face_id_accessor() {
        let opened = FaceEvent::Opened(FaceId(3));
        let closed = FaceEvent::Closed(FaceId(7));
        assert_eq!(opened.face_id(), FaceId(3));
        assert_eq!(closed.face_id(), FaceId(7));
    }

    #[test]
    fn events_are_clone_and_eq() {
        let e = FaceEvent::Closed(FaceId(1));
        assert_eq!(e.clone(), e);
    }
}
