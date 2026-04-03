use crate::FaceId;

/// Lifecycle events emitted by face tasks.
///
/// When a face task's `recv()` returns `FaceError::Closed`, the task removes
/// itself from the `FaceTable` and sends `FaceEvent::Closed(id)` to the face
/// manager. The manager then cleans up any PIT `OutRecord` entries for that
/// face.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaceEvent {
    /// A new face has been registered and its task is running.
    Opened(FaceId),
    /// A face has closed (remote disconnect or I/O error).
    Closed(FaceId),
}

impl FaceEvent {
    pub fn face_id(&self) -> FaceId {
        match self {
            FaceEvent::Opened(id) | FaceEvent::Closed(id) => *id,
        }
    }
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
