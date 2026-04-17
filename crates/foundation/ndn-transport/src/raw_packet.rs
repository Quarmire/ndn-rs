use crate::FaceId;
use bytes::Bytes;

/// A raw, undecoded packet as it enters the engine from a face task.
///
/// The timestamp is taken at `recv()` time — before the packet is enqueued on
/// the pipeline channel — so Interest lifetime accounting starts from arrival,
/// not from when the pipeline runner dequeues it.
#[derive(Debug, Clone)]
pub struct RawPacket {
    pub bytes: Bytes,
    pub face_id: FaceId,
    /// Nanoseconds since the Unix epoch; taken at `recv()` time.
    pub arrival: u64,
}

impl RawPacket {
    pub fn new(bytes: Bytes, face_id: FaceId, arrival: u64) -> Self {
        Self {
            bytes,
            face_id,
            arrival,
        }
    }
}
