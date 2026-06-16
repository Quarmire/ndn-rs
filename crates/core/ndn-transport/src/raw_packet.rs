use crate::FaceId;
use bytes::Bytes;

/// A raw, undecoded packet as it enters the engine from a face task.
/// The arrival timestamp is taken at `recv()` time so Interest lifetime
/// accounting starts from arrival, not pipeline dispatch.
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
