use bytes::Bytes;
use crate::FaceId;

/// A raw, undecoded packet as it enters the engine from a face task.
///
/// The timestamp is taken at `recv()` time — before the packet is enqueued on
/// the pipeline channel — so Interest lifetime accounting starts from arrival,
/// not from when the pipeline runner dequeues it.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Wire-format bytes.
    pub bytes: Bytes,
    /// Face the packet arrived on.
    pub face_id: FaceId,
    /// Arrival time as nanoseconds since the Unix epoch.
    pub arrival: u64,
}

impl RawPacket {
    pub fn new(bytes: Bytes, face_id: FaceId, arrival: u64) -> Self {
        Self { bytes, face_id, arrival }
    }
}
