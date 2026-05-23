use ndn_transport::FaceId;
use smallvec::SmallVec;

/// Per-face link quality snapshot, inserted into `StrategyContext::extensions`.
#[derive(Clone, Debug)]
pub struct LinkQualitySnapshot {
    pub per_face: SmallVec<[FaceLinkQuality; 4]>,
}

impl LinkQualitySnapshot {
    pub fn for_face(&self, face_id: FaceId) -> Option<&FaceLinkQuality> {
        self.per_face.iter().find(|f| f.face_id == face_id)
    }
}

/// Link quality metrics for a single face. All fields `Option` for extensibility.
#[derive(Clone, Debug)]
pub struct FaceLinkQuality {
    pub face_id: FaceId,
    pub rssi_dbm: Option<i8>,
    pub retransmit_rate: Option<f32>,
    pub observed_rtt_ms: Option<f64>,
    pub observed_tput: Option<f64>,
}
