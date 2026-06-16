use ndn_transport::FaceId;

#[derive(Clone, Debug, Default)]
pub struct RadioFaceMetadata {
    pub radio_id: u8,
    pub channel: u8,
    /// Frequency band (2.4 GHz = 2, 5 GHz = 5, 6 GHz = 6).
    pub band: u8,
}

#[derive(Clone, Debug, Default)]
pub struct LinkMetrics {
    pub rssi_dbm: i8,
    pub retransmit_rate: f32,
    pub last_updated: u64,
}

/// Shared table of link metrics, keyed by `FaceId`.
pub struct RadioTable {
    metrics: dashmap::DashMap<FaceId, LinkMetrics>,
}

impl RadioTable {
    pub fn new() -> Self {
        Self {
            metrics: dashmap::DashMap::new(),
        }
    }

    pub fn update(&self, face_id: FaceId, metrics: LinkMetrics) {
        self.metrics.insert(face_id, metrics);
    }

    pub fn get(&self, face_id: &FaceId) -> Option<LinkMetrics> {
        self.metrics.get(face_id).map(|r| r.clone())
    }
}

impl Default for RadioTable {
    fn default() -> Self {
        Self::new()
    }
}
