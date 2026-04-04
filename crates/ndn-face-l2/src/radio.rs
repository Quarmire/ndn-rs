use ndn_transport::FaceId;

/// Metadata attached to a wireless face for multi-radio strategy decisions.
#[derive(Clone, Debug, Default)]
pub struct RadioFaceMetadata {
    /// Index of the physical radio (0-based).
    pub radio_id: u8,
    /// Current 802.11 channel number.
    pub channel: u8,
    /// Frequency band (2.4 GHz = 2, 5 GHz = 5, 6 GHz = 6).
    pub band: u8,
}

/// Per-face link quality metrics, updated by the nl80211 task.
#[derive(Clone, Debug, Default)]
pub struct LinkMetrics {
    /// Received signal strength in dBm.
    pub rssi_dbm: i8,
    /// MAC-layer retransmission rate (0.0–1.0).
    pub retransmit_rate: f32,
    /// Last updated (ns since Unix epoch).
    pub last_updated: u64,
}

/// Shared table of link metrics, keyed by `FaceId`.
///
/// Written by the nl80211 monitoring task; read by wireless strategies.
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
