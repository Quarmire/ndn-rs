use ndn_transport::FaceId;
use smallvec::SmallVec;

/// Per-face link quality snapshot inserted into `StrategyContext::extensions`.
///
/// Access from a strategy: `ctx.extensions.get::<LinkQualitySnapshot>()`.
///
/// Populated by a `ContextEnricher` in `ndn-engine` that reads from
/// `RadioTable`, `FlowTable`, or other data sources.
#[derive(Clone, Debug)]
pub struct LinkQualitySnapshot {
    /// Link quality entries, one per known face.
    pub per_face: SmallVec<[FaceLinkQuality; 4]>,
}

impl LinkQualitySnapshot {
    /// Look up link quality for a specific face.
    pub fn for_face(&self, face_id: FaceId) -> Option<&FaceLinkQuality> {
        self.per_face.iter().find(|f| f.face_id == face_id)
    }
}

/// Link quality metrics for a single face.
///
/// All fields are `Option` so that:
/// - Missing data sources simply leave fields as `None`.
/// - New metrics can be added without breaking existing strategies.
#[derive(Clone, Debug)]
pub struct FaceLinkQuality {
    /// The face these metrics belong to.
    pub face_id: FaceId,
    /// RSSI in dBm (from RadioTable / nl80211). Typical range: -90 to -20.
    pub rssi_dbm: Option<i8>,
    /// MAC-layer retransmit rate (0.0 = no retransmits, 1.0 = every frame retransmitted).
    pub retransmit_rate: Option<f32>,
    /// Observed RTT in milliseconds (from FlowTable or MeasurementsTable).
    pub observed_rtt_ms: Option<f64>,
    /// Observed throughput in bytes/sec (from FlowTable).
    pub observed_tput: Option<f64>,
}
