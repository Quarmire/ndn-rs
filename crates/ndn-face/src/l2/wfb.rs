use bytes::Bytes;
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

/// NDN face over Wifibroadcast NG (wfb-ng): 802.11 monitor-mode raw injection
/// with FEC, no MAC/ACK/CSMA. Each face is unidirectional and must be paired
/// via the engine's `FacePairTable` so Data returning on an Rx face is sent on
/// the matching Tx face.
///
/// **Superseded.** The working monitor-mode injection face now lives in the
/// `ndn-face-monitor-wifi` crate (`MonitorWifiFace` over a `RawFrameIo`
/// backend: `AfPacketBackend` on Linux, `LoopbackMonitorBus` for tests). It is
/// bidirectional, picks the injection MCS per frame (radiotap TX descriptor),
/// and feeds per-frame RSSI to the signal store. This stub is kept only so the
/// `FaceKind::Wfb` scope/LP-framing wiring has a home; new code should use
/// `ndn-face-monitor-wifi`.
pub struct WfbFace {
    id: FaceId,
    direction: WfbDirection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WfbDirection {
    Rx,
    Tx,
}

impl WfbFace {
    pub fn new(id: FaceId, direction: WfbDirection) -> Self {
        Self { id, direction }
    }
}

impl Transport for WfbFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Wfb
    }

    // TODO(wfb): monitor-mode capture / raw-frame injection not implemented yet.
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        match self.direction {
            WfbDirection::Rx => Err(FaceError::Closed),
            WfbDirection::Tx => futures_pending().await,
        }
    }

    async fn send_bytes(&self, _pkt: Bytes) -> Result<(), FaceError> {
        Err(FaceError::Closed)
    }
}

/// Parks the recv task on a tx-only face; never resolves.
async fn futures_pending() -> Result<Bytes, FaceError> {
    std::future::pending::<()>().await;
    unreachable!()
}
