use bytes::Bytes;
use ndn_transport::{Face, FaceError, FaceId, FaceKind};

/// NDN face over Wifibroadcast NG (wfb-ng).
///
/// wfb-ng uses 802.11 monitor mode with raw frame injection to implement a
/// **unidirectional broadcast link** with FEC, discarding the 802.11 MAC
/// entirely (no association, ACK, or CSMA/CA).
///
/// Because wfb-ng links are inherently unidirectional, this face is paired
/// with a complementary face via `FacePairTable` in the engine dispatcher:
/// when Data needs to return on a wfb-ng rx face, the dispatcher redirects it
/// to the paired tx face.
pub struct WfbFace {
    id: FaceId,
    direction: WfbDirection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WfbDirection {
    /// Receive-only (downlink from air unit to ground station).
    Rx,
    /// Transmit-only (uplink from ground station to air unit).
    Tx,
}

impl WfbFace {
    pub fn new(id: FaceId, direction: WfbDirection) -> Self {
        Self { id, direction }
    }
}

impl Face for WfbFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Wfb
    }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        match self.direction {
            WfbDirection::Rx => Err(FaceError::Closed), // placeholder — monitor mode capture
            WfbDirection::Tx => futures_pending().await,
        }
    }

    async fn send(&self, _pkt: Bytes) -> Result<(), FaceError> {
        match self.direction {
            WfbDirection::Tx => Err(FaceError::Closed), // placeholder — raw frame injection
            WfbDirection::Rx => Err(FaceError::Closed), // tx not supported on rx face
        }
    }
}

/// Never resolves — used to park the recv task on a tx-only face.
async fn futures_pending() -> Result<Bytes, FaceError> {
    std::future::pending::<()>().await;
    unreachable!()
}
