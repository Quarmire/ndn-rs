//! A hardware-free monitor-mode medium: every endpoint's injection is heard by
//! every *other* endpoint on the same bus, with a configurable observed RSSI.
//! Models the shared-medium, half-duplex (no self-hearing), fire-and-forget
//! semantics of raw 802.11 injection — enough to exercise the face, NDNLPv2
//! fragmentation/reassembly, and RSSI plumbing through a real engine without a
//! radio. The radiotap/802.11 framing lives in `AfPacketBackend`(crate);
//! this bus carries the NDN payload directly, like the real air carries it
//! once the headers are stripped.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_transport::FaceError;
use tokio::sync::{Mutex, broadcast};

use crate::{CapturedFrame, FrameIo, InjectFrame};

#[derive(Clone)]
struct AirFrame {
    sender: u64,
    /// 802.11 destination/group (`addr1`) and source (`addr2`) the injector set
    /// — name-derived for a grouped face, broadcast/default otherwise.
    dst: [u8; 6],
    src: [u8; 6],
    payload: Bytes,
    /// MCS the sender injected at — surfaced to receivers as the captured MCS,
    /// mirroring radiotap reporting the RX rate.
    mcs_index: u8,
}

/// A shared injection medium. Hand out [`LoopbackEndpoint`]s with
/// [`endpoint`](Self::endpoint).
pub struct LoopbackMonitorBus {
    tx: broadcast::Sender<Arc<AirFrame>>,
}

impl LoopbackMonitorBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(1024);
        Self { tx }
    }

    /// Attach an endpoint identified by `node_id` (used to suppress
    /// self-hearing), observing `observed_rssi_dbm` on every frame it captures.
    /// Frame addresses come from each [`InjectFrame`], not the endpoint.
    pub fn endpoint(&self, node_id: u64, observed_rssi_dbm: i8) -> LoopbackEndpoint {
        LoopbackEndpoint {
            node_id,
            observed_rssi_dbm,
            tx: self.tx.clone(),
            rx: Mutex::new(self.tx.subscribe()),
        }
    }
}

impl Default for LoopbackMonitorBus {
    fn default() -> Self {
        Self::new()
    }
}

/// One node on a [`LoopbackMonitorBus`]. Implements [`FrameIo`].
pub struct LoopbackEndpoint {
    node_id: u64,
    observed_rssi_dbm: i8,
    tx: broadcast::Sender<Arc<AirFrame>>,
    rx: Mutex<broadcast::Receiver<Arc<AirFrame>>>,
}

#[async_trait]
impl FrameIo for LoopbackEndpoint {
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
        // No subscribers is not an error on a broadcast medium (nobody is
        // listening — the frame is simply lost, like real injection).
        let _ = self.tx.send(Arc::new(AirFrame {
            sender: self.node_id,
            dst: frame.dst,
            src: frame.src,
            payload: frame.payload,
            mcs_index: frame.mcs.index,
        }));
        Ok(())
    }

    async fn recv_frame(&self) -> Result<CapturedFrame, FaceError> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Ok(air) if air.sender != self.node_id => {
                    return Ok(CapturedFrame {
                        payload: air.payload.clone(),
                        addr: Some(air.src),
                        group: Some(air.dst),
                        rssi_dbm: Some(self.observed_rssi_dbm),
                        mcs_index: Some(air.mcs_index),
                    });
                }
                // Own transmission — a radio does not hear itself.
                Ok(_) => continue,
                // Slow consumer dropped frames; keep going (lossy medium).
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return Err(FaceError::Closed),
            }
        }
    }
}
