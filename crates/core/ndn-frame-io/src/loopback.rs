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

impl LoopbackEndpoint {
    /// Put a frame on the simulated air at a resolved MCS index. No subscribers
    /// is not an error on a broadcast medium (the frame is simply lost).
    fn emit(&self, dst: [u8; 6], src: [u8; 6], payload: Bytes, mcs_index: u8) {
        let _ = self.tx.send(Arc::new(AirFrame {
            sender: self.node_id,
            dst,
            src,
            payload,
            mcs_index,
        }));
    }
}

#[async_trait]
impl FrameIo for LoopbackEndpoint {
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
        let idx = crate::McsDescriptor::for_intent(&frame.tx, crate::MAX_RELIABLE_MCS, false).index;
        self.emit(frame.dst, frame.src, frame.payload, idx);
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
                        // The loopback bus is a format-agnostic in-memory test
                        // double with no hardware clock — honestly unstamped.
                        stamp: None,
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

#[async_trait]
impl crate::WifiRadio for LoopbackEndpoint {
    async fn inject_at(
        &self,
        frame: InjectFrame,
        mcs: crate::McsDescriptor,
    ) -> Result<(), FaceError> {
        self.emit(frame.dst, frame.src, frame.payload, mcs.index);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{BROADCAST, DEFAULT_SRC};
    use crate::{McsDescriptor, TxIntent, WifiRadio};

    /// A distinctive non-broadcast group MAC (locally-administered multicast).
    const GROUP: [u8; 6] = [0x03, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    /// A distinctive non-default source MAC (locally-administered unicast).
    const NODE_SRC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    fn inj(payload: &[u8], dst: [u8; 6], src: [u8; 6]) -> InjectFrame {
        InjectFrame {
            payload: Bytes::copy_from_slice(payload),
            tx: TxIntent::CONSERVATIVE,
            dst,
            src,
        }
    }

    /// A frame injected on one endpoint is captured on another, and every
    /// link-layer hint (src→addr, dst→group, sender MCS, observer RSSI) survives.
    #[tokio::test]
    async fn frame_reaches_other_endpoint_with_all_hints() {
        let bus = LoopbackMonitorBus::new();
        let sender = bus.endpoint(1, -10);
        let receiver = bus.endpoint(2, -73);

        sender
            .inject_at(inj(b"\x05\x03abc", GROUP, NODE_SRC), McsDescriptor::ht(5))
            .await
            .unwrap();

        let got = receiver.recv_frame().await.unwrap();
        assert_eq!(got.payload.as_ref(), b"\x05\x03abc", "payload survives");
        assert_eq!(got.addr, Some(NODE_SRC), "InjectFrame.src → captured addr");
        assert_eq!(got.group, Some(GROUP), "InjectFrame.dst → captured group");
        assert_eq!(got.mcs_index, Some(5), "sender MCS surfaced as RX rate");
        assert_eq!(
            got.rssi_dbm,
            Some(-73),
            "the receiver's own observed RSSI, not the sender's"
        );
    }

    /// Half-duplex: a node never hears its own transmission. The sender injects
    /// first, then a peer injects; the sender's next capture is the peer's frame,
    /// with its own frame silently skipped (deterministic — both are queued).
    #[tokio::test]
    async fn endpoint_does_not_hear_itself() {
        let bus = LoopbackMonitorBus::new();
        let a = bus.endpoint(1, -50);
        let b = bus.endpoint(2, -50);

        a.inject(inj(b"mine", BROADCAST, NODE_SRC)).await.unwrap();
        b.inject(inj(b"yours", BROADCAST, DEFAULT_SRC))
            .await
            .unwrap();

        let got = a.recv_frame().await.unwrap();
        assert_eq!(got.payload.as_ref(), b"yours", "own frame was skipped");
    }

    /// Broadcast semantics: one injection is delivered to every other endpoint on
    /// the bus (each gets an independent copy at its own observed RSSI).
    #[tokio::test]
    async fn broadcast_reaches_all_other_endpoints() {
        let bus = LoopbackMonitorBus::new();
        let sender = bus.endpoint(1, 0);
        let r1 = bus.endpoint(2, -60);
        let r2 = bus.endpoint(3, -61);
        let r3 = bus.endpoint(4, -62);

        sender
            .inject_at(inj(b"hello", BROADCAST, DEFAULT_SRC), McsDescriptor::ht(3))
            .await
            .unwrap();

        for (r, rssi) in [(&r1, -60i8), (&r2, -61), (&r3, -62)] {
            let got = r.recv_frame().await.unwrap();
            assert_eq!(got.payload.as_ref(), b"hello");
            assert_eq!(got.rssi_dbm, Some(rssi), "each observer sees its own RSSI");
            assert_eq!(got.mcs_index, Some(3));
        }
    }

    /// Two receivers configured with different observed RSSIs each report their
    /// own value for the same on-air frame.
    #[tokio::test]
    async fn observed_rssi_is_per_endpoint() {
        let bus = LoopbackMonitorBus::new();
        let sender = bus.endpoint(1, 0);
        let near = bus.endpoint(2, -40);
        let far = bus.endpoint(3, -90);

        sender.inject(inj(b"x", GROUP, NODE_SRC)).await.unwrap();

        assert_eq!(near.recv_frame().await.unwrap().rssi_dbm, Some(-40));
        assert_eq!(far.recv_frame().await.unwrap().rssi_dbm, Some(-90));
    }

    /// Multiple senders on one bus: a single receiver captures both frames (order
    /// preserved by the underlying broadcast queue).
    #[tokio::test]
    async fn receiver_captures_frames_from_multiple_senders() {
        let bus = LoopbackMonitorBus::new();
        let receiver = bus.endpoint(1, -55);
        let s2 = bus.endpoint(2, 0);
        let s3 = bus.endpoint(3, 0);

        s2.inject(inj(b"from-2", BROADCAST, DEFAULT_SRC))
            .await
            .unwrap();
        s3.inject(inj(b"from-3", BROADCAST, DEFAULT_SRC))
            .await
            .unwrap();

        assert_eq!(
            receiver.recv_frame().await.unwrap().payload.as_ref(),
            b"from-2"
        );
        assert_eq!(
            receiver.recv_frame().await.unwrap().payload.as_ref(),
            b"from-3"
        );
    }

    /// Fire-and-forget: injecting with no other endpoint listening is not an
    /// error (the frame is simply lost, like real broadcast injection).
    #[tokio::test]
    async fn inject_with_no_other_listeners_is_ok() {
        let bus = LoopbackMonitorBus::new();
        let lone = bus.endpoint(1, -50);
        // Nobody else subscribed; the send has only the sender's own receiver.
        lone.inject(inj(b"lost", BROADCAST, DEFAULT_SRC))
            .await
            .expect("injection never fails on a broadcast medium");
    }

    /// Backpressure: a slow consumer that lets the 1024-deep broadcast queue
    /// overflow keeps receiving (the lag is swallowed, the medium is lossy) —
    /// `recv_frame` returns the oldest surviving frame rather than erroring.
    #[tokio::test]
    async fn slow_consumer_lags_without_error() {
        let bus = LoopbackMonitorBus::new();
        let receiver = bus.endpoint(1, -50);
        let sender = bus.endpoint(2, -50);

        // Overrun the 1024-slot channel without receiving, forcing a Lagged skip.
        for i in 0..1100u32 {
            sender
                .inject(inj(&i.to_le_bytes(), BROADCAST, DEFAULT_SRC))
                .await
                .unwrap();
        }

        let got = receiver
            .recv_frame()
            .await
            .expect("lag is swallowed, not surfaced as an error");
        assert_eq!(got.payload.len(), 4, "still a well-formed captured frame");
    }

    /// The `Default` bus behaves identically to `new()`.
    #[tokio::test]
    async fn default_bus_round_trips() {
        let bus = LoopbackMonitorBus::default();
        let sender = bus.endpoint(1, -50);
        let receiver = bus.endpoint(2, -50);
        sender
            .inject(inj(b"d", BROADCAST, DEFAULT_SRC))
            .await
            .unwrap();
        assert_eq!(receiver.recv_frame().await.unwrap().payload.as_ref(), b"d");
    }
}
