//! F3 broadcast-link wiring (feature `f3-link-face`).
//!
//! [`CopeBroadcastLink`] drives the [`crate::cope`] core over a broadcast
//! [`Transport`]: it frames natives, opportunistically XOR-codes queued
//! natives bound for different next-hops, broadcasts them, and on receive
//! records overheard natives and decodes coded frames addressed to this node.
//!
//! **Layering constraint (honest):** COPE codes by *next-hop*, which is
//! forwarding-plane information not present in a raw `send_bytes(bytes)`. So
//! the coded path is driven by [`enqueue`](CopeBroadcastLink::enqueue), which
//! takes the next-hop the strategy/FIB chose; wiring that into the engine's
//! egress (so the forwarder supplies next-hop automatically) is the remaining
//! integration seam. Likewise the **reception-report control protocol** (how
//! neighbors announce what they overheard) is modelled here by
//! [`report`](CopeBroadcastLink::report) / passive overhearing on receive; a
//! real deployment broadcasts periodic reports — also a seam.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::sync::Mutex;

use ndn_transport::{FaceError, Transport};

use crate::cope::{
    CodedFrame, CopeCoder, CopeWire, FrameId, NativeFrame, NeighborId, decode, decode_wire,
    encode_coded, encode_native, encode_report,
};

/// An event surfaced by [`CopeBroadcastLink::recv_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopeEvent {
    /// A native packet (received directly or recovered by decoding) is ready.
    Native { id: FrameId, payload: bytes::Bytes },
    /// A neighbor's reception report was applied to the coding state.
    ReportApplied { from: NeighborId, count: usize },
}

/// A COPE coding sublayer over a broadcast `Transport`. One per node.
pub struct CopeBroadcastLink<T: Transport> {
    inner: T,
    /// This node's neighbor id (so it knows which decoded natives are "for me"
    /// vs overheard for others).
    me: NeighborId,
    coder: Mutex<CopeCoder>,
    /// Natives this node holds (sent, overheard, or decoded) — the side info
    /// used to decode future coded frames. id → payload.
    held: Mutex<HashMap<FrameId, Bytes>>,
    next_id: AtomicU64,
}

impl<T: Transport> CopeBroadcastLink<T> {
    pub fn new(me: NeighborId, inner: T) -> Self {
        Self {
            inner,
            me,
            coder: Mutex::new(CopeCoder::new()),
            held: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Record that `neighbor` holds frame `id` (a reception report — from a
    /// neighbor's overhearing announcement). Feeds the COPE coding rule.
    pub async fn report(&self, neighbor: NeighborId, id: FrameId) {
        self.coder.lock().await.report(neighbor, id);
    }

    /// Queue a native for transmission to `next_hop`, returning its frame id.
    /// The node also retains it as side info for its own decoding.
    pub async fn enqueue(&self, next_hop: NeighborId, payload: Bytes) -> FrameId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.held.lock().await.insert(id, payload.clone());
        self.coder.lock().await.enqueue(NativeFrame {
            id,
            next_hop,
            payload,
        });
        id
    }

    /// Code whatever is queued (greedy COPE) and broadcast each resulting
    /// frame over the inner transport. Returns the number of frames sent and
    /// how many of them were genuinely coded (≥2 natives).
    pub async fn flush(&self) -> Result<(usize, usize), FaceError> {
        let mut coded_frames: Vec<CodedFrame> = Vec::new();
        {
            let mut coder = self.coder.lock().await;
            while let Some(frame) = coder.encode_next() {
                coded_frames.push(frame);
            }
        }
        let (mut sent, mut coded) = (0, 0);
        for frame in &coded_frames {
            if frame.is_coded() {
                coded += 1;
                self.inner.send_bytes(encode_coded(frame)).await?;
            } else {
                // Single member → send the native uncoded (tagged with its id).
                let (id, len) = frame.members[0];
                let payload = frame.payload.slice(..len.min(frame.payload.len()));
                self.inner.send_bytes(encode_native(id, &payload)).await?;
            }
            sent += 1;
        }
        Ok((sent, coded))
    }

    /// Broadcast this node's reception report — the frame ids it currently
    /// holds — so neighbors' coders learn what it can decode (seam B, the COPE
    /// control protocol). A real deployment calls this periodically (a tick).
    pub async fn announce(&self) -> Result<(), FaceError> {
        let ids: Vec<FrameId> = self.held.lock().await.keys().copied().collect();
        self.inner.send_bytes(encode_report(self.me, &ids)).await
    }

    /// Receive and classify the next link frame: a native (received or
    /// decoded), or a neighbor's reception report (applied to the coding
    /// state). Records overheard natives and skips coded frames this node
    /// cannot yet decode.
    pub async fn recv_event(&self) -> Result<CopeEvent, FaceError> {
        loop {
            let wire = self.inner.recv_bytes().await?;
            match decode_wire(&wire) {
                Some(CopeWire::Native { id, payload }) => {
                    self.held.lock().await.insert(id, payload.clone());
                    return Ok(CopeEvent::Native { id, payload });
                }
                Some(CopeWire::Coded(coded)) => {
                    let snapshot: HashMap<FrameId, Bytes> = self.held.lock().await.clone();
                    if let Some((id, native)) = decode(&coded, &snapshot) {
                        self.held.lock().await.insert(id, native.clone());
                        return Ok(CopeEvent::Native {
                            id,
                            payload: native,
                        });
                    }
                    // Can't decode (missing >1) or already hold all members.
                }
                Some(CopeWire::Report { from, ids }) => {
                    let mut coder = self.coder.lock().await;
                    for id in &ids {
                        coder.report(from, *id);
                    }
                    return Ok(CopeEvent::ReportApplied {
                        from,
                        count: ids.len(),
                    });
                }
                None => { /* malformed frame; ignore */ }
            }
        }
    }

    /// Receive the next native destined for this node (decoding as needed),
    /// transparently applying any reception reports seen along the way.
    pub async fn recv_native(&self) -> Result<(FrameId, Bytes), FaceError> {
        loop {
            if let CopeEvent::Native { id, payload } = self.recv_event().await? {
                return Ok((id, payload));
            }
        }
    }

    /// This node's neighbor id.
    pub fn me(&self) -> NeighborId {
        self.me
    }
}

/// A per-neighbor face over a shared [`CopeBroadcastLink`] (seam A): the
/// engine treats it as an ordinary face, and its [`Transport::send_bytes`]
/// feeds the link with **this member's neighbor id as the next-hop** — i.e.
/// the next-hop is exactly the out-`FaceId` the engine's strategy already
/// chose, so COPE coding needs **no** core/PIT change to learn the recipient.
/// (Threading per-neighbor `FaceAddr` through the PIT was deliberately
/// rejected: it would bloat the PIT hot path for a niche feature.)
///
/// Coding is batched, so `send_bytes` enqueues; a flush (a tick, or
/// [`CopeBroadcastLink::flush`]) emits the coded frames.
pub struct CopeMemberFace<T: Transport> {
    neighbor: NeighborId,
    link: Arc<CopeBroadcastLink<T>>,
    /// When `false`, `recv_bytes` parks forever (egress-only) — used in a mesh
    /// where a single ingress face drains the shared link, avoiding contention.
    recv_via_link: bool,
}

impl<T: Transport> CopeMemberFace<T> {
    /// A standalone member face: `recv_bytes` decodes from the shared link.
    pub fn new(neighbor: NeighborId, link: Arc<CopeBroadcastLink<T>>) -> Self {
        Self {
            neighbor,
            link,
            recv_via_link: true,
        }
    }

    /// An egress-only member face: `send_bytes` codes; `recv_bytes` parks (the
    /// mesh's single ingress face owns the receive path).
    pub fn send_only(neighbor: NeighborId, link: Arc<CopeBroadcastLink<T>>) -> Self {
        Self {
            neighbor,
            link,
            recv_via_link: false,
        }
    }
}

impl<T: Transport> Transport for CopeMemberFace<T> {
    fn id(&self) -> ndn_transport::FaceId {
        ndn_transport::FaceId(self.neighbor)
    }
    fn kind(&self) -> ndn_transport::FaceKind {
        ndn_transport::FaceKind::EtherMulticast
    }
    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.link.enqueue(self.neighbor, pkt).await;
        Ok(())
    }
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        if self.recv_via_link {
            self.link.recv_native().await.map(|(_id, payload)| payload)
        } else {
            std::future::pending().await // egress-only; ingress face receives
        }
    }
}

/// The mesh's single receive face: drains decoded natives from the shared
/// link into the engine. `send_bytes` is a no-op (it is not a FIB next-hop).
pub struct CopeIngressFace<T: Transport> {
    id: ndn_transport::FaceId,
    link: Arc<CopeBroadcastLink<T>>,
}

impl<T: Transport> CopeIngressFace<T> {
    pub fn new(id: ndn_transport::FaceId, link: Arc<CopeBroadcastLink<T>>) -> Self {
        Self { id, link }
    }
}

impl<T: Transport> Transport for CopeIngressFace<T> {
    fn id(&self) -> ndn_transport::FaceId {
        self.id
    }
    fn kind(&self) -> ndn_transport::FaceKind {
        ndn_transport::FaceKind::EtherMulticast
    }
    async fn send_bytes(&self, _pkt: Bytes) -> Result<(), FaceError> {
        Ok(()) // ingress-only
    }
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.link.recv_native().await.map(|(_id, payload)| payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use ndn_transport::{FaceId, FaceKind};

    // A minimal in-memory broadcast medium: every endpoint's `send_bytes`
    // delivers to every *other* endpoint's queue.
    struct BroadcastBus {
        senders: Vec<tokio::sync::mpsc::UnboundedSender<Bytes>>,
    }
    struct BusEndpoint {
        id: FaceId,
        index: usize,
        bus: Arc<BroadcastBus>,
        rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<Bytes>>,
    }
    impl BroadcastBus {
        fn with_endpoints(n: usize) -> Vec<BusEndpoint> {
            let mut senders = Vec::with_capacity(n);
            let mut rxs = Vec::with_capacity(n);
            for _ in 0..n {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                senders.push(tx);
                rxs.push(rx);
            }
            let bus = Arc::new(BroadcastBus { senders });
            rxs.into_iter()
                .enumerate()
                .map(|(index, rx)| BusEndpoint {
                    id: FaceId(index as u64 + 1),
                    index,
                    bus: Arc::clone(&bus),
                    rx: Mutex::new(rx),
                })
                .collect()
        }
    }
    impl Transport for BusEndpoint {
        fn id(&self) -> FaceId {
            self.id
        }
        fn kind(&self) -> FaceKind {
            FaceKind::EtherMulticast
        }
        async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
            for (i, tx) in self.bus.senders.iter().enumerate() {
                if i != self.index {
                    let _ = tx.send(pkt.clone());
                }
            }
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
            self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
        }
    }

    const ALICE: NeighborId = 1;
    const BOB: NeighborId = 2;

    /// Canonical COPE through real broadcast faces: the relay holds p1 (→Bob)
    /// and p2 (→Alice); Alice overheard p1, Bob overheard p2 (reported to the
    /// relay and held locally). One coded broadcast lets both recover — two
    /// unicasts collapsed to one transmission, over the wire framing.
    #[tokio::test]
    async fn alice_bob_relay_over_broadcast_faces() {
        let mut eps = BroadcastBus::with_endpoints(3);
        let relay_ep = eps.remove(2);
        let bob_ep = eps.remove(1);
        let alice_ep = eps.remove(0);

        let alice = CopeBroadcastLink::new(ALICE, alice_ep);
        let bob = CopeBroadcastLink::new(BOB, bob_ep);
        let relay = CopeBroadcastLink::new(99, relay_ep);

        let p1 = Bytes::from_static(b"native-packet-for-bob");
        let p2 = Bytes::from_static(b"the-native-for-alice");

        // Relay queues p1→Bob (id 1) and p2→Alice (id 2).
        let id1 = relay.enqueue(BOB, p1.clone()).await;
        let id2 = relay.enqueue(ALICE, p2.clone()).await;
        // Alice/Bob each hold their overheard native locally …
        alice.held.lock().await.insert(id1, p1.clone());
        bob.held.lock().await.insert(id2, p2.clone());
        // … and report it so the relay's coding rule is satisfied.
        relay.report(ALICE, id1).await;
        relay.report(BOB, id2).await;

        let (sent, coded) = relay.flush().await.unwrap();
        assert_eq!((sent, coded), (1, 1), "one coded broadcast");

        // Alice (holding p1) recovers p2; Bob (holding p2) recovers p1.
        let (rid_a, got_a) = alice.recv_native().await.unwrap();
        assert_eq!((rid_a, got_a), (id2, p2));
        let (rid_b, got_b) = bob.recv_native().await.unwrap();
        assert_eq!((rid_b, got_b), (id1, p1));
    }

    /// Without overhearing the relay can't code: it broadcasts the head native
    /// uncoded, and the recipient simply receives it.
    #[tokio::test]
    async fn falls_back_to_native_without_reports() {
        let mut eps = BroadcastBus::with_endpoints(2);
        let bob_ep = eps.remove(1);
        let relay_ep = eps.remove(0);
        let relay = CopeBroadcastLink::new(99, relay_ep);
        let bob = CopeBroadcastLink::new(BOB, bob_ep);

        let p = Bytes::from_static(b"just-one");
        let id = relay.enqueue(BOB, p.clone()).await;
        let (sent, coded) = relay.flush().await.unwrap();
        assert_eq!((sent, coded), (1, 0), "uncoded native broadcast");
        assert_eq!(bob.recv_native().await.unwrap(), (id, p));
    }

    /// Seam A: per-neighbor `CopeMemberFace`s feed the next-hop. The relay
    /// "forwards" two Data via the member faces toward neighbors A and B
    /// (exactly what the engine's per-face send loop does — `face.send_bytes`);
    /// the shared link then codes them because each recipient holds the other.
    #[tokio::test]
    async fn member_faces_feed_next_hop_into_coding() {
        let mut eps = BroadcastBus::with_endpoints(1);
        let relay_ep = eps.remove(0);
        let link = Arc::new(CopeBroadcastLink::new(99, relay_ep));
        let face_a = CopeMemberFace::new(ALICE, Arc::clone(&link));
        let face_b = CopeMemberFace::new(BOB, Arc::clone(&link));

        // The engine sends Data out the chosen out-face — next-hop is implicit
        // in WHICH member face. enqueue assigns ids 1 (→Alice) then 2 (→Bob).
        face_a
            .send_bytes(Bytes::from_static(b"for-alice"))
            .await
            .unwrap();
        face_b
            .send_bytes(Bytes::from_static(b"for-bob"))
            .await
            .unwrap();
        // Reception reports: Alice holds frame 2, Bob holds frame 1.
        link.report(ALICE, 2).await;
        link.report(BOB, 1).await;

        let (sent, coded) = link.flush().await.unwrap();
        assert_eq!(
            (sent, coded),
            (1, 1),
            "the two member-face sends are coded into one broadcast"
        );
        assert_eq!(
            face_a.id().0,
            ALICE,
            "member face id is its neighbor/next-hop"
        );
    }

    /// Seam B: the reception-report control protocol. Alice announces the
    /// frames she holds; the relay's `recv_event` applies the report to its
    /// coder automatically (no manual `report()` call).
    #[tokio::test]
    async fn reception_report_announce_and_apply() {
        let mut eps = BroadcastBus::with_endpoints(2);
        let relay_ep = eps.remove(1);
        let alice_ep = eps.remove(0);
        let alice = CopeBroadcastLink::new(ALICE, alice_ep);
        let relay = CopeBroadcastLink::new(99, relay_ep);

        alice.held.lock().await.insert(5, Bytes::from_static(b"x"));
        alice.held.lock().await.insert(6, Bytes::from_static(b"y"));
        alice.announce().await.unwrap();

        let ev = relay.recv_event().await.unwrap();
        assert_eq!(
            ev,
            CopeEvent::ReportApplied {
                from: ALICE,
                count: 2
            }
        );
    }
}
