use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

use crate::side_stream::{
    Inbound, RECORD_MAX, SideLane, SidePump, SideTlvCodec, lane_and_pump, put_hello,
};
use crate::{
    FaceError, FaceId, FaceKind, FacePersistency, FaceTrust, MtuError, PeerCredentials,
    PersistencyError, SIDE_MARKER, SideClass, SideRefused, Transport,
};

/// Generic stream-based `Transport` over any async read/write pair with a
/// TLV codec. Reader/writer halves each sit behind a `Mutex`; the writer
/// lock serialises concurrent `send_bytes()` calls. NDNLPv2 framing is
/// applied by the paired [`LinkService`](crate::link_service::LinkService).
///
/// **Trust.** A stream face is [`FaceTrust::Validated`] (TCP, a Unix socket
/// of any user the node does not trust as its own, a named pipe) unless its
/// constructor called [`program_peer`](Self::program_peer). The peer's
/// kernel-attested credentials ([`with_peer_credentials`](Self::with_peer_credentials))
/// are recorded either way, so the management gate can still tell who sent a
/// command, but a socket's peer being *identified* does not make it *trusted*.
///
/// **Side frames.** A face made with [`SideTlvCodec`] and
/// [`with_side_lane`](StreamFace::with_side_lane) carries them as records
/// ([`crate::side_stream`]); any other stream face carries none.
pub struct StreamFace<R, W, C: Clone> {
    id: FaceId,
    kind: FaceKind,
    remote_uri: Option<String>,
    local_uri: Option<String>,
    reader: Mutex<FramedRead<R, C>>,
    writer: Arc<Mutex<FramedWrite<W, C>>>,
    lane: Option<Arc<SideLane>>,
    peer_credentials: Option<PeerCredentials>,
    trust: FaceTrust,
}

impl<R, W, C: Clone> StreamFace<R, W, C> {
    pub fn new(
        id: FaceId,
        kind: FaceKind,
        remote_uri: Option<String>,
        local_uri: Option<String>,
        reader: R,
        writer: W,
        codec: C,
    ) -> Self {
        Self {
            id,
            kind,
            remote_uri,
            local_uri,
            reader: Mutex::new(FramedRead::new(reader, codec.clone())),
            writer: Arc::new(Mutex::new(FramedWrite::new(writer, codec))),
            lane: None,
            peer_credentials: None,
            trust: FaceTrust::Validated,
        }
    }

    /// Record the peer process credentials the operating system reported for
    /// the underlying local socket (reported by
    /// [`Transport::peer_credentials`]). They say *who* is on the other end;
    /// they do not make the face a program face — that is the constructor's
    /// decision ([`program_peer`](Self::program_peer)), because a local
    /// socket is reachable by every user of the host. Call it only with
    /// credentials read from the socket (`SO_PEERCRED`, `getpeereid`), never
    /// with credentials the peer or a configuration states.
    pub fn with_peer_credentials(mut self, c: Option<PeerCredentials>) -> Self {
        self.peer_credentials = c;
        self
    }

    /// Make the face a program face ([`FaceTrust::Program`]): its Data is
    /// believed without validation. Call it only when the operating system
    /// identified the peer *and* that peer is one the node's policy trusts as
    /// it trusts its own programs (the daemon's user, root, a member of a
    /// `[security] program_groups` group), or when the process itself holds
    /// both ends of the connection.
    pub fn program_peer(mut self) -> Self {
        self.trust = FaceTrust::Program;
        self
    }
}

impl<R, W, C> StreamFace<R, W, C>
where
    R: AsyncRead + Unpin,
    C: Decoder<Error = std::io::Error> + Clone,
    C::Item: Into<Inbound>,
{
    /// The next thing the peer sent: an NDN packet, or a side frame with the face it arrived
    /// over at the forwarder ([`Inbound`]). [`recv_bytes`](Transport::recv_bytes) is this
    /// without the ingress. Ends with [`FaceError::Closed`] when the peer closed, and with the
    /// codec's error (the stream is then out of step and the face is closed) when it sent what
    /// the framing does not allow.
    pub async fn recv_inbound(&self) -> Result<Inbound, FaceError> {
        let mut reader = self.reader.lock().await;
        loop {
            let inbound: Inbound = match reader.next().await {
                Some(Ok(item)) => item.into(),
                Some(Err(e)) => return Err(FaceError::Io(e)),
                None => return Err(FaceError::Closed),
            };
            if inbound.is_hello() {
                // The peer reads side records: this end's frames may go to it.
                if let Some(lane) = &self.lane {
                    lane.open_for_peer();
                }
                continue;
            }
            if inbound.wire.first() == Some(&SIDE_MARKER)
                && self.lane.as_ref().is_some_and(|lane| !lane.is_open())
            {
                return Err(FaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a side record arrived before the peer's hello: a peer that reads side \
                     records says so first (`open_side`), so the stream is closed",
                )));
            }
            return Ok(inbound);
        }
    }
}

impl<R, W> StreamFace<R, W, SideTlvCodec> {
    /// Make the face carry side frames as records ([`crate::side_stream`]), and return the pump
    /// that writes them: run it as a task (`tokio::spawn(pump.run())`), or the frames wait
    /// for ever. Only a face whose codec reads the record can have a lane, and its peer must read
    /// it as well: an IPC socket's two ends are both [`SideTlvCodec`] faces.
    pub fn with_side_lane(mut self) -> (Self, SidePump<W>) {
        let (lane, pump) = lane_and_pump(Arc::clone(&self.writer));
        self.lane = Some(lane);
        (self, pump)
    }

    /// Completes when [`forward_side`](Transport::forward_side) may take a frame again (at once
    /// if it may now, or if the lane is closed, which refuses). Room is not reserved.
    pub async fn side_ready(&self) {
        if let Some(lane) = &self.lane {
            lane.ready().await;
        }
    }

    /// Whether the face has a lane, so can carry side records once it is opened.
    pub fn has_side_lane(&self) -> bool {
        self.lane.is_some()
    }

    /// Whether the lane is open: the peer has said it reads side records (see
    /// [`open_side`](Self::open_side)), or this end said it does.
    pub fn side_open(&self) -> bool {
        self.lane.as_ref().is_some_and(|lane| lane.is_open())
    }

    /// Say that this end reads side records, which a client does when it means to carry
    /// channel frames. The hello record is written before anything else this end writes from
    /// now on, and this end's frames are carried from now on. A forwarder that predates the
    /// record closes the stream on reading it; a face with no lane does nothing.
    pub fn open_side(&self) {
        if let Some(lane) = &self.lane {
            lane.open_here();
        }
    }
}

impl<R, W, C: Clone> Drop for StreamFace<R, W, C> {
    fn drop(&mut self) {
        // The pump ends, and a sender still waiting for room is refused.
        if let Some(lane) = &self.lane {
            lane.close();
        }
    }
}

impl<R, W, C> Transport for StreamFace<R, W, C>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    C: Decoder<Error = std::io::Error>
        + Encoder<Bytes, Error = std::io::Error>
        + Clone
        + Send
        + Sync
        + 'static,
    C::Item: Into<Inbound>,
{
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        self.kind
    }

    fn remote_uri(&self) -> Option<String> {
        self.remote_uri.clone()
    }
    fn local_uri(&self) -> Option<String> {
        self.local_uri.clone()
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_inbound().await.map(|inbound| inbound.wire)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        let mut writer = self.writer.lock().await;
        // The hello goes before this packet and everything written after it opened the lane.
        if let Some(lane) = &self.lane
            && lane.take_hello()
        {
            put_hello(writer.write_buffer_mut());
        }
        writer.send(wire).await.map_err(FaceError::Io)
    }

    /// Streams have no link MTU; the override has no wire effect today.
    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::NotSupported)
    }

    /// A TLV-framed byte stream cannot carry a side frame: the codec finds the end of a frame
    /// from its first octets read as a TLV header, and a side frame's first octets are not one,
    /// so written as is it would put the reader out of step and corrupt the NDN packets behind
    /// it. A face made with [`with_side_lane`](StreamFace::with_side_lane) (a
    /// [`SideTlvCodec`] face, whose peer reads the side record) carries them as records;
    /// every other stream face refuses, whatever the size, and writes nothing.
    async fn send_side(&self, frame: Bytes, _class: SideClass) -> Result<(), SideRefused> {
        match &self.lane {
            Some(lane) => lane.push(frame, None).await,
            None => Err(SideRefused::NotCarried),
        }
    }

    fn forward_side(&self, frame: Bytes, _class: SideClass) -> Result<(), SideRefused> {
        match &self.lane {
            Some(lane) => lane.try_push(&frame, None),
            None => Err(SideRefused::Unsupported),
        }
    }

    /// The frame goes to the peer with the id of the face it arrived over, which the app end
    /// of an IPC stream reports to its channel node.
    fn forward_side_from(
        &self,
        frame: Bytes,
        _class: SideClass,
        ingress: FaceId,
    ) -> Result<(), SideRefused> {
        match &self.lane {
            Some(lane) => lane.try_push(&frame, Some(ingress)),
            None => Err(SideRefused::Unsupported),
        }
    }

    /// Whether the lane's queue has room for a frame (a face with no lane has no queue to
    /// fill, and refuses another way).
    fn side_room(&self, _class: SideClass) -> bool {
        self.lane.as_ref().is_none_or(|lane| lane.has_room())
    }

    /// [`side_room`](Self::side_room) for this frame: the lane's queue must hold the frame and
    /// its record header under both bounds, the test `forward_side` makes. A frame the lane
    /// refuses another way has no room to wait for.
    fn side_room_for(&self, frame: &[u8], _class: SideClass) -> bool {
        self.lane
            .as_ref()
            .is_none_or(|lane| lane.has_room_for(frame))
    }

    /// What the peer has said it reads: [`RECORD_MAX`] once it opened the lane (a forwarder's
    /// end read the client's hello; a client's end said hello), `0` before, and for a face with
    /// no lane.
    fn side_frame_max(&self) -> usize {
        match &self.lane {
            Some(lane) if lane.is_open() => RECORD_MAX,
            _ => 0,
        }
    }

    /// Persistency is a face-table hint only — destruction is driven by I/O
    /// error for stream faces (matches NFD).
    fn set_persistency(&self, _persistency: FacePersistency) -> Result<(), PersistencyError> {
        Ok(())
    }

    fn peer_credentials(&self) -> Option<PeerCredentials> {
        self.peer_credentials
    }

    fn trust(&self) -> FaceTrust {
        self.trust
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SIDE_MARKER, TlvCodec};
    use tokio::io::AsyncReadExt;

    /// A stream face refuses a side frame and writes nothing: the octets of a
    /// refused frame never reach the stream, so the NDN packet after it is
    /// framed as before.
    #[tokio::test]
    async fn a_stream_face_carries_no_side_frame_and_writes_nothing() {
        let (near, mut far) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(near);
        let face = StreamFace::new(FaceId(1), FaceKind::Tcp, None, None, r, w, TlvCodec);

        let frame = Bytes::from_static(&[SIDE_MARKER, 0x20, 1, 2, 3]);
        for class in [SideClass::Datagram, SideClass::Stream] {
            assert_eq!(
                Transport::send_side(&face, frame.clone(), class).await,
                Err(SideRefused::NotCarried)
            );
        }
        assert_eq!(Transport::side_frame_max(&face), 0);
        assert_eq!(
            Transport::forward_side(&face, frame, SideClass::Datagram),
            Err(SideRefused::Unsupported)
        );

        // The next packet is the first octets on the stream.
        let pkt = Bytes::from_static(&[0x05, 0x01, 0xAB]);
        Transport::send_bytes(&face, pkt.clone()).await.unwrap();
        let mut got = [0u8; 3];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], &pkt[..]);
    }

    type Pair = StreamFace<
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
        SideTlvCodec,
    >;

    /// Two side-lane faces on the two ends of one stream, each with its pump running.
    fn pair() -> (Pair, Pair, [tokio::task::JoinHandle<()>; 2]) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let end = |id, io| {
            let (r, w) = tokio::io::split(io);
            let (face, pump) =
                StreamFace::new(FaceId(id), FaceKind::Unix, None, None, r, w, SideTlvCodec)
                    .with_side_lane();
            (face, tokio::spawn(pump.run()))
        };
        let (fa, pa) = end(1, a);
        let (fb, pb) = end(2, b);
        (fa, fb, [pa, pb])
    }

    fn side(n: u8, len: usize) -> Bytes {
        let mut v = vec![n; len];
        v[0] = SIDE_MARKER;
        Bytes::from(v)
    }

    /// An app's side frame reaches the forwarder's face, and a frame the forwarder routes to
    /// the app reaches it with the face it arrived over; NDN packets between them are untouched
    /// and every stream stays in order.
    #[tokio::test]
    async fn side_frames_cross_a_lane_face_in_both_directions_beside_ndn_packets() {
        let (app, fwd, _pumps) = pair();
        let pkt = |n: u8| Bytes::from(vec![0x05, 0x02, n, n]);

        // Nothing is carried either way until the app has said it reads records.
        for face in [&app, &fwd] {
            assert_eq!(Transport::side_frame_max(face), 0);
            assert!(!Transport::side_carries(face, SideClass::Datagram));
            assert_eq!(
                Transport::forward_side(face, side(1, 50), SideClass::Datagram),
                Err(SideRefused::NotCarried)
            );
            assert_eq!(
                Transport::send_side(face, side(1, 50), SideClass::Stream).await,
                Err(SideRefused::NotCarried)
            );
        }
        app.open_side();

        Transport::send_bytes(&app, pkt(1)).await.unwrap();
        Transport::send_side(&app, side(1, 50), SideClass::Datagram)
            .await
            .unwrap();
        Transport::send_bytes(&app, pkt(2)).await.unwrap();
        Transport::send_side(&app, side(2, 60), SideClass::Stream)
            .await
            .unwrap();

        let got = [
            fwd.recv_inbound().await.unwrap(),
            fwd.recv_inbound().await.unwrap(),
            fwd.recv_inbound().await.unwrap(),
            fwd.recv_inbound().await.unwrap(),
        ];
        // A side frame goes by the lane, NDN packets by the writer: each kind keeps its order.
        let packets: Vec<_> = got.iter().filter(|i| i.wire[0] != SIDE_MARKER).collect();
        let frames: Vec<_> = got.iter().filter(|i| i.wire[0] == SIDE_MARKER).collect();
        assert_eq!(
            packets.iter().map(|i| i.wire.clone()).collect::<Vec<_>>(),
            [pkt(1), pkt(2)]
        );
        assert_eq!(
            frames.iter().map(|i| i.wire.clone()).collect::<Vec<_>>(),
            [side(1, 50), side(2, 60)]
        );
        // An app names no ingress: the forwarder knows the face it came over.
        assert!(got.iter().all(|i| i.ingress.is_none()));

        Transport::forward_side_from(&fwd, side(3, 70), SideClass::Datagram, FaceId(42)).unwrap();
        Transport::forward_side(&fwd, side(4, 80), SideClass::Stream).unwrap();
        let first = app.recv_inbound().await.unwrap();
        assert_eq!((first.wire, first.ingress), (side(3, 70), Some(FaceId(42))));
        let second = app.recv_inbound().await.unwrap();
        assert_eq!((second.wire, second.ingress), (side(4, 80), None));
        // `recv_bytes` is the frame without the ingress.
        Transport::forward_side_from(&fwd, side(5, 46), SideClass::Datagram, FaceId(7)).unwrap();
        assert_eq!(Transport::recv_bytes(&app).await.unwrap(), side(5, 46));
        assert_eq!(Transport::side_frame_max(&app), RECORD_MAX);
        assert!(Transport::side_carries(&app, SideClass::Stream));
    }

    /// What a lane face refuses it refuses before it writes: the next NDN packet is the first
    /// octets on the stream, and a record on the stream is exactly marker, ingress, length,
    /// frame.
    #[tokio::test]
    async fn a_lane_face_refuses_a_bad_frame_and_writes_the_record_exactly() {
        let (near, mut far) = tokio::io::duplex(1 << 20);
        let (r, w) = tokio::io::split(near);
        let (face, pump) =
            StreamFace::new(FaceId(1), FaceKind::Unix, None, None, r, w, SideTlvCodec)
                .with_side_lane();
        tokio::spawn(pump.run());

        for class in [SideClass::Datagram, SideClass::Stream] {
            assert_eq!(
                Transport::send_side(&face, Bytes::from_static(&[0x05, 0x01, 0xAB]), class).await,
                Err(SideRefused::Malformed)
            );
            assert_eq!(
                Transport::send_side(&face, Bytes::new(), class).await,
                Err(SideRefused::Malformed)
            );
            assert_eq!(
                Transport::send_side(&face, side(0, RECORD_MAX + 1), class).await,
                Err(SideRefused::TooLarge {
                    size: RECORD_MAX + 1,
                    max: RECORD_MAX
                })
            );
        }
        // Opening the lane puts the hello first on the stream, then the packet.
        face.open_side();
        let pkt = Bytes::from_static(&[0x05, 0x01, 0xAB]);
        Transport::send_bytes(&face, pkt.clone()).await.unwrap();
        let mut hello = [0u8; 13];
        far.read_exact(&mut hello).await.unwrap();
        let mut want_hello = vec![0u8];
        want_hello.extend_from_slice(&u64::MAX.to_be_bytes());
        want_hello.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(&hello[..], &want_hello[..]);
        let mut got = [0u8; 3];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..], &pkt[..]);

        let frame = side(9, 46);
        Transport::forward_side_from(&face, frame.clone(), SideClass::Datagram, FaceId(0x0102))
            .unwrap();
        let mut record = vec![0u8; 13 + 46];
        far.read_exact(&mut record).await.unwrap();
        let mut want = vec![0u8];
        want.extend_from_slice(&0x0102u64.to_be_bytes());
        want.extend_from_slice(&46u32.to_be_bytes());
        want.extend_from_slice(&frame);
        assert_eq!(record, want);
    }

    /// The lane is bounded: a pump that is not running leaves `forward_side` refusing `Full`
    /// instead of queueing without end, and a pump that is gone makes it refuse `Closed`.
    #[tokio::test]
    async fn forward_side_never_waits_and_a_lane_without_a_pump_refuses() {
        let (near, _far) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(near);
        let (face, pump) =
            StreamFace::new(FaceId(1), FaceKind::Unix, None, None, r, w, SideTlvCodec)
                .with_side_lane();
        face.open_side();
        assert!(Transport::side_room(&face, SideClass::Datagram));
        for _ in 0..crate::side_stream::LANE_FRAMES {
            Transport::forward_side(&face, side(1, 46), SideClass::Datagram).unwrap();
        }
        assert_eq!(
            Transport::forward_side(&face, side(1, 46), SideClass::Datagram),
            Err(SideRefused::Full)
        );
        assert!(
            !Transport::side_room(&face, SideClass::Datagram),
            "a lane at its bound has no room"
        );
        drop(pump);
        assert_eq!(
            Transport::forward_side(&face, side(1, 46), SideClass::Datagram),
            Err(SideRefused::Closed)
        );
        assert!(
            Transport::side_room(&face, SideClass::Datagram),
            "a closed lane refuses Closed, not Full: nothing to wait for"
        );
        assert_eq!(
            Transport::send_side(&face, side(1, 46), SideClass::Stream).await,
            Err(SideRefused::Closed)
        );
    }

    /// Room for a frame is room for **that** frame: a lane with a little under a mebibyte left
    /// takes a small frame and refuses a big one, and `side_room_for` says so before the frame
    /// is sent. The frame-less `side_room` only asks that the lane is under its bound, so a
    /// mebibyte frame judged "room" at 3.9 of 4 MiB was refused `Full` by `forward_side` and
    /// lost at the first hop, which a sender's hold-back claims to prevent.
    #[tokio::test]
    async fn side_room_for_a_frame_reads_the_octets_forward_side_checks() {
        let (near, _far) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(near);
        let (face, _pump) =
            StreamFace::new(FaceId(1), FaceKind::Unix, None, None, r, w, SideTlvCodec)
                .with_side_lane();
        face.open_side();
        let big = side(1, RECORD_MAX);
        let small = side(2, 1_000);
        for _ in 0..3 {
            Transport::forward_side(&face, big.clone(), SideClass::Stream).unwrap();
        }
        assert!(
            Transport::side_room(&face, SideClass::Stream),
            "the lane is under its bound"
        );
        assert!(Transport::side_room_for(&face, &small, SideClass::Stream));
        assert!(
            !Transport::side_room_for(&face, &big, SideClass::Stream),
            "forward_side refuses a mebibyte here, and the read said room"
        );
        assert_eq!(
            Transport::forward_side(&face, big.clone(), SideClass::Stream),
            Err(SideRefused::Full)
        );
        Transport::forward_side(&face, small.clone(), SideClass::Stream).unwrap();
        // A frame the lane refuses another way is not waited for.
        let over = side(3, RECORD_MAX + 1);
        assert!(Transport::side_room_for(&face, &over, SideClass::Stream));
        let ndn = Bytes::from_static(&[0x06, 0x00]);
        assert!(Transport::side_room_for(&face, &ndn, SideClass::Stream));
    }

    /// Dropping the face ends its pump.
    #[tokio::test]
    async fn dropping_a_lane_face_ends_its_pump() {
        let (near, _far) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(near);
        let (face, pump) =
            StreamFace::new(FaceId(1), FaceKind::Unix, None, None, r, w, SideTlvCodec)
                .with_side_lane();
        let task = tokio::spawn(pump.run());
        tokio::task::yield_now().await;
        drop(face);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the pump ends once its face is dropped")
            .unwrap();
    }

    /// A peer that sends a record the framing does not allow gets its stream closed with the
    /// reason, and the NDN packet before it is still delivered.
    #[tokio::test]
    async fn a_bad_record_from_the_peer_closes_the_face_with_a_reason() {
        use tokio::io::AsyncWriteExt;
        let (near, mut far) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(near);
        let face = StreamFace::new(FaceId(1), FaceKind::Unix, None, None, r, w, SideTlvCodec);

        far.write_all(&[0x05, 0x01, 0xAB]).await.unwrap();
        // A record that announces more than a frame may be.
        far.write_all(&[SIDE_MARKER, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF])
            .await
            .unwrap();
        assert_eq!(
            face.recv_inbound().await.unwrap().wire[..],
            [0x05, 0x01, 0xAB]
        );
        match face.recv_inbound().await {
            Err(FaceError::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
                assert!(
                    e.to_string().contains("side record of 4294967295 octets"),
                    "{e}"
                );
            }
            other => panic!("expected a framing error, got {other:?}"),
        }
    }

    /// An app that only says it reads records, and sends no packet, still opens the forwarder's
    /// lane: the pump writes the hello by itself, and the reader takes it in and hands nothing on.
    #[tokio::test]
    async fn the_hello_opens_the_peers_lane_and_is_handed_on_to_nobody() {
        let (app, fwd, _pumps) = pair();
        let fwd = Arc::new(fwd);
        let reading = tokio::spawn({
            let fwd = Arc::clone(&fwd);
            async move { fwd.recv_inbound().await }
        });
        assert!(!fwd.side_open());
        app.open_side();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !fwd.side_open() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the hello reaches the forwarder's end and opens its lane");
        assert!(!reading.is_finished(), "the hello is no packet");
        Transport::forward_side(&*fwd, side(1, 46), SideClass::Datagram).unwrap();
        assert_eq!(app.recv_inbound().await.unwrap().wire, side(1, 46));
        reading.abort();
    }

    /// A record from a peer that never said it reads them closes the face with the reason: an
    /// app that predates the record sends none, so this is a peer out of step.
    #[tokio::test]
    async fn a_record_before_the_hello_closes_the_face_with_a_reason() {
        use tokio::io::AsyncWriteExt;
        let (near, mut far) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(near);
        let (face, _pump) =
            StreamFace::new(FaceId(1), FaceKind::Unix, None, None, r, w, SideTlvCodec)
                .with_side_lane();
        let mut record = bytes::BytesMut::new();
        crate::side_stream::put_record(&mut record, &side(1, 46), None);
        far.write_all(&record).await.unwrap();
        match face.recv_inbound().await {
            Err(FaceError::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
                assert!(e.to_string().contains("before the peer's hello"), "{e}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
