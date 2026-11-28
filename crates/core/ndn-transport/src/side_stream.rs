//! Side frames on a byte stream: the record form, its decoder, and the lane that writes it.
//!
//! A [`StreamFace`](crate::StreamFace) over [`TlvCodec`] frames what it carries as NDN TLV
//! elements, and a side frame ([`crate::side`]) is not one: its first octets read as a TLV header
//! would put the reader out of step. A stream that is to carry them says so by its codec,
//! [`SideTlvCodec`], and a side frame travels on it as a **record**:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 1 | `0x00`, the marker ([`SIDE_MARKER`]) |
//! | 1 | 8 | ingress: the id of the face the frame arrived over at the forwarder, big-endian; `u64::MAX` when none (what an app sends: the forwarder knows which face it came over and never reads this) |
//! | 9 | 4 | length of the frame, big-endian |
//! | 13 | length | the frame, which starts with its own marker octet |
//!
//! A TLV element never starts with `0x00` (TLV-TYPE 0 is not assigned, and a longer type number
//! starts `0xFD`/`0xFE`/`0xFF`), so the decoder tells a record from an NDN packet by its first
//! octet and a stream's ordinary traffic is byte-for-byte what [`TlvCodec`] carries. The decoder
//! fails closed: a record whose length is over [`RECORD_MAX`], or whose frame does not
//! start with the marker, is an error that closes the face with its reason; so is a stream that
//! ends inside a record. Nothing is skipped or guessed at.
//!
//! **Hello.** A record whose length is zero ([`put_hello`]) carries no frame: it says its writer
//! reads records. A peer built before the record reads its stream as TLV elements and a record
//! would put it out of step for good, so a face writes a record only to a peer that said so:
//! the app end writes the hello first when it opts in (`StreamFace::open_side`), the forwarder's
//! end opens its lane when it reads it, and until then both ends refuse every frame
//! [`NotCarried`](SideRefused::NotCarried) and report [`side_frame_max`](crate::Transport) 0. A
//! record that arrives before the hello is an error that closes the face. A peer that predates
//! the record answers the hello (a TLV element of type 0 with a length of `u64::MAX`) by closing
//! the stream.
//!
//! A face's side frames go through a bounded `SideLane`, one queue in order, written by a
//! [`SidePump`] the owner of the face runs as a task (this crate spawns nothing): `send_side` waits
//! for room in it, `forward_side` never waits and refuses [`SideRefused::Full`]. The pump writes
//! each record whole under the face's writer lock, so a record is never split by an NDN packet.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::SinkExt;
use tokio::io::AsyncWrite;
use tokio::sync::{Mutex, Notify};
use tokio_util::codec::{Decoder, Encoder, FramedWrite};

use crate::side_header::STREAM_FRAME_GRANT;
use crate::{FaceId, SIDE_MARKER, SideRefused, TlvCodec};

/// Octets before the frame in a record: marker, ingress, length.
pub const RECORD_HEADER_LEN: usize = 13;

/// The longest frame a record carries: what a face grants its peer on a side stream.
pub const RECORD_MAX: usize = STREAM_FRAME_GRANT;

/// How many frames a lane holds for its pump before `forward_side` refuses more.
pub const LANE_FRAMES: usize = 1024;

/// How many octets (frames and their record headers) a lane holds in all.
pub const LANE_OCTETS: usize = 4 * 1024 * 1024;

/// What the wire says of a frame's ingress when it has none.
const NO_INGRESS: u64 = u64::MAX;

/// One thing read from a stream: an NDN packet, or the frame of a side record with the face it
/// arrived over at the forwarder (the peer's own word, which only an app end reads: a forwarder
/// knows the face a frame came over).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inbound {
    /// The NDN packet's wire, or the side frame (which starts with [`SIDE_MARKER`]).
    pub wire: Bytes,
    /// For a side frame, the face it arrived over at the forwarder, if the record said.
    pub ingress: Option<FaceId>,
}

impl From<Bytes> for Inbound {
    fn from(wire: Bytes) -> Self {
        Self {
            wire,
            ingress: None,
        }
    }
}

impl Inbound {
    /// What the hello record decodes to: no wire at all. A face that reads it opens its lane
    /// and hands it on to nobody.
    pub(crate) fn hello() -> Self {
        Self {
            wire: Bytes::new(),
            ingress: None,
        }
    }

    /// Whether this is the hello record ([`put_hello`]).
    pub fn is_hello(&self) -> bool {
        self.wire.is_empty()
    }
}

/// [`TlvCodec`] that also reads and writes the side record (see the module docs). `Item` is
/// [`Inbound`]; writing is as is, so a face frames a side frame with [`put_record`] (the
/// [`SidePump`] does) and an NDN packet with nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct SideTlvCodec;

fn invalid(what: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what)
}

impl Decoder for SideTlvCodec {
    type Item = Inbound;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Inbound>, Self::Error> {
        match src.first() {
            None => return Ok(None),
            Some(&SIDE_MARKER) => {}
            Some(_) => return Ok(TlvCodec.decode(src)?.map(Inbound::from)),
        }
        if src.len() < RECORD_HEADER_LEN {
            return Ok(None);
        }
        let ingress = u64::from_be_bytes(src[1..9].try_into().expect("8 octets"));
        let len = u32::from_be_bytes(src[9..13].try_into().expect("4 octets")) as usize;
        if len > RECORD_MAX {
            return Err(invalid(format!(
                "side record of {len} octets: a frame is 1 to {RECORD_MAX} octets; the peer is \
                 not speaking the side-record framing, so the stream is closed"
            )));
        }
        if len == 0 {
            src.advance(RECORD_HEADER_LEN);
            return Ok(Some(Inbound::hello()));
        }
        if src.len() > RECORD_HEADER_LEN && src[RECORD_HEADER_LEN] != SIDE_MARKER {
            return Err(invalid(format!(
                "side record whose frame starts with {:#04x}, not the marker 0x00; the peer is \
                 not speaking the side-record framing, so the stream is closed",
                src[RECORD_HEADER_LEN]
            )));
        }
        let total = RECORD_HEADER_LEN + len;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }
        let mut record = src.split_to(total);
        record.advance(RECORD_HEADER_LEN);
        Ok(Some(Inbound {
            wire: record.freeze(),
            ingress: (ingress != NO_INGRESS).then_some(FaceId(ingress)),
        }))
    }
}

impl Encoder<Bytes> for SideTlvCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}

/// Append the record of `frame` (which starts with [`SIDE_MARKER`] and is at most
/// [`RECORD_MAX`] long, as a lane checks before it takes the frame) to `dst`.
pub fn put_record(dst: &mut BytesMut, frame: &[u8], ingress: Option<FaceId>) {
    debug_assert!(frame.first() == Some(&SIDE_MARKER) && frame.len() <= RECORD_MAX);
    dst.reserve(RECORD_HEADER_LEN + frame.len());
    dst.put_u8(SIDE_MARKER);
    dst.put_u64(ingress.map_or(NO_INGRESS, |f| f.0));
    dst.put_u32(frame.len() as u32);
    dst.extend_from_slice(frame);
}

/// Append the hello record to `dst`: a record of no frame, which says its writer reads side
/// records (and is the first thing its writer writes after it says so).
pub fn put_hello(dst: &mut BytesMut) {
    dst.reserve(RECORD_HEADER_LEN);
    dst.put_u8(SIDE_MARKER);
    dst.put_u64(NO_INGRESS);
    dst.put_u32(0);
}

#[derive(Default)]
struct LaneState {
    frames: VecDeque<(Bytes, Option<FaceId>)>,
    octets: usize,
    closed: bool,
}

/// The bounded queue between a face's `send_side`/`forward_side` and the [`SidePump`] that writes
/// its records.
pub(crate) struct SideLane {
    state: StdMutex<LaneState>,
    /// Wakes the pump: a frame was queued, the hello is due, or the lane closed.
    wake: Notify,
    /// Wakes the senders waiting for room: the pump took what was queued, or the lane closed.
    room: Notify,
    /// The peer reads side records: it said so (a daemon's end reads the client's hello) or this
    /// end did (a client's end writes it). A lane that is not open refuses every frame
    /// [`NotCarried`](SideRefused::NotCarried): a peer built before the record reads its stream
    /// as TLV elements and a record would put it out of step for good.
    open: AtomicBool,
    /// The hello is yet to be written.
    hello_due: AtomicBool,
}

impl SideLane {
    fn new() -> Self {
        Self {
            state: StdMutex::new(LaneState::default()),
            wake: Notify::new(),
            room: Notify::new(),
            open: AtomicBool::new(false),
            hello_due: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LaneState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `frame` may be queued at all: it starts with the marker and fits a record.
    fn check(frame: &[u8]) -> Result<(), SideRefused> {
        if frame.first() != Some(&SIDE_MARKER) {
            return Err(SideRefused::Malformed);
        }
        if frame.len() > RECORD_MAX {
            return Err(SideRefused::TooLarge {
                size: frame.len(),
                max: RECORD_MAX,
            });
        }
        Ok(())
    }

    /// Queue `frame` if there is room: [`Full`](SideRefused::Full) if not, and
    /// [`Closed`](SideRefused::Closed) if the lane is closed.
    pub(crate) fn try_push(
        &self,
        frame: &Bytes,
        ingress: Option<FaceId>,
    ) -> Result<(), SideRefused> {
        Self::check(frame)?;
        if !self.is_open() {
            return Err(SideRefused::NotCarried);
        }
        let cost = frame.len() + RECORD_HEADER_LEN;
        let mut state = self.lock();
        if state.closed {
            return Err(SideRefused::Closed);
        }
        if !Self::fits(&state, cost) {
            return Err(SideRefused::Full);
        }
        state.octets += cost;
        state.frames.push_back((frame.clone(), ingress));
        drop(state);
        self.wake.notify_one();
        Ok(())
    }

    /// Whether a frame whose record costs `cost` octets (the frame and its header) is under
    /// both bounds: the one test `try_push` and [`has_room_for`](Self::has_room_for) make.
    fn fits(state: &LaneState, cost: usize) -> bool {
        state.frames.len() < LANE_FRAMES && state.octets + cost <= LANE_OCTETS
    }

    /// Whether [`try_push`](Self::try_push) may take a frame now and not refuse it
    /// [`Full`](SideRefused::Full): fewer frames and octets wait than the bounds, or the lane is
    /// closed (which refuses another way). The read `try_push` makes first, without the frame
    /// (a frame of one octet: any frame needs at least that); room is not reserved.
    pub(crate) fn has_room(&self) -> bool {
        let state = self.lock();
        state.closed || Self::fits(&state, RECORD_HEADER_LEN + 1)
    }

    /// [`has_room`](Self::has_room) for `frame`: what `try_push` would answer for it without
    /// taking it. A frame the lane refuses another way (not a side frame, over a record, a lane
    /// the peer has not opened or that is closed) is no frame to wait for room for, as waiting
    /// would end in the same refusal, later.
    pub(crate) fn has_room_for(&self, frame: &[u8]) -> bool {
        if Self::check(frame).is_err() || !self.is_open() {
            return true;
        }
        let state = self.lock();
        state.closed || Self::fits(&state, frame.len() + RECORD_HEADER_LEN)
    }

    /// Queue `frame`, waiting for room.
    pub(crate) async fn push(
        &self,
        frame: Bytes,
        ingress: Option<FaceId>,
    ) -> Result<(), SideRefused> {
        loop {
            let room = self.room.notified();
            tokio::pin!(room);
            room.as_mut().enable();
            match self.try_push(&frame, ingress) {
                Err(SideRefused::Full) => room.await,
                other => return other,
            }
        }
    }

    /// Completes when [`try_push`](Self::try_push) may take a frame again (at once if it may).
    pub(crate) async fn ready(&self) {
        loop {
            let room = self.room.notified();
            tokio::pin!(room);
            room.as_mut().enable();
            if self.has_room() {
                return;
            }
            room.await;
        }
    }

    pub(crate) fn close(&self) {
        self.lock().closed = true;
        self.wake.notify_one();
        self.room.notify_waiters();
    }

    /// Whether side frames may go over this stream: the peer has said it reads them.
    pub(crate) fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// This end says it reads side records: the hello is written before anything else this end
    /// writes from now on, and its frames may be queued.
    pub(crate) fn open_here(&self) {
        self.hello_due.store(true, Ordering::Release);
        self.open.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    /// The peer said it reads side records (its hello was read): this end's frames may be queued.
    pub(crate) fn open_for_peer(&self) {
        self.open.store(true, Ordering::Release);
    }

    /// Whether the hello is still to be written; clears it. Called under the writer lock by
    /// whoever writes next.
    pub(crate) fn take_hello(&self) -> bool {
        self.hello_due.load(Ordering::Acquire) && self.hello_due.swap(false, Ordering::AcqRel)
    }
}

/// Writes a face's queued side records. [`StreamFace::with_side_lane`](crate::StreamFace) makes
/// one and the owner of the face runs it as a task; it ends when the face is dropped or a write
/// fails (and the lane then refuses [`Closed`](SideRefused::Closed)).
pub struct SidePump<W> {
    lane: Arc<SideLane>,
    writer: Arc<Mutex<FramedWrite<W, SideTlvCodec>>>,
}

pub(crate) fn lane_and_pump<W>(
    writer: Arc<Mutex<FramedWrite<W, SideTlvCodec>>>,
) -> (Arc<SideLane>, SidePump<W>) {
    let lane = Arc::new(SideLane::new());
    let pump = SidePump {
        lane: Arc::clone(&lane),
        writer,
    };
    (lane, pump)
}

impl<W: AsyncWrite + Unpin + Send + 'static> SidePump<W> {
    /// Write queued records, in order, until the lane closes or a write fails.
    pub async fn run(self) {
        loop {
            let wake = self.lane.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let (batch, closed) = {
                let mut state = self.lane.lock();
                state.octets = 0;
                (std::mem::take(&mut state.frames), state.closed)
            };
            let hello = self.lane.hello_due.load(Ordering::Acquire);
            if batch.is_empty() && !hello {
                if closed {
                    return;
                }
                wake.await;
                continue;
            }
            self.lane.room.notify_waiters();
            let mut writer = self.writer.lock().await;
            // The hello goes before any record, and before any packet an NDN send writes after
            // it (`StreamFace::send_bytes` takes the same flag under this lock).
            if self.lane.take_hello() {
                put_hello(writer.write_buffer_mut());
            }
            for (frame, ingress) in &batch {
                put_record(writer.write_buffer_mut(), frame, *ingress);
            }
            if SinkExt::<Bytes>::flush(&mut *writer).await.is_err() {
                drop(writer);
                self.lane.close();
                return;
            }
        }
    }
}

impl<W> Drop for SidePump<W> {
    fn drop(&mut self) {
        // A lane nobody writes would hold frames for ever: it refuses instead.
        self.lane.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(frame: &[u8], ingress: Option<FaceId>) -> BytesMut {
        let mut b = BytesMut::new();
        put_record(&mut b, frame, ingress);
        b
    }

    fn frame(len: usize) -> Bytes {
        let mut v = vec![0xA5; len];
        v[0] = SIDE_MARKER;
        Bytes::from(v)
    }

    /// A record is the marker, the ingress, the length and the frame, in that order.
    #[test]
    fn a_record_is_marker_ingress_length_frame() {
        let f = frame(5);
        let r = record(&f, Some(FaceId(7)));
        assert_eq!(r[0], 0x00);
        assert_eq!(&r[1..9], &7u64.to_be_bytes());
        assert_eq!(&r[9..13], &5u32.to_be_bytes());
        assert_eq!(&r[13..], &f[..]);
        let none = record(&f, None);
        assert_eq!(&none[1..9], &u64::MAX.to_be_bytes());
    }

    #[test]
    fn a_record_decodes_to_its_frame_and_ingress_and_leaves_what_follows() {
        let f = frame(46);
        let mut src = record(&f, Some(FaceId(9)));
        src.extend_from_slice(&[0x05, 0x01, 0xAB]);
        let got = SideTlvCodec.decode(&mut src).unwrap().unwrap();
        assert_eq!(got.wire, f);
        assert_eq!(got.ingress, Some(FaceId(9)));
        let next = SideTlvCodec.decode(&mut src).unwrap().unwrap();
        assert_eq!(&next.wire[..], &[0x05, 0x01, 0xAB]);
        assert_eq!(next.ingress, None);
        assert!(src.is_empty());
        // No ingress on the wire is no ingress.
        let mut src = record(&f, None);
        assert_eq!(
            SideTlvCodec.decode(&mut src).unwrap().unwrap().ingress,
            None
        );
    }

    /// Ordinary NDN traffic is what `TlvCodec` carries, byte for byte: every element decodes to the
    /// same bytes, whole or fed a byte at a time, and the encoder appends as is.
    #[test]
    fn ndn_traffic_is_what_tlv_codec_carries() {
        let elements: Vec<Bytes> = vec![
            Bytes::from_static(&[0x05, 0x03, 1, 2, 3]),
            Bytes::from_static(&[0x06, 0x00]),
            Bytes::from_static(&[0x64, 0x02, 9, 9]),
            Bytes::from([&[0x15u8, 0xFD, 0x01, 0x2C][..], &[7u8; 300][..]].concat()),
        ];
        let mut wire = BytesMut::new();
        for e in &elements {
            SideTlvCodec.encode(e.clone(), &mut wire).unwrap();
        }
        let mut plain = wire.clone();
        let mut whole = wire.clone();
        for e in &elements {
            assert_eq!(&TlvCodec.decode(&mut plain).unwrap().unwrap(), e);
            assert_eq!(&SideTlvCodec.decode(&mut whole).unwrap().unwrap().wire, e);
        }
        let mut drip = BytesMut::new();
        let mut out = Vec::new();
        for b in wire.iter() {
            drip.put_u8(*b);
            while let Some(i) = SideTlvCodec.decode(&mut drip).unwrap() {
                assert_eq!(i.ingress, None);
                out.push(i.wire);
            }
        }
        assert_eq!(out, elements);
    }

    #[test]
    fn a_record_split_anywhere_decodes_once_whole() {
        let f = frame(100);
        let wire = record(&f, Some(FaceId(3)));
        for cut in 0..wire.len() {
            let mut src = BytesMut::from(&wire[..cut]);
            assert_eq!(SideTlvCodec.decode(&mut src).unwrap(), None, "cut {cut}");
        }
        let mut src = wire;
        assert_eq!(SideTlvCodec.decode(&mut src).unwrap().unwrap().wire, f);
    }

    /// A frame the record's length does not allow, or that is not a side frame, closes the stream
    /// with a reason; nothing is consumed as if it were an NDN packet.
    #[test]
    fn a_bad_record_fails_closed_with_a_reason() {
        let bad = |mut src: BytesMut| SideTlvCodec.decode(&mut src).unwrap_err();
        // (A record of length zero is the hello, not an error.)
        // Length over the limit, announced by the header alone.
        let mut over = BytesMut::new();
        over.put_u8(SIDE_MARKER);
        over.put_u64(0);
        over.put_u32((RECORD_MAX + 1) as u32);
        assert!(
            bad(over)
                .to_string()
                .contains("side record of 1048577 octets")
        );
        let mut huge = BytesMut::new();
        huge.put_u8(SIDE_MARKER);
        huge.put_u64(0);
        huge.put_u32(u32::MAX);
        assert!(bad(huge).to_string().contains("1 to"));
        // A frame that does not start with the marker, seen as soon as its first octet is.
        let mut unmarked = BytesMut::new();
        unmarked.put_u8(SIDE_MARKER);
        unmarked.put_u64(0);
        unmarked.put_u32(40);
        unmarked.put_u8(0x05);
        assert!(bad(unmarked).to_string().contains("not the marker"));
        // The limit itself is fine (the frame is awaited, not refused).
        let mut at = BytesMut::new();
        at.put_u8(SIDE_MARKER);
        at.put_u64(0);
        at.put_u32(RECORD_MAX as u32);
        assert_eq!(SideTlvCodec.decode(&mut at).unwrap(), None);
    }

    /// A stream that ends inside a record is an error, not a silent end.
    #[tokio::test]
    async fn a_truncated_record_is_an_error_at_the_end_of_the_stream() {
        use futures::StreamExt;
        use tokio_util::codec::FramedRead;
        let mut wire = record(&frame(100), None).to_vec();
        wire.truncate(60);
        let mut read = FramedRead::new(&wire[..], SideTlvCodec);
        let err = read.next().await.unwrap().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(read.next().await.is_none());
    }

    /// A lane takes no frame until its peer said it reads records, and then takes them: a peer
    /// that predates the record would be put out of step by the first.
    #[test]
    fn a_lane_refuses_every_frame_until_it_is_open() {
        let lane = SideLane::new();
        assert!(!lane.is_open());
        assert_eq!(
            lane.try_push(&frame(46), None),
            Err(SideRefused::NotCarried)
        );
        lane.open_for_peer();
        assert_eq!(lane.try_push(&frame(46), None), Ok(()));
        // Opening here is saying hello: it is written once, before anything else.
        let here = SideLane::new();
        here.open_here();
        assert!(here.is_open());
        assert!(here.take_hello());
        assert!(!here.take_hello());
    }

    /// The hello is a record of no frame: 13 octets, marker, no ingress, length 0; it decodes to
    /// an `Inbound` that is none, and what follows it decodes as before.
    #[test]
    fn the_hello_is_a_record_of_no_frame() {
        let mut src = BytesMut::new();
        put_hello(&mut src);
        assert_eq!(src.len(), RECORD_HEADER_LEN);
        assert_eq!(src[0], SIDE_MARKER);
        assert_eq!(&src[1..9], &u64::MAX.to_be_bytes());
        assert_eq!(&src[9..13], &0u32.to_be_bytes());
        src.extend_from_slice(&[0x05, 0x01, 0xAB]);
        let hello = SideTlvCodec.decode(&mut src).unwrap().unwrap();
        assert!(hello.is_hello());
        let next = SideTlvCodec.decode(&mut src).unwrap().unwrap();
        assert!(!next.is_hello());
        assert_eq!(&next.wire[..], &[0x05, 0x01, 0xAB]);
    }
    #[test]
    fn a_lane_refuses_what_is_not_a_side_frame_and_what_does_not_fit() {
        let lane = SideLane::new();
        lane.open_for_peer();
        assert_eq!(
            lane.try_push(&Bytes::from_static(&[0x05, 0x00]), None),
            Err(SideRefused::Malformed)
        );
        assert_eq!(
            lane.try_push(&Bytes::new(), None),
            Err(SideRefused::Malformed)
        );
        assert_eq!(
            lane.try_push(&frame(RECORD_MAX + 1), None),
            Err(SideRefused::TooLarge {
                size: RECORD_MAX + 1,
                max: RECORD_MAX
            })
        );
        assert_eq!(lane.try_push(&frame(RECORD_MAX), None), Ok(()));
    }

    #[test]
    fn a_lane_is_bounded_in_frames_and_in_octets() {
        let lane = SideLane::new();
        lane.open_for_peer();
        for _ in 0..LANE_FRAMES {
            lane.try_push(&frame(46), None).unwrap();
        }
        assert_eq!(lane.try_push(&frame(46), None), Err(SideRefused::Full));

        let lane = SideLane::new();
        lane.open_for_peer();
        let mut n = 0;
        while lane.try_push(&frame(RECORD_MAX), None).is_ok() {
            n += 1;
        }
        assert!(n >= 1 && n * (RECORD_MAX + RECORD_HEADER_LEN) <= LANE_OCTETS);
        lane.close();
        assert_eq!(lane.try_push(&frame(46), None), Err(SideRefused::Closed));
    }
}
