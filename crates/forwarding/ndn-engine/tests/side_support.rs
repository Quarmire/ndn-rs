//! Test faces for the side-frame fan-out tests: a transport that records what
//! the engine hands it (NDN packets and side frames, with the ingress face a
//! side frame came over), can be told to refuse side frames, and can be paired
//! with another face so two engines form a hop chain.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_runtime::{BoxFuture, Now, Runtime, Sleep, Spawn};
use ndn_transport::side_header::{AnswerPrefix, QueryPrefix, SideHeader, SideKind, UpOp, UpRecord};
use ndn_transport::{
    FaceError, FaceId, FaceKind, FaceTrust, SIDE_MARKER, SideClass, SideRefused, Transport,
};
use tokio::sync::{Mutex as AsyncMutex, mpsc};

/// One side frame a face was handed.
#[derive(Clone, Debug)]
pub struct SideRecord {
    pub frame: Bytes,
    pub class: SideClass,
    /// The face the frame arrived over, as `forward_side_from` was told.
    pub ingress: Option<FaceId>,
}

/// What a test face saw, shared with its [`Handle`].
#[derive(Default)]
pub struct Log {
    /// Every NDN packet the engine sent on the face (`send_bytes`).
    pub sent: Mutex<Vec<Bytes>>,
    /// Every side frame the engine handed the face.
    pub side: Mutex<Vec<SideRecord>>,
    /// `forward_side` answers `Full` while set.
    pub full: AtomicBool,
    /// `forward_side` answers `Unsupported` while set.
    pub unsupported: AtomicBool,
    /// The face reports that it carries the datagram class only.
    pub datagram_only: AtomicBool,
    /// The face carries no side frames at all (`side_frame_max` is 0).
    pub carries_none: AtomicBool,
    /// The datagram limit the face reports and enforces, as a link does (a datagram frame over
    /// it is refused `TooLarge`, never cut); 0: the default 10,000, enforced by nothing.
    pub side_max: std::sync::atomic::AtomicUsize,
}

/// The test's end of a face.
pub struct Handle {
    pub id: FaceId,
    tx: mpsc::UnboundedSender<Bytes>,
    pub log: Arc<Log>,
}

impl Handle {
    /// Deliver `wire` to the engine as if it arrived on the face.
    pub fn inject(&self, wire: Bytes) {
        self.tx.send(wire).expect("face reader is gone");
    }

    /// Close the face's receive side: the engine's reader sees `Closed`.
    pub fn close(self) {
        drop(self.tx);
    }

    /// Set the datagram limit the face reports from now on, and enforces.
    pub fn set_side_max(&self, max: usize) {
        self.log.side_max.store(max, Ordering::Relaxed);
    }

    pub fn sent(&self) -> Vec<Bytes> {
        self.log.sent.lock().unwrap().clone()
    }

    pub fn side(&self) -> Vec<SideRecord> {
        self.log.side.lock().unwrap().clone()
    }

    /// Wait until `n` NDN packets were sent on the face and return them.
    pub async fn wait_sent(&self, n: usize) -> Vec<Bytes> {
        for _ in 0..400 {
            let sent = self.sent();
            if sent.len() >= n {
                return sent;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "face {}: {} NDN packets sent, expected {n}",
            self.id,
            self.sent().len()
        );
    }

    /// Wait until `n` side frames were handed to the face and return them.
    pub async fn wait_side(&self, n: usize) -> Vec<SideRecord> {
        for _ in 0..400 {
            let side = self.side();
            if side.len() >= n {
                return side;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "face {}: {} side frames handed, expected {n}",
            self.id,
            self.side().len()
        );
    }
}

/// A transport the test drives.
pub struct TestFace {
    id: FaceId,
    kind: FaceKind,
    program: bool,
    inbox: AsyncMutex<mpsc::UnboundedReceiver<Bytes>>,
    log: Arc<Log>,
    /// Where `send_bytes` and `forward_side*` deliver: the far end's inbox.
    peer: Mutex<Option<mpsc::UnboundedSender<Bytes>>>,
}

fn make(id: FaceId, kind: FaceKind, program: bool) -> (TestFace, Handle) {
    let (tx, rx) = mpsc::unbounded_channel();
    let log = Arc::new(Log::default());
    (
        TestFace {
            id,
            kind,
            program,
            inbox: AsyncMutex::new(rx),
            log: Arc::clone(&log),
            peer: Mutex::new(None),
        },
        Handle { id, tx, log },
    )
}

/// A face of `kind` that is a program face (its Data is not validated).
pub fn face(id: u64, kind: FaceKind) -> (TestFace, Handle) {
    make(FaceId(id), kind, true)
}

/// A program face of `kind` whose medium has no ordered stream (as an Ethernet segment): it
/// reports that it carries the datagram class only.
pub fn datagram_only_face(id: u64, kind: FaceKind) -> (TestFace, Handle) {
    let (face, handle) = make(FaceId(id), kind, true);
    handle.log.datagram_only.store(true, Ordering::Relaxed);
    (face, handle)
}

/// A program face of `kind` that carries no side frames (as a TCP, UDP or Unix socket face): its
/// `side_frame_max` is 0.
pub fn no_side_face(id: u64, kind: FaceKind) -> (TestFace, Handle) {
    let (face, handle) = make(FaceId(id), kind, true);
    handle.log.carries_none.store(true, Ordering::Relaxed);
    (face, handle)
}

/// Two faces joined as a link: what the first sends (NDN or side) arrives on
/// the second and the other way round. Both are `kind`.
pub fn pair(a: u64, b: u64, kind: FaceKind) -> ((TestFace, Handle), (TestFace, Handle)) {
    let (fa, ha) = make(FaceId(a), kind, true);
    let (fb, hb) = make(FaceId(b), kind, true);
    *fa.peer.lock().unwrap() = Some(hb.tx.clone());
    *fb.peer.lock().unwrap() = Some(ha.tx.clone());
    ((fa, ha), (fb, hb))
}

impl TestFace {
    fn deliver(&self, wire: Bytes) {
        if let Some(peer) = self.peer.lock().unwrap().as_ref() {
            let _ = peer.send(wire);
        }
    }
}

impl Transport for TestFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        self.kind
    }
    fn trust(&self) -> FaceTrust {
        if self.program {
            FaceTrust::Program
        } else {
            FaceTrust::Validated
        }
    }
    fn side_frame_max(&self) -> usize {
        if self.log.carries_none.load(Ordering::Relaxed) {
            return 0;
        }
        match self.log.side_max.load(Ordering::Relaxed) {
            0 => 10_000,
            max => max,
        }
    }
    /// Both classes, unless the face is a datagram-only one ([`datagram_only_face`]) or carries
    /// none ([`no_side_face`]).
    fn side_carries(&self, class: SideClass) -> bool {
        self.side_frame_max() != 0
            && (class == SideClass::Datagram || !self.log.datagram_only.load(Ordering::Relaxed))
    }
    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        self.forward_side_from(frame, class, FaceId::INVALID)
    }
    fn forward_side_from(
        &self,
        frame: Bytes,
        class: SideClass,
        ingress: FaceId,
    ) -> Result<(), SideRefused> {
        if self.log.full.load(Ordering::Relaxed) {
            return Err(SideRefused::Full);
        }
        if self.log.unsupported.load(Ordering::Relaxed) {
            return Err(SideRefused::Unsupported);
        }
        let limit = self.log.side_max.load(Ordering::Relaxed);
        if limit != 0 && class == SideClass::Datagram && frame.len() > limit {
            return Err(SideRefused::TooLarge {
                size: frame.len(),
                max: limit,
            });
        }
        self.log.side.lock().unwrap().push(SideRecord {
            frame: frame.clone(),
            class,
            ingress: (ingress != FaceId::INVALID).then_some(ingress),
        });
        self.deliver(frame);
        Ok(())
    }
    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        self.log.sent.lock().unwrap().push(wire.clone());
        self.deliver(wire);
        Ok(())
    }
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.inbox
            .lock()
            .await
            .recv()
            .await
            .ok_or(FaceError::Closed)
    }
}

/// A marked frame of `kind` and `class` on route `id`, padded to `len` octets.
pub fn frame(class: SideClass, kind: SideKind, id: u64, len: usize) -> Bytes {
    let mut v = SideHeader::new(class, kind, id)
        .expect("kind on its class")
        .encode()
        .to_vec();
    v.resize(len.max(v.len()), 0xA5);
    assert_eq!(v[0], SIDE_MARKER);
    Bytes::from(v)
}

/// A `DATA` datagram frame of `len` octets on route `id`.
pub fn data_frame(id: u64, len: usize) -> Bytes {
    frame(SideClass::Datagram, SideKind::Data, id, len)
}

/// An `UP` record (padded to 46 octets) on route `id`.
pub fn up(id: u64, op: UpOp) -> Bytes {
    Bytes::copy_from_slice(&UpRecord { id, op }.encode())
}

/// A `QUERY` datagram on route `id` with `token` and a ttl of `ttl_ticks` (100 ms each), padded to
/// `len` octets.
pub fn query(id: u64, token: u64, ttl_ticks: u8, len: usize) -> Bytes {
    let mut v = QueryPrefix {
        id,
        token,
        ttl_ticks,
    }
    .encode()
    .to_vec();
    v.resize(len.max(v.len()), 0xA5);
    Bytes::from(v)
}

/// An `ANSWER` on `class` on route `id` to the query with `token`, padded to `len` octets.
pub fn answer(class: SideClass, id: u64, token: u64, len: usize) -> Bytes {
    let mut v = AnswerPrefix { class, id, token }.encode().to_vec();
    v.resize(len.max(v.len()), 0xA5);
    Bytes::from(v)
}

/// Which of the engine's sleeps a [`WarpRuntime`] shortens.
#[derive(Clone, Copy)]
pub enum Warp {
    /// Every sleep is a thousand times shorter.
    All,
    /// The idle reaper's 30 s sleep is a thousand times shorter and the 1 s
    /// sleeps (the side sweep among them) do not end within the test: only
    /// the reaper can remove an idle face.
    ReaperOnly,
    /// The 1 s sleeps (the side sweep among them) do not end within the test,
    /// so a face's routes can only have gone with the face itself.
    Frozen,
}

/// A runtime whose clocks are the test's, so the engine's periodic tasks (the 1 s sweep, the
/// 30 s idle reaper) act on logical time the test sets, and whose chosen sleeps are a thousand
/// times shorter, so the test does not wait for them. Its wall clock (`unix_nanos`, `clock`)
/// and its monotonic clock (`now`) are separate: [`advance`](Self::advance) moves both, as time
/// passing does; [`step_wall`](Self::step_wall) moves only the wall clock, as a host's clock
/// being set does (NTP, a VM resuming).
pub struct WarpRuntime {
    pub clock: Arc<AtomicU64>,
    mono: AtomicU64,
    warp: Warp,
}

impl WarpRuntime {
    pub fn new(start_ns: u64, warp: Warp) -> Arc<Self> {
        Arc::new(Self {
            clock: Arc::new(AtomicU64::new(start_ns)),
            mono: AtomicU64::new(0),
            warp,
        })
    }

    /// Time passes: both clocks move.
    pub fn advance(&self, by: Duration) {
        self.clock
            .fetch_add(by.as_nanos() as u64, Ordering::Relaxed);
        self.mono.fetch_add(by.as_nanos() as u64, Ordering::Relaxed);
    }

    /// The host's wall clock is set forward by `by`; no time passed.
    pub fn step_wall(&self, by: Duration) {
        self.clock
            .fetch_add(by.as_nanos() as u64, Ordering::Relaxed);
    }
}

impl Spawn for WarpRuntime {
    fn spawn(&self, fut: BoxFuture) {
        tokio::spawn(fut);
    }
}
impl Sleep for WarpRuntime {
    fn sleep(&self, dur: Duration) -> BoxFuture {
        let one_second = Duration::from_secs(1);
        let reaper = Duration::from_secs(30);
        let dur = match self.warp {
            Warp::All => dur / 1000,
            Warp::ReaperOnly if dur == reaper => dur / 1000,
            Warp::ReaperOnly if dur == one_second => Duration::from_secs(3600),
            Warp::Frozen if dur == one_second => Duration::from_secs(3600),
            Warp::ReaperOnly | Warp::Frozen => dur,
        };
        Box::pin(async move { tokio::time::sleep(dur).await })
    }
}
impl Now for WarpRuntime {
    /// Real monotonic time plus what the test advanced.
    fn now(&self) -> ndn_runtime::Instant {
        ndn_runtime::Instant::now() + Duration::from_nanos(self.mono.load(Ordering::Relaxed))
    }
    fn unix_nanos(&self) -> u64 {
        self.clock.load(Ordering::Relaxed)
    }
}
impl Runtime for WarpRuntime {}
