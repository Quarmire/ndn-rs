//! A carrier for tests: one direction of a link held in memory (docs/specs/channel.md, The carrier
//! a face must provide).
//!
//! The sender side is a [`Carrier`]; the receiver side is what the test calls: [`Link::pop_datagram`]
//! and [`Link::pop_stream`] hand out the queued frames, in order. The link can be made to behave as
//! a bad one: a datagram **capacity** (past it `try_send_datagram` says `Full`, as the headroom
//! rule would), a stream **window** in octets (past it `send_stream` waits, as flow control
//! would), a datagram size that **shrinks**, and **loss, duplication and reordering** of
//! datagrams, seeded and deterministic. [`Link::stats`] counts the frames and their message
//! counts.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::Notify;

use super::carrier::{Carrier, CarrierFuture, CarrierRefused};

/// How a [`Link`] behaves.
#[derive(Clone, Debug)]
pub(crate) struct LinkConfig {
    /// The largest datagram frame.
    pub datagram_max: usize,
    /// Whether there is a stream.
    pub has_stream: bool,
    /// How many datagram frames may be queued before `try_send_datagram` says `Full`.
    pub datagram_capacity: usize,
    /// How many octets may be queued on the stream before `send_stream` waits (a frame is taken
    /// whole when the stream is empty, however large).
    pub stream_window: usize,
    /// The seed of loss, duplication and reordering.
    pub seed: u64,
    /// Datagrams lost, in thousandths.
    pub loss: u32,
    /// Datagrams duplicated, in thousandths.
    pub duplicate: u32,
    /// Datagrams that overtake the one before them, in thousandths.
    pub reorder: u32,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            datagram_max: 1_400,
            has_stream: true,
            datagram_capacity: 64,
            stream_window: 1 << 20,
            seed: 1,
            loss: 0,
            duplicate: 0,
            reorder: 0,
        }
    }
}

/// What a link counted.
#[derive(Clone, Debug, Default)]
pub(crate) struct LinkStats {
    /// Datagram frames taken (before any loss).
    pub datagrams: u64,
    /// Stream frames taken.
    pub stream_frames: u64,
    /// `try_send_datagram` calls that said `Full`.
    pub full: u64,
    /// Datagrams lost, duplicated, reordered.
    pub lost: u64,
    /// Datagrams duplicated.
    pub duplicated: u64,
    /// Datagrams that overtook another.
    pub reordered: u64,
    /// `DATA` frames by the messages they carry.
    pub by_count: BTreeMap<u8, u64>,
    /// `CONTROL` frames taken.
    pub control_frames: u64,
}

struct LinkState {
    cfg: LinkConfig,
    datagrams: VecDeque<Bytes>,
    stream: VecDeque<Bytes>,
    stream_bytes: usize,
    forced_full: bool,
    shrinks: VecDeque<usize>,
    ready: Vec<Box<dyn FnOnce() + Send>>,
    rng: u64,
    stats: LinkStats,
}

impl LinkState {
    fn next(&mut self) -> u32 {
        // xorshift64*: deterministic from the seed.
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u32 % 1000
    }

    fn has_room(&self) -> bool {
        !self.forced_full && self.datagrams.len() < self.cfg.datagram_capacity
    }

    fn note(&mut self, frame: &[u8]) {
        match frame.get(1).map(|b| b & 0x0f) {
            Some(0) => {
                *self.stats.by_count.entry(frame[19]).or_default() += 1;
            }
            Some(2) => self.stats.control_frames += 1,
            _ => {}
        }
    }
}

/// One direction of a link.
pub(crate) struct Link {
    state: Mutex<LinkState>,
    stream_room: Notify,
}

impl Link {
    /// A link that behaves as `cfg` says.
    pub(crate) fn new(cfg: LinkConfig) -> Arc<Link> {
        Arc::new(Link {
            state: Mutex::new(LinkState {
                rng: cfg.seed.max(1),
                cfg,
                datagrams: VecDeque::new(),
                stream: VecDeque::new(),
                stream_bytes: 0,
                forced_full: false,
                shrinks: VecDeque::new(),
                ready: Vec::new(),
                stats: LinkStats::default(),
            }),
            stream_room: Notify::new(),
        })
    }

    /// A link with the default behaviour.
    pub(crate) fn plain() -> Arc<Link> {
        Link::new(LinkConfig::default())
    }

    /// What the link counted.
    pub(crate) fn stats(&self) -> LinkStats {
        self.state.lock().stats.clone()
    }

    /// Say `Full` to every datagram while `full` (a busy link), and call the waiting drains when
    /// it stops.
    pub(crate) fn set_full(&self, full: bool) {
        self.state.lock().forced_full = full;
        if !full {
            self.run_ready();
        }
    }

    /// The path's datagram size is now `max`.
    pub(crate) fn set_datagram_max(&self, max: usize) {
        self.state.lock().cfg.datagram_max = max;
    }

    /// The next datagram is refused `TooLarge`, and the path's size is `max` from then on: the
    /// path's size fell between the moment the sender read it and the moment it sent. Calls queue:
    /// each refuses one datagram.
    pub(crate) fn shrink_on_next_send(&self, max: usize) {
        self.state.lock().shrinks.push_back(max);
    }

    /// Datagrams waiting to be received.
    pub(crate) fn queued_datagrams(&self) -> usize {
        self.state.lock().datagrams.len()
    }

    /// Octets waiting on the stream.
    pub(crate) fn queued_stream_bytes(&self) -> usize {
        self.state.lock().stream_bytes
    }

    /// Drains registered with [`Carrier::on_ready`] that were not called yet.
    pub(crate) fn waiting_drains(&self) -> usize {
        self.state.lock().ready.len()
    }

    /// The next datagram, as the receiver sees it (after loss, duplication and reordering).
    pub(crate) fn pop_datagram(&self) -> Option<Bytes> {
        let frame = self.state.lock().datagrams.pop_front();
        if frame.is_some() {
            self.run_ready();
        }
        frame
    }

    /// The next frame of the stream, in order.
    pub(crate) fn pop_stream(&self) -> Option<Bytes> {
        let frame = {
            let mut st = self.state.lock();
            let frame = st.stream.pop_front()?;
            st.stream_bytes -= frame.len();
            frame
        };
        self.stream_room.notify_waiters();
        Some(frame)
    }

    /// Every datagram waiting.
    pub(crate) fn take_datagrams(&self) -> Vec<Bytes> {
        std::iter::from_fn(|| self.pop_datagram()).collect()
    }

    /// Every frame waiting on the stream.
    pub(crate) fn take_stream(&self) -> Vec<Bytes> {
        std::iter::from_fn(|| self.pop_stream()).collect()
    }

    fn run_ready(&self) {
        let ready = {
            let mut st = self.state.lock();
            if !st.has_room() {
                return;
            }
            std::mem::take(&mut st.ready)
        };
        for drain in ready {
            drain();
        }
    }
}

impl Carrier for Link {
    fn datagram_max(&self) -> usize {
        self.state.lock().cfg.datagram_max
    }

    fn has_stream(&self) -> bool {
        self.state.lock().cfg.has_stream
    }

    fn try_send_datagram(&self, frame: Bytes) -> Result<(), CarrierRefused> {
        let mut st = self.state.lock();
        if let Some(max) = st.shrinks.pop_front() {
            st.cfg.datagram_max = max;
            return Err(CarrierRefused::TooLarge { max });
        }
        if frame.len() > st.cfg.datagram_max {
            return Err(CarrierRefused::TooLarge {
                max: st.cfg.datagram_max,
            });
        }
        if !st.has_room() {
            st.stats.full += 1;
            return Err(CarrierRefused::Full);
        }
        st.stats.datagrams += 1;
        st.note(&frame);
        if st.next() < st.cfg.loss {
            st.stats.lost += 1;
            return Ok(());
        }
        let overtakes = st.next() < st.cfg.reorder && !st.datagrams.is_empty();
        let twice = st.next() < st.cfg.duplicate;
        let copies = if twice { 2 } else { 1 };
        if twice {
            st.stats.duplicated += 1;
        }
        for _ in 0..copies {
            if overtakes {
                st.stats.reordered += 1;
                let at = st.datagrams.len() - 1;
                st.datagrams.insert(at, frame.clone());
            } else {
                st.datagrams.push_back(frame.clone());
            }
        }
        Ok(())
    }

    fn send_stream(&self, frame: Bytes) -> CarrierFuture<'_, Result<(), CarrierRefused>> {
        Box::pin(async move {
            loop {
                let notified = {
                    let mut st = self.state.lock();
                    if !st.cfg.has_stream {
                        return Err(CarrierRefused::Closed);
                    }
                    if st.stream.is_empty() || st.stream_bytes + frame.len() <= st.cfg.stream_window
                    {
                        st.stream_bytes += frame.len();
                        st.stats.stream_frames += 1;
                        st.note(&frame);
                        st.stream.push_back(frame);
                        return Ok(());
                    }
                    self.stream_room.notified()
                };
                notified.await;
            }
        })
    }

    fn on_ready(&self, drain: Box<dyn FnOnce() + Send>) {
        let now = {
            let mut st = self.state.lock();
            if st.has_room() {
                Some(drain)
            } else {
                st.ready.push(drain);
                None
            }
        };
        if let Some(drain) = now {
            drain();
        }
    }
}
