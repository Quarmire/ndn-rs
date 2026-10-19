//! `NotificationStream<T>` — per-module persistent-Interest event streams.
//!
//! Mirrors NFD `daemon/mgmt/notification-stream.hpp`. Each event gets a
//! monotonic sequence number; subscribers issue a persistent Interest at
//! `<prefix>/seq=<N>` (using `SequenceNumberComponent` TLV, per ndn-cxx
//! `mgmt/dispatcher.cpp:324` `appendSequenceNumber`). The producer
//! serves the cached Data immediately when seq is known, or holds the
//! Interest — for its lifetime, at most [`MAX_HOLD`] — until
//! [`NotificationStream::publish`] raises seq to `N`.
//!
//! Recent events are kept in a bounded ring (`NOTIFICATION_RING_CAP`) so a
//! late subscriber can fetch a missed event without re-fetching the whole
//! stream. A stream whose event type has a resync answer
//! ([`NotificationEvent::resync`]) gives it, at the requested name, to a
//! subscriber asking for an event it no longer holds — dropped from the
//! ring, from before this stream started ([`NotificationStream::starting_after`]),
//! or not yet numbered while an earlier one is still to come — so the
//! subscriber re-lists and continues at the next event. Data is signed
//! `DigestSha256` for v1; signed notifications are a follow-up.

use portable_atomic::AtomicU64;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::ForwarderEngine;
use ndn_packet::{Name, encode::encode_data_unsigned};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Number of recent events the stream keeps for late subscribers.
const NOTIFICATION_RING_CAP: usize = 100;

/// How long the producer holds a subscriber's Interest at most (it holds
/// it for the Interest's lifetime, the NDN default 4 s when it has none).
pub const MAX_HOLD: Duration = Duration::from_secs(60);
const DEFAULT_HOLD: Duration = Duration::from_secs(4);

/// Per-module event type carried in a [`NotificationStream`].
pub trait NotificationEvent: Send + Sync + Clone + 'static {
    fn encode(&self) -> Bytes;

    /// The content answering a subscriber that asked for an event the
    /// stream does not hold: re-list, then continue at sequence `next`.
    /// `None` (the NFD streams): such an Interest is left unanswered.
    fn resync(_next: u64) -> Option<Bytes> {
        None
    }
}

/// Persistent-Interest event stream — one per NFD-style module.
pub struct NotificationStream<T: NotificationEvent> {
    prefix: Name,
    /// The sequence number before this stream's first event.
    start: u64,
    seq: AtomicU64,
    ring: Mutex<VecDeque<(u64, Bytes)>>,
    notify: Notify,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: NotificationEvent> NotificationStream<T> {
    /// Construct a fresh stream rooted at `prefix`; the producer task
    /// is not started until [`Self::install`] runs.
    pub fn new(prefix: Name) -> Arc<Self> {
        Self::starting_after(prefix, 0)
    }

    /// As [`new`](Self::new), numbering the first event `start + 1`. A
    /// stream numbered from a value its previous runs never reached (e.g.
    /// the start time in microseconds) tells a subscriber resuming across a
    /// restart that it missed events, instead of handing it a new event
    /// under a number it took for an old one.
    pub fn starting_after(prefix: Name, start: u64) -> Arc<Self> {
        Arc::new(Self {
            prefix,
            start,
            seq: AtomicU64::new(start),
            ring: Mutex::new(VecDeque::with_capacity(NOTIFICATION_RING_CAP)),
            notify: Notify::new(),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Publish a new event: bumps seq, encodes the Data, rings it, and
    /// wakes any subscriber blocked on the next-seq.
    pub fn publish(&self, event: T) {
        let content = event.encode();
        {
            // Numbered under the ring's lock, so the ring stays in order.
            let mut g = self
                .ring
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
            let name = self.prefix.clone().append_sequence_num(seq);
            g.push_back((seq, encode_data_unsigned(&name, &content)));
            while g.len() > NOTIFICATION_RING_CAP {
                g.pop_front();
            }
        }
        self.notify.notify_waiters();
    }

    /// Most recently published sequence (the start, 0 by default, if no
    /// event has been published).
    pub fn current_seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    /// The prefix subscribers fetch under.
    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// What answers a request for `requested` now: the event, a resync
    /// (when `T` has one) for an event this stream does not hold, or
    /// nothing yet (the next event, or a later one while an earlier one is
    /// still to come and `T` has no resync).
    fn answer(&self, requested: u64) -> Option<Bytes> {
        let (oldest, current) = {
            let g = self.ring.lock().ok()?;
            if let Some((_, wire)) = g.iter().find(|(s, _)| *s == requested) {
                return Some(wire.clone());
            }
            (g.front().map(|(s, _)| *s), self.current_seq())
        };
        let next = current + 1;
        let gone = requested <= self.start || oldest.is_some_and(|o| requested < o);
        let ahead = requested > next;
        if !(gone || ahead) {
            return None;
        }
        let content = T::resync(next)?;
        let name = self.prefix.clone().append_sequence_num(requested);
        Some(encode_data_unsigned(&name, &content))
    }

    /// The newest event's Data, if any.
    fn newest(&self) -> Option<Bytes> {
        let g = self.ring.lock().ok()?;
        g.back().map(|(_, b)| b.clone())
    }

    /// Snapshot of encoded event-payload bytes currently in the ring,
    /// oldest-first. Test-only: production subscribers read the wire.
    pub fn recent_event_bytes(&self) -> Vec<Bytes> {
        let Ok(g) = self.ring.lock() else {
            return Vec::new();
        };
        g.iter()
            .map(|(_, data_wire)| {
                ndn_packet::Data::decode(data_wire.clone())
                    .ok()
                    .and_then(|d| d.content().cloned())
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Mount the notification producer on `engine`. Call once per stream.
    pub fn install(self: Arc<Self>, engine: &ForwarderEngine, cancel: CancellationToken) {
        use ndn_engine::FibNexthop;
        let face_id = engine.faces().alloc_id();
        let (face, handle) = ndn_face_local::InProcFace::new_kind(
            face_id,
            32,
            ndn_transport::face::FaceKind::Internal,
        );
        engine.add_face(face, cancel.child_token());
        engine
            .fib()
            .set_nexthops(&self.prefix, vec![FibNexthop { face_id, cost: 0 }]);

        // Portable spawn: `tokio::spawn` panics in the browser (no Tokio
        // reactor). The engine runtime is Tokio on native, `spawn_local` on wasm.
        let rt = engine.runtime();
        let serve_rt = Arc::clone(&rt);
        let stream = self;
        let task_cancel = cancel.clone();
        rt.spawn(Box::pin(async move {
            stream.serve(handle, task_cancel, serve_rt).await;
        }));
    }

    async fn serve(
        self: Arc<Self>,
        handle: ndn_face_local::InProcHandle,
        cancel: CancellationToken,
        rt: Arc<dyn ndn_engine::Runtime>,
    ) {
        use ndn_packet::Interest;
        let handle = Arc::new(handle);
        loop {
            let tagged = tokio::select! {
                _ = cancel.cancelled() => break,
                r = handle.recv_tagged() => match r {
                    Some(t) => t,
                    None    => break,
                },
            };
            let interest = match Interest::decode(tagged.wire) {
                Ok(i) => i,
                Err(_) => continue,
            };

            let requested_seq = parse_seq_num(&interest.name);
            let hold = interest.lifetime().unwrap_or(DEFAULT_HOLD).min(MAX_HOLD);
            let stream = Arc::clone(&self);
            let h = Arc::clone(&handle);
            let cancel_child = cancel.child_token();
            rt.spawn(Box::pin(async move {
                serve_one(stream, h, requested_seq, hold, cancel_child).await;
            }));
        }
    }
}

async fn serve_one<T: NotificationEvent>(
    stream: Arc<NotificationStream<T>>,
    handle: Arc<ndn_face_local::InProcHandle>,
    requested_seq: Option<u64>,
    hold: Duration,
    cancel: CancellationToken,
) {
    // No seq in name → serve the newest event, or the next one.
    let requested = match requested_seq {
        Some(s) => s,
        None => match stream.newest() {
            Some(wire) => {
                let _ = handle.send(wire).await;
                return;
            }
            None => stream.current_seq() + 1,
        },
    };

    // Long-poll for the Interest's lifetime; the client asks again for the
    // same seq when it expires unanswered.
    let deadline = tokio::time::sleep(hold);
    tokio::pin!(deadline);
    loop {
        // Armed before looking, so a publish in between is not missed.
        let published = stream.notify.notified();
        tokio::pin!(published);
        published.as_mut().enable();
        if let Some(wire) = stream.answer(requested) {
            let _ = handle.send(wire).await;
            return;
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = &mut deadline => return,
            _ = &mut published => {}
        }
    }
}

fn parse_seq_num(name: &Name) -> Option<u64> {
    let last = name.components().last()?;
    if last.typ != ndn_packet::tlv_type::SEQUENCE_NUM {
        return None;
    }
    let mut n: u64 = 0;
    for b in last.value.as_ref() {
        n = (n << 8) | u64::from(*b);
    }
    Some(n)
}
