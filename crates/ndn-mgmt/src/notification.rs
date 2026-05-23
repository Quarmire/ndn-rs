//! `NotificationStream<T>` — per-module persistent-Interest event streams.
//!
//! Mirrors NFD `daemon/mgmt/notification-stream.hpp`. Each event gets a
//! monotonic sequence number; subscribers issue a persistent Interest at
//! `<prefix>/seq=<N>` (using `SequenceNumberComponent` TLV, per ndn-cxx
//! `mgmt/dispatcher.cpp:324` `appendSequenceNumber`). The producer
//! serves the cached Data immediately when seq is known, or holds the
//! Interest until [`NotificationStream::publish`] raises seq to `N`.
//!
//! Recent events are kept in a bounded ring (default
//! [`NOTIFICATION_RING_CAP`]) so a late subscriber can fetch a missed
//! event without re-fetching the whole stream. Data is signed
//! `DigestSha256` for v1; signed notifications are a follow-up.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_engine::ForwarderEngine;
use ndn_packet::{Name, encode::encode_data_unsigned};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Number of recent events the stream keeps for late subscribers.
const NOTIFICATION_RING_CAP: usize = 100;

/// Per-module event type carried in a [`NotificationStream`].
pub trait NotificationEvent: Send + Sync + Clone + 'static {
    fn encode(&self) -> Bytes;
}

/// Persistent-Interest event stream — one per NFD-style module.
pub struct NotificationStream<T: NotificationEvent> {
    prefix: Name,
    seq: AtomicU64,
    ring: Mutex<VecDeque<(u64, Bytes)>>,
    notify: Notify,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: NotificationEvent> NotificationStream<T> {
    /// Construct a fresh stream rooted at `prefix`; the producer task
    /// is not started until [`Self::install`] runs.
    pub fn new(prefix: Name) -> Arc<Self> {
        Arc::new(Self {
            prefix,
            seq: AtomicU64::new(0),
            ring: Mutex::new(VecDeque::with_capacity(NOTIFICATION_RING_CAP)),
            notify: Notify::new(),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Publish a new event: bumps seq, encodes the Data, rings it, and
    /// wakes any subscriber blocked on the next-seq.
    pub fn publish(&self, event: T) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let content = event.encode();
        let name = self.prefix.clone().append_sequence_num(seq);
        let data_wire = encode_data_unsigned(&name, &content);
        if let Ok(mut g) = self.ring.lock() {
            g.push_back((seq, data_wire));
            while g.len() > NOTIFICATION_RING_CAP {
                g.pop_front();
            }
        }
        self.notify.notify_waiters();
    }

    /// Most recently published sequence (0 if no event has been published).
    pub fn current_seq(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    fn lookup(&self, seq: u64) -> Option<Bytes> {
        let g = self.ring.lock().ok()?;
        g.iter().find(|(s, _)| *s == seq).map(|(_, b)| b.clone())
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

    /// Wait up to `timeout` for the next publish; `None` on timeout.
    async fn wait_for_publish(
        &self,
        timeout: std::time::Duration,
        cancel: &CancellationToken,
    ) -> Option<u64> {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            _ = tokio::time::sleep(timeout) => None,
            _ = &mut notified => Some(self.current_seq()),
        }
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

        let stream = self;
        let task_cancel = cancel.clone();
        tokio::spawn(async move {
            stream.serve(handle, task_cancel).await;
        });
    }

    async fn serve(
        self: Arc<Self>,
        handle: ndn_face_local::InProcHandle,
        cancel: CancellationToken,
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
            let stream = Arc::clone(&self);
            let h = Arc::clone(&handle);
            let cancel_child = cancel.child_token();
            tokio::spawn(async move {
                serve_one(stream, h, requested_seq, cancel_child).await;
            });
        }
    }
}

async fn serve_one<T: NotificationEvent>(
    stream: Arc<NotificationStream<T>>,
    handle: Arc<ndn_face_local::InProcHandle>,
    requested_seq: Option<u64>,
    cancel: CancellationToken,
) {
    // No seq in name → serve latest (or skip if none yet).
    let requested = match requested_seq {
        Some(s) => s,
        None => stream.current_seq().max(1),
    };

    if let Some(wire) = stream.lookup(requested) {
        let _ = handle.send(wire).await;
        return;
    }

    // Long-poll, bounded; client re-fetches with same seq on timeout.
    const WAIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(4);
    let _ = stream.wait_for_publish(WAIT_BUDGET, &cancel).await;
    if let Some(wire) = stream.lookup(requested) {
        let _ = handle.send(wire).await;
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
