//! Client-side connection demultiplexer.
//!
//! A bare [`Connection`] is a single ordered byte pipe: `send` and `recv`. That
//! is fine for *one* consumer **or** *one* producer, but two readers on the same
//! connection race — whoever calls [`Connection::recv`] first gets the next
//! packet, regardless of whether it was meant for them. That breaks any endpoint
//! that must serve and fetch at once: a node running a producer (e.g. a
//! RemoteSigner responder) while it also fetches, or — the motivating case —
//! reflexive forwarding, where the advertiser sends a forward Interest *and*
//! serves the producer's reverse pulls on the same face.
//!
//! [`DemuxConnection`] wraps an inner [`Connection`] and owns the single
//! `recv` loop, routing each inbound packet:
//!
//! - a **bare Interest** whose name falls under a registered serve prefix
//!   (longest match wins) → that prefix's serve channel;
//! - a **Data or Nack answering a pending Interest** → every [`Replies`]
//!   stream that registered that Interest ([`Replies::expect`]);
//! - **everything else** (unmatched Data/Nacks, unmatched Interests) → a
//!   fallback queue that [`DemuxConnection`]'s own [`Connection::recv`] drains.
//!
//! So `DemuxConnection` *is* a [`Connection`]: every
//! [`Consumer`](crate::Consumer) fetch over it registers its Interest on its
//! own [`Replies`] stream ([`Connection::replies`]) and receives exactly the
//! reply that answers it, however many fetches share the connection, while
//! serves are peeled off to their handlers
//! ([`DemuxConnection::serve`] / [`DemuxConnection::serve_scoped`]).
//!
//! Replies are matched the way `ndn-cxx`'s `Face` matches its pending
//! Interest table:
//!
//! - **Data** satisfies every pending Interest it matches (exact name,
//!   `CanBePrefix` descendant, implicit digest, parameters digest — the
//!   Content-Store rules), so one Data answers all overlapping fetches. The
//!   forwarder sends it to the face once for all of them.
//! - **A Nack** answers every pending Interest with the name and selectors
//!   (`CanBePrefix`, `MustBeFresh`) of the Interest it carries. The nonce is
//!   not part of the match: the forwarder keeps one PIT entry per name for all
//!   of a face's Interests and, when it gives up upstream, Nacks the face once
//!   with the *upstream* Interest, whose nonce may be another fetch's.
//!
//! A reply to an Interest whose fetch already gave up is discarded rather than
//! queued: the abandoned Interest stays registered until its lifetime ends,
//! when no forwarder can answer it any more.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};

use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Interest, NackReason, Name};
use parking_lot::Mutex as SyncMutex;

use crate::connection::{Connection, LpInfo};
use crate::consumer::{DEFAULT_INTEREST_LIFETIME, data_matches};
use crate::error::AppError;
use crate::responder::Responder;
use crate::rt::Instant;

type Serves = Arc<SyncMutex<Vec<(Name, mpsc::UnboundedSender<Bytes>)>>>;
type Pending = Arc<SyncMutex<PendingTable>>;

/// The reply that answers an Interest registered on a [`Replies`] stream.
#[derive(Debug)]
// Nearly every reply is Data; boxing it would add an allocation per reply to
// shrink only the rare Nack.
#[allow(clippy::large_enum_variant)]
pub enum Reply {
    /// Data satisfying the Interest, with the NDNLPv2 local fields it arrived
    /// with (e.g. a CongestionMark).
    Data(Data, LpInfo),
    /// A Nack of the Interest, with the forwarder's reason if it gave one.
    Nack(Option<NackReason>),
}

/// One expressed Interest awaiting its reply: the identity a reply is matched
/// against, and the stream it is delivered to.
struct Waiter {
    stream: u64,
    name: Name,
    can_be_prefix: bool,
    must_be_fresh: bool,
    lifetime: Duration,
}

impl Waiter {
    fn answered_by(&self, reply: &Inbound) -> bool {
        match reply {
            Inbound::Data(data, _) => data_matches(&self.name, self.can_be_prefix, data),
            Inbound::Nack(interest, _) => {
                let sel = interest.selectors();
                *interest.name == self.name
                    && sel.can_be_prefix == self.can_be_prefix
                    && sel.must_be_fresh == self.must_be_fresh
            }
        }
    }
}

/// The Interests pending on one connection, by the stream awaiting each.
#[derive(Default)]
struct PendingTable {
    next_stream: u64,
    /// Live [`Replies`] streams.
    streams: HashMap<u64, mpsc::UnboundedSender<Reply>>,
    /// Interests of live streams.
    waiters: Vec<Waiter>,
    /// Interests whose stream was dropped before a reply came, kept until the
    /// instant their lifetime ends so a late reply is discarded, not queued.
    abandoned: Vec<(Instant, Waiter)>,
    /// The connection closed: no reply will arrive.
    closed: bool,
}

/// A Data or Nack off the wire, decoded once for matching.
enum Inbound {
    Data(Data, LpInfo),
    Nack(Interest, Option<NackReason>),
}

/// Decode `pkt` as a Data (bare or in an NDNLP frame) or an NDNLP Nack; `None`
/// for anything else (Interests, idle LP frames).
fn decode_inbound(pkt: &Bytes) -> Option<Inbound> {
    if !is_lp_packet(pkt) {
        let data = Data::decode(pkt.clone()).ok()?;
        return Some(Inbound::Data(data, LpInfo::default()));
    }
    let lp = LpPacket::decode(pkt.clone()).ok()?;
    let info = LpInfo::from_lp(&lp);
    let fragment = lp.fragment?;
    match lp.nack {
        Some(nack) => Some(Inbound::Nack(Interest::decode(fragment).ok()?, nack.reason)),
        None => Some(Inbound::Data(Data::decode(fragment).ok()?, info)),
    }
}

/// Deliver `pkt` to every live stream with a pending Interest it answers,
/// once per stream, and retire those Interests. Returns `pkt` back when it
/// answers no pending Interest, live or abandoned, so it falls back.
fn route_reply(pending: &Pending, pkt: Bytes) -> Option<Bytes> {
    let mut table = pending.lock();
    if table.waiters.is_empty() && table.abandoned.is_empty() {
        return Some(pkt);
    }
    let Some(reply) = decode_inbound(&pkt) else {
        return Some(pkt);
    };
    let table = &mut *table;
    if !table.abandoned.is_empty() {
        let now = Instant::now();
        table.abandoned.retain(|(expires, _)| now < *expires);
    }
    let before = table.abandoned.len();
    table.abandoned.retain(|(_, w)| !w.answered_by(&reply));
    let answered_abandoned = table.abandoned.len() != before;

    let mut targets: Vec<u64> = Vec::new();
    table.waiters.retain(|w| {
        if !w.answered_by(&reply) {
            return true;
        }
        if !targets.contains(&w.stream) {
            targets.push(w.stream);
        }
        false
    });
    if targets.is_empty() {
        return (!answered_abandoned).then_some(pkt);
    }
    match reply {
        Inbound::Data(data, lp) => {
            // `Data` is not `Clone`: each extra stream gets its own decode of
            // the same wire (rare — only overlapping fetches share a reply).
            let (last, rest) = targets.split_last().expect("targets is non-empty");
            for id in rest {
                if let (Some(tx), Ok(copy)) =
                    (table.streams.get(id), Data::decode(data.raw().clone()))
                {
                    let _ = tx.send(Reply::Data(copy, lp.clone()));
                }
            }
            if let Some(tx) = table.streams.get(last) {
                let _ = tx.send(Reply::Data(data, lp));
            }
        }
        Inbound::Nack(_, reason) => {
            for id in &targets {
                if let Some(tx) = table.streams.get(id) {
                    let _ = tx.send(Reply::Nack(reason));
                }
            }
        }
    }
    None
}

/// Receives the replies to the Interests registered on it, matched by NDN
/// rules (see the [module docs](self)), from a [`DemuxConnection`] shared with
/// any number of other fetches and serves. Obtained from
/// [`Connection::replies`]. Register each Interest with [`expect`](Self::expect)
/// **before** sending it. Dropping the stream abandons its unanswered
/// Interests: their late replies are discarded.
pub struct Replies {
    id: u64,
    rx: mpsc::UnboundedReceiver<Reply>,
    pending: Pending,
}

impl Replies {
    /// Await the reply to `interest` on this stream. Register before sending,
    /// so a fast reply cannot arrive first.
    pub fn expect(&self, interest: &Interest) {
        let sel = interest.selectors();
        self.expect_name(
            (*interest.name).clone(),
            sel.can_be_prefix,
            sel.must_be_fresh,
            interest.lifetime().unwrap_or(DEFAULT_INTEREST_LIFETIME),
        );
    }

    /// [`expect`](Self::expect) from the Interest's identity, for a caller
    /// that built the Interest itself and need not decode it again.
    pub(crate) fn expect_name(
        &self,
        name: Name,
        can_be_prefix: bool,
        must_be_fresh: bool,
        lifetime: Duration,
    ) {
        let mut table = self.pending.lock();
        if table.closed {
            return;
        }
        table.waiters.push(Waiter {
            stream: self.id,
            name,
            can_be_prefix,
            must_be_fresh,
            lifetime,
        });
    }

    /// The next reply; `None` once the connection has closed.
    pub async fn recv(&mut self) -> Option<Reply> {
        self.rx.recv().await
    }
}

impl Drop for Replies {
    fn drop(&mut self) {
        let mut table = self.pending.lock();
        let table = &mut *table;
        table.streams.remove(&self.id);
        // The stream's unanswered Interests may still be answered until their
        // lifetime ends (measured from now: an upper bound, since each was
        // sent earlier); keep them so those replies are discarded, not queued
        // on the fallback, which nothing may ever read.
        let mut now = None;
        let mut i = 0;
        while i < table.waiters.len() {
            if table.waiters[i].stream == self.id {
                let w = table.waiters.swap_remove(i);
                let expires = *now.get_or_insert_with(Instant::now) + w.lifetime;
                table.abandoned.push((expires, w));
            } else {
                i += 1;
            }
        }
    }
}

/// A [`Connection`] that demultiplexes its inbound stream so a node can serve
/// producers and run consumers over one underlying connection concurrently.
pub struct DemuxConnection {
    inner: Arc<dyn Connection>,
    serves: Serves,
    /// Interests awaiting replies, by [`Replies`] stream.
    pending: Pending,
    /// Packets matching no serve and no pending Interest, for [`Self::recv`].
    fallback: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

/// Pick the longest registered serve prefix that is a prefix of `name`, dropping
/// closed channels lazily. Returns a cloned sender to use outside the lock.
fn route(serves: &Serves, pkt: &Bytes) -> Option<mpsc::UnboundedSender<Bytes>> {
    if is_lp_packet(pkt) {
        return None;
    }
    let interest = Interest::decode(pkt.clone()).ok()?;
    let guard = serves.lock();
    guard
        .iter()
        .filter(|(p, tx)| !tx.is_closed() && interest.name.has_prefix(p))
        .max_by_key(|(p, _)| p.len())
        .map(|(_, tx)| tx.clone())
}

impl DemuxConnection {
    /// Wrap `inner` and start the demux loop. The loop runs until `inner`'s
    /// `recv` returns `None` (the connection closed).
    pub fn new(inner: Arc<dyn Connection>) -> Arc<Self> {
        let (fb_tx, fb_rx) = mpsc::unbounded_channel();
        let serves: Serves = Arc::new(SyncMutex::new(Vec::new()));
        let pending: Pending = Arc::new(SyncMutex::new(PendingTable::default()));
        {
            let inner = Arc::clone(&inner);
            let serves = Arc::clone(&serves);
            let pending = Arc::clone(&pending);
            crate::rt::spawn(async move {
                while let Some(pkt) = inner.recv().await {
                    // Serve Interest → its handler; else the streams awaiting
                    // the Interest it answers; else the fallback recv queue.
                    if let Some(tx) = route(&serves, &pkt) {
                        let _ = tx.send(pkt);
                    } else if let Some(pkt) = route_reply(&pending, pkt)
                        && fb_tx.send(pkt).is_err()
                    {
                        break; // no DemuxConnection left to drain
                    }
                }
                // Ends every stream's `recv` with `None`.
                let mut table = pending.lock();
                table.closed = true;
                table.streams.clear();
                table.waiters.clear();
                table.abandoned.clear();
            });
        }
        Arc::new(Self {
            inner,
            serves,
            pending,
            fallback: Mutex::new(fb_rx),
        })
    }

    fn register(&self, prefix: Name) -> mpsc::UnboundedReceiver<Bytes> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.serves.lock().push((prefix, tx));
        rx
    }

    fn unregister(serves: &Serves, prefix: &Name) {
        serves.lock().retain(|(p, _)| p != prefix);
    }

    /// Serve `prefix` until the connection closes (the long-lived producer
    /// pattern, e.g. a RemoteSigner responder). Registers the prefix with the
    /// forwarder so matching Interests route here, then dispatches each to
    /// `handler`. Mirrors [`Producer::serve`](crate::Producer::serve) but reads
    /// from this prefix's demux channel instead of the shared `recv`.
    pub async fn serve<F, Fut>(self: &Arc<Self>, prefix: Name, handler: F) -> Result<(), AppError>
    where
        F: Fn(Interest, Responder) -> Fut + Send + Sync,
        Fut: Future<Output = ()> + Send,
    {
        let mut rx = self.register(prefix.clone());
        self.inner.register_prefix(&prefix).await?;
        while let Some(raw) = rx.recv().await {
            let Ok(interest) = Interest::decode(raw.clone()) else {
                continue;
            };
            let responder = Responder::new(self.clone() as Arc<dyn Connection>, raw, None);
            handler(interest, responder).await;
        }
        Ok(())
    }

    /// Serve `prefix` for the lifetime of the returned [`ServeGuard`], then stop.
    /// Does NOT register the prefix with the forwarder — for a reflexive name,
    /// whose reverse pulls arrive via the reflexive reverse route, not the FIB.
    /// Spawns the serve loop so the caller can concurrently fetch on the same
    /// connection (the reflexive advertiser pattern).
    pub fn serve_scoped<F, Fut>(self: &Arc<Self>, prefix: Name, handler: F) -> ServeGuard
    where
        F: Fn(Interest, Responder) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut rx = self.register(prefix.clone());
        let me = Arc::clone(self);
        crate::rt::spawn(async move {
            while let Some(raw) = rx.recv().await {
                let Ok(interest) = Interest::decode(raw.clone()) else {
                    continue;
                };
                let responder = Responder::new(me.clone() as Arc<dyn Connection>, raw, None);
                // Spawn each handler instead of awaiting it: serving a segmented
                // object signs + responds to one Interest per call, and a serial
                // loop caps producer throughput at one (sign + send) at a time —
                // the bottleneck that starved the tail of a big file under the
                // consumer's in-flight burst. Concurrent handlers parallelize the
                // per-segment signing across cores and keep retransmits prompt.
                // The consumer's window bounds how many run at once.
                crate::rt::spawn(handler(interest, responder));
            }
        });
        ServeGuard {
            prefix,
            serves: Arc::clone(&self.serves),
        }
    }
}

#[async_trait]
impl Connection for DemuxConnection {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.inner.send(wire).await
    }

    async fn recv(&self) -> Option<Bytes> {
        self.fallback.lock().await.recv().await
    }

    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.inner.register_prefix(prefix).await
    }

    fn replies(&self) -> Option<Replies> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut table = self.pending.lock();
        let id = table.next_stream;
        table.next_stream += 1;
        // After close the sender is dropped here, so `recv` yields `None`.
        if !table.closed {
            table.streams.insert(id, tx);
        }
        Some(Replies {
            id,
            rx,
            pending: Arc::clone(&self.pending),
        })
    }
}

/// Unregisters a [`DemuxConnection::serve_scoped`] prefix on drop, which closes
/// the serve channel and ends its loop.
#[must_use = "the scoped serve stops when the guard is dropped"]
pub struct ServeGuard {
    prefix: Name,
    serves: Serves,
}

impl Drop for ServeGuard {
    fn drop(&mut self) {
        DemuxConnection::unregister(&self.serves, &self.prefix);
    }
}
