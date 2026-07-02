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
//! - **everything else** (Data, Nacks, unmatched Interests) → a fallback queue
//!   that [`DemuxConnection`]'s own [`Connection::recv`] drains.
//!
//! So `DemuxConnection` *is* a [`Connection`]: existing `Consumer`(crate::Consumer)
//! code fetches over it unchanged (it only ever sees the fallback — the Data it
//! awaited), while serves are peeled off to their handlers. Only the serve side
//! uses the new [`DemuxConnection::serve`] / [`DemuxConnection::serve_scoped`].

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{Mutex, mpsc, oneshot};

use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Interest, Name};

use crate::connection::Connection;
use crate::error::AppError;
use crate::responder::Responder;

type Serves = Arc<StdMutex<Vec<(Name, mpsc::UnboundedSender<Bytes>)>>>;
/// Data waiters keyed by the exact Data name they await, so concurrent
/// name-correlated fetches over one connection don't steal each other's replies.
type Pending = Arc<StdMutex<HashMap<Name, oneshot::Sender<Bytes>>>>;

/// A [`Connection`] that demultiplexes its inbound stream so a node can serve
/// producers and run consumers over one underlying connection concurrently.
pub struct DemuxConnection {
    inner: Arc<dyn Connection>,
    serves: Serves,
    /// Outstanding name-correlated Data waiters (see [`Self::fetch_correlated`]).
    pending: Pending,
    /// Non-serve packets (Data / Nacks / unmatched Interests) for [`Self::recv`].
    fallback: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

/// Pick the longest registered serve prefix that is a prefix of `name`, dropping
/// closed channels lazily. Returns a cloned sender to use outside the lock.
fn route(serves: &Serves, pkt: &Bytes) -> Option<mpsc::UnboundedSender<Bytes>> {
    if is_lp_packet(pkt) {
        return None;
    }
    let interest = Interest::decode(pkt.clone()).ok()?;
    let guard = serves.lock().unwrap();
    guard
        .iter()
        .filter(|(p, tx)| !tx.is_closed() && interest.name.has_prefix(p))
        .max_by_key(|(p, _)| p.len())
        .map(|(_, tx)| tx.clone())
}

/// Decode the name of an inbound Data packet (unwrapping an NDNLP fragment if
/// present). Returns `None` for non-Data (Nacks, Interests) — those fall back.
fn data_name(pkt: &Bytes) -> Option<Name> {
    let raw = if is_lp_packet(pkt) {
        LpPacket::decode(pkt.clone()).ok()?.fragment?
    } else {
        pkt.clone()
    };
    Data::decode(raw).ok().map(|d| (*d.name).clone())
}

/// If `pkt` is a Data whose name matches a registered waiter, take that waiter's
/// sender (removing it). Otherwise `None` so the packet falls back.
fn route_data(pending: &Pending, pkt: &Bytes) -> Option<oneshot::Sender<Bytes>> {
    let name = data_name(pkt)?;
    pending.lock().unwrap().remove(&name)
}

impl DemuxConnection {
    /// Wrap `inner` and start the demux loop. The loop runs until `inner`'s
    /// `recv` returns `None` (the connection closed).
    pub fn new(inner: Arc<dyn Connection>) -> Arc<Self> {
        let (fb_tx, fb_rx) = mpsc::unbounded_channel();
        let serves: Serves = Arc::new(StdMutex::new(Vec::new()));
        let pending: Pending = Arc::new(StdMutex::new(HashMap::new()));
        {
            let inner = Arc::clone(&inner);
            let serves = Arc::clone(&serves);
            let pending = Arc::clone(&pending);
            crate::rt::spawn(async move {
                while let Some(pkt) = inner.recv().await {
                    // Serve Interest → its handler; else a name-correlated Data
                    // waiter if one is registered; else the fallback recv queue.
                    if let Some(tx) = route(&serves, &pkt) {
                        let _ = tx.send(pkt);
                    } else if let Some(tx) = route_data(&pending, &pkt) {
                        let _ = tx.send(pkt);
                    } else if fb_tx.send(pkt).is_err() {
                        break; // no DemuxConnection left to drain
                    }
                }
            });
        }
        Arc::new(Self {
            inner,
            serves,
            pending,
            fallback: Mutex::new(fb_rx),
        })
    }

    /// Send `wire` and await exactly the Data named `expected`, routed to this
    /// caller by name so concurrent fetches over the one connection never steal
    /// each other's replies (the bare `recv` FIFO does). `expected` is the full
    /// Interest name including any `ParametersSha256Digest`, which the responder
    /// echoes as the Data name. Returns the raw reply wire (Data, possibly NDNLP).
    pub async fn fetch_correlated(
        &self,
        expected: Name,
        wire: Bytes,
        timeout: Duration,
    ) -> Result<Bytes, AppError> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(expected.clone(), tx);
        if let Err(e) = self.inner.send(wire).await {
            self.pending.lock().unwrap().remove(&expected);
            return Err(e);
        }
        match crate::rt::timeout(timeout, rx).await {
            Ok(Ok(pkt)) => Ok(pkt),
            _ => {
                self.pending.lock().unwrap().remove(&expected);
                Err(AppError::Timeout)
            }
        }
    }

    fn register(&self, prefix: Name) -> mpsc::UnboundedReceiver<Bytes> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.serves.lock().unwrap().push((prefix, tx));
        rx
    }

    fn unregister(serves: &Serves, prefix: &Name) {
        serves.lock().unwrap().retain(|(p, _)| p != prefix);
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
