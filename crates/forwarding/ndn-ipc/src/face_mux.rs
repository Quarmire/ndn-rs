//! Single-reader demultiplexer for an [`IpcFace`] shared by management and data.
//!
//! A [`ForwarderClient`](crate::ForwarderClient) sends NFD management commands
//! over its control face, and on the Unix data plane that same face carries its
//! data too. Two independent readers of one face race — whoever calls
//! `recv_bytes` first gets the next packet — so a receive loop already waiting
//! on the data path would swallow a `rib/register` reply and the registration
//! would never complete (and vice-versa).
//!
//! [`FaceMux`] owns the *single* reader and routes each inbound packet:
//!
//! - a **Data** that satisfies a registered management exchange (longest
//!   registered command name that is a prefix of the Data name — handles both
//!   the exact `ControlResponse` name and `…/v=N/seg=0` dataset segments) →
//!   that exchange's waiter;
//! - **everything else** (app Data, all Interests, Nacks) → a fallback queue
//!   that [`FaceMux::recv`] drains (the data plane), unless the data plane is
//!   elsewhere ([`FaceMux::discard_data`]), in which case it is dropped.
//!
//! Management exchanges therefore never compete with the data `recv`, whatever
//! the timing. The data plane can be further demultiplexed (serve vs. fetch)
//! one layer up by `ndn-app`'s `DemuxConnection`.
//!
//! When the face closes the reader marks the client dead, cancels its token
//! (so an external data plane tied to it aborts too), and fails every waiting
//! and later exchange with [`ForwarderError::Closed`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use ndn_face::local::IpcFace;
use ndn_packet::{Data, Name};
use ndn_transport::Transport;

use crate::forwarder_client::{ForwarderError, strip_lp};

/// Waiting management exchanges; `None` once the reader has stopped, so no
/// later exchange waits for a reply that can no longer arrive.
type Pending = Arc<SyncMutex<Option<Vec<(Name, oneshot::Sender<Bytes>)>>>>;

/// One reader of an [`IpcFace`], demultiplexing management responses from the
/// data stream. See the module docs.
pub(crate) struct FaceMux {
    pending: Pending,
    deliver_data: Arc<AtomicBool>,
    fallback: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

/// A management exchange's reply, routed by the reader.
pub(crate) struct Reply(oneshot::Receiver<Bytes>);

impl Reply {
    /// The reply Data wire (LP stripped), or [`ForwarderError::Closed`] when
    /// the face closed before it came.
    pub(crate) async fn get(self) -> Result<Bytes, ForwarderError> {
        self.0.await.map_err(|_| ForwarderError::Closed)
    }
}

impl FaceMux {
    /// Start the reader over `face`. It runs until `cancel` fires or the face
    /// closes; on a close it sets `dead` and cancels `cancel`. Must be called
    /// from within a Tokio runtime.
    pub(crate) fn new(
        face: Arc<IpcFace>,
        cancel: CancellationToken,
        dead: Arc<AtomicBool>,
    ) -> Arc<Self> {
        let (fb_tx, fb_rx) = mpsc::unbounded_channel();
        let pending: Pending = Arc::new(SyncMutex::new(Some(Vec::new())));
        let deliver_data = Arc::new(AtomicBool::new(true));
        {
            let pending = Arc::clone(&pending);
            let deliver_data = Arc::clone(&deliver_data);
            tokio::spawn(async move {
                loop {
                    let raw = tokio::select! {
                        _ = cancel.cancelled() => break,
                        r = face.recv_bytes() => match r {
                            Ok(b) => b,
                            Err(_) => {
                                dead.store(true, Ordering::Relaxed);
                                cancel.cancel();
                                break;
                            }
                        },
                    };
                    let pkt = strip_lp(raw);
                    // Route a Data that satisfies a pending management exchange.
                    if let Ok(data) = Data::decode(pkt.clone()) {
                        let taken = pending.lock().as_mut().and_then(|pend| {
                            pend.retain(|(_, tx)| !tx.is_closed());
                            pend.iter()
                                .enumerate()
                                .filter(|(_, (n, _))| data.name.has_prefix(n))
                                .max_by_key(|(_, (n, _))| n.len())
                                .map(|(i, _)| i)
                                .map(|i| pend.remove(i))
                        });
                        if let Some((_, tx)) = taken {
                            let _ = tx.send(pkt);
                            continue;
                        }
                    }
                    if deliver_data.load(Ordering::Relaxed) && fb_tx.send(pkt).is_err() {
                        break; // no FaceMux left to drain the data plane
                    }
                }
                // Dropping the waiters' senders answers them with `Closed`.
                pending.lock().take();
            });
        }
        Arc::new(Self {
            pending,
            deliver_data,
            fallback: Mutex::new(fb_rx),
        })
    }

    /// Register an expected management response named under `name`. Call it
    /// *before* sending the command, so the reply cannot arrive unregistered;
    /// the reader delivers the matching (LP-stripped) Data wire.
    pub(crate) fn expect(&self, name: Name) -> Reply {
        let (tx, rx) = oneshot::channel();
        // Once the reader has stopped, `tx` drops here and the reply is `Closed`.
        if let Some(pend) = self.pending.lock().as_mut() {
            pend.push((name, tx));
        }
        Reply(rx)
    }

    /// The data plane is not this face (an external one carries it): drop
    /// what is not a management reply instead of queueing it for a
    /// [`recv`](Self::recv) nobody calls.
    pub(crate) fn discard_data(&self) {
        self.deliver_data.store(false, Ordering::Relaxed);
    }

    /// Drain the next data-plane packet (everything not routed to a management
    /// exchange). `None` when the face has closed.
    pub(crate) async fn recv(&self) -> Option<Bytes> {
        self.fallback.lock().await.recv().await
    }
}
