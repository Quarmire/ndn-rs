//! Single-reader demultiplexer for an [`IpcFace`] shared by management and data.
//!
//! The cross-process seam (`socketpair` adopted via
//! [`ForwarderClient::from_raw_fd`](crate::ForwarderClient::from_raw_fd))
//! multiplexes NFD management commands AND the data plane over ONE fd: the
//! [`MgmtClient`](crate::MgmtClient) and the data `recv` both read the same
//! `IpcFace`. Two independent readers race — whoever calls `recv_bytes` first
//! gets the next packet — so a management `ControlResponse` can be swallowed by
//! the data path (and vice-versa).
//!
//! [`FaceMux`] owns the *single* reader and routes each inbound packet:
//!
//! - a **Data** that satisfies a registered management exchange (longest
//!   registered command name that is a prefix of the Data name — handles both
//!   the exact `ControlResponse` name and `…/v=N/seg=0` dataset segments) →
//!   that exchange's waiter;
//! - **everything else** (app Data, all Interests, Nacks) → a fallback queue
//!   that [`FaceMux::recv`] drains (the data plane).
//!
//! Management exchanges therefore never compete with the data `recv`. The data
//! plane can be further demultiplexed (serve vs. fetch) one layer up by
//! `ndn-app`'s `DemuxConnection`.

use std::sync::{Arc, Mutex as StdMutex};

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use ndn_face::local::IpcFace;
use ndn_packet::{Data, Name};
use ndn_transport::Transport;

use crate::forwarder_client::strip_lp;

type Pending = Arc<StdMutex<Vec<(Name, oneshot::Sender<Bytes>)>>>;

/// One reader of an [`IpcFace`], demultiplexing management responses from the
/// data stream. See the module docs.
pub(crate) struct FaceMux {
    pending: Pending,
    fallback: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

impl FaceMux {
    /// Start the demux loop over `face`. It runs until `cancel` fires or the
    /// face closes. Must be called from within a Tokio runtime.
    pub(crate) fn new(face: Arc<IpcFace>, cancel: CancellationToken) -> Arc<Self> {
        let (fb_tx, fb_rx) = mpsc::unbounded_channel();
        let pending: Pending = Arc::new(StdMutex::new(Vec::new()));
        {
            let face = Arc::clone(&face);
            let pending = Arc::clone(&pending);
            tokio::spawn(async move {
                loop {
                    let raw = tokio::select! {
                        _ = cancel.cancelled() => break,
                        r = face.recv_bytes() => match r {
                            Ok(b) => b,
                            Err(_) => break,
                        },
                    };
                    let pkt = strip_lp(raw);
                    // Route a Data that satisfies a pending management exchange.
                    if let Ok(data) = Data::decode(pkt.clone()) {
                        let taken = {
                            let mut pend = pending.lock().unwrap();
                            pend.retain(|(_, tx)| !tx.is_closed());
                            pend.iter()
                                .enumerate()
                                .filter(|(_, (n, _))| data.name.has_prefix(n))
                                .max_by_key(|(_, (n, _))| n.len())
                                .map(|(i, _)| i)
                                .map(|i| pend.remove(i))
                        };
                        if let Some((_, tx)) = taken {
                            let _ = tx.send(pkt);
                            continue;
                        }
                    }
                    if fb_tx.send(pkt).is_err() {
                        break; // no FaceMux left to drain the data plane
                    }
                }
            });
        }
        Arc::new(Self {
            pending,
            fallback: Mutex::new(fb_rx),
        })
    }

    /// Register an expected management response named under `name`, returning the
    /// receiver to await after [`send`](Self::send)ing the command. The demux
    /// loop delivers the matching (LP-stripped) Data wire.
    pub(crate) fn expect(&self, name: Name) -> oneshot::Receiver<Bytes> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().push((name, tx));
        rx
    }

    /// Drain the next data-plane packet (everything not routed to a management
    /// exchange). `None` when the face has closed.
    pub(crate) async fn recv(&self) -> Option<Bytes> {
        self.fallback.lock().await.recv().await
    }
}
