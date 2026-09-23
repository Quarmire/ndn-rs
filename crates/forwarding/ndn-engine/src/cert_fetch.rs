//! Certificate fetching through the forwarder itself.
//!
//! Validating a Data packet needs its signer's certificate. When the cert is
//! not cached, [`ValidationStage`](crate::stages::ValidationStage) parks the
//! Data and asks a [`CertFetcher`] for the KeyLocator name; this module is that
//! fetcher's transport. The fetch is an ordinary Interest expressed from an
//! internal face of THIS engine, so it takes the FIB routes, strategy and faces
//! any consumer's Interest would, and the certificate Data answering it is
//! validated on arrival like any other Data (its own issuer resolved the same
//! way) before it reaches the fetcher.
//!
//! The Data-path `Validator` itself holds no fetcher, and the fetch is never
//! awaited inside the pipeline: with one pipeline task the pipeline would sit
//! blocked on the very certificate Data it must process to finish the fetch.
//! The validation stage spawns the fetch and re-validates the parked Data once
//! the certificate is cached.
//!
//! One implementation for every engine-backed validator: the Data path gets it
//! from [`EngineBuilder`](crate::EngineBuilder); a forwarder's command
//! validators (e.g. ndn-fwd's localhop validator) take one from
//! [`ForwarderEngine::cert_fetcher`].

use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Interest, Name};
use ndn_security::{CertCache, CertFetcher, FetchFn};
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::engine::{EngineInner, ForwarderEngine};

/// Deadline of one certificate fetch (the Interest lifetime too). Equal to the
/// validation stage's pending timeout, after which the Data waiting on the
/// certificate is dropped regardless.
pub(crate) const CERT_FETCH_TIMEOUT: Duration = Duration::from_secs(4);

impl ForwarderEngine {
    /// A [`CertFetcher`] that fills `cert_cache` with certificates fetched over
    /// NDN through this engine. Attach it to a validator that runs *outside* the
    /// forwarding pipeline (a management command validator); the Data path
    /// already has one. `cancel` ends the fetcher's internal face.
    pub fn cert_fetcher(
        &self,
        cert_cache: Arc<CertCache>,
        cancel: CancellationToken,
    ) -> Arc<CertFetcher> {
        engine_cert_fetcher(Arc::downgrade(&self.inner), cert_cache, cancel)
    }
}

/// [`ForwarderEngine::cert_fetcher`] over a not-yet-wrapped engine (the builder
/// wires the Data path's fetcher before the pipeline runs). Holds the engine
/// weakly: the fetcher lives in the pipeline the engine owns.
pub(crate) fn engine_cert_fetcher(
    engine: Weak<EngineInner>,
    cert_cache: Arc<CertCache>,
    cancel: CancellationToken,
) -> Arc<CertFetcher> {
    let fetch = Arc::new(EngineFetch {
        engine,
        cancel,
        face: OnceLock::new(),
        waiters: Arc::new(Mutex::new(Vec::new())),
    });
    let fetch_fn: FetchFn = Arc::new(move |name: Name| {
        let fetch = Arc::clone(&fetch);
        Box::pin(async move { fetch.fetch(name).await })
    });
    Arc::new(CertFetcher::new(cert_cache, fetch_fn, CERT_FETCH_TIMEOUT))
}

/// A fetch waiting for its reply.
struct Waiter {
    /// The Interest name, i.e. the KeyLocator name.
    name: Name,
    /// The Interest was CanBePrefix: any Data under `name` answers it.
    can_be_prefix: bool,
    reply: oneshot::Sender<Option<Bytes>>,
}

type Waiters = Mutex<Vec<Waiter>>;

struct EngineFetch {
    engine: Weak<EngineInner>,
    cancel: CancellationToken,
    /// The internal face the Interests are expressed from, created on the
    /// first fetch so an engine that never fetches has no extra face.
    face: OnceLock<FaceId>,
    waiters: Arc<Waiters>,
}

impl EngineFetch {
    async fn fetch(&self, name: Name) -> Option<Data> {
        // A KeyLocator naming a KEY (`/<id>/KEY/<key-id>`, as ndn-cxx producers
        // emit) is answered by a certificate two components longer, so ask the
        // way ndn-cxx's CertificateFetcherFromNetwork does: CanBePrefix +
        // MustBeFresh. The cert cache indexes the answer under its KEY name too,
        // which is what the parked Data is re-checked against. A full
        // certificate name is fetched exactly.
        let can_be_prefix = ndn_security::cert_cache::is_key_name(&name);
        let (tx, rx) = oneshot::channel();
        {
            let mut waiters = self.waiters.lock().unwrap();
            // A fetch past its deadline dropped its receiver; forget it.
            waiters.retain(|w| !w.reply.is_closed());
            waiters.push(Waiter {
                name: name.clone(),
                can_be_prefix,
                reply: tx,
            });
        }
        let mut interest = InterestBuilder::new(name).lifetime(CERT_FETCH_TIMEOUT);
        if can_be_prefix {
            interest = interest.can_be_prefix().must_be_fresh();
        }
        let wire = interest.build();
        {
            // No strong engine handle across the wait: an engine shut down
            // mid-fetch is released, and the fetch ends at its deadline.
            let engine = ForwarderEngine {
                inner: self.engine.upgrade()?,
            };
            let face = self.face(&engine);
            let arrival = engine.inner.runtime.unix_nanos();
            engine
                .inject_packet(wire, face, arrival, ndn_discovery_core::InboundMeta::none())
                .await
                .ok()?;
        }
        Data::decode(rx.await.ok()??).ok()
    }

    fn face(&self, engine: &ForwarderEngine) -> FaceId {
        *self.face.get_or_init(|| {
            let id = engine.inner.face_table.alloc_id();
            engine.add_face_send_only(
                FetchFace {
                    id,
                    waiters: Arc::clone(&self.waiters),
                },
                self.cancel.clone(),
            );
            id
        })
    }
}

/// The internal face certificate Interests leave from. Inbound packets are
/// injected straight into the pipeline, so only its send side (the engine
/// returning Data or a Nack) is used.
struct FetchFace {
    id: FaceId,
    waiters: Arc<Waiters>,
}

impl FetchFace {
    /// Hand a reply to the fetches it answers: the Data wire, or `None` for a
    /// Nack so the fetch fails now rather than at its deadline.
    fn deliver(&self, wire: Bytes) {
        let decoded = if is_lp_packet(&wire) {
            let Ok(lp) = LpPacket::decode(wire) else {
                return;
            };
            let Some(fragment) = lp.fragment else {
                return;
            };
            if lp.nack.is_some() {
                Interest::decode(fragment).map(|i| ((*i.name).clone(), None))
            } else {
                Data::decode(fragment.clone()).map(|d| ((*d.name).clone(), Some(fragment)))
            }
        } else {
            Data::decode(wire.clone()).map(|d| ((*d.name).clone(), Some(wire)))
        };
        let Ok((name, reply)) = decoded else {
            return;
        };
        // A Nack carries the Interest itself: match its name exactly.
        let answers = |w: &Waiter| {
            w.name == name || (reply.is_some() && w.can_be_prefix && name.has_prefix(&w.name))
        };
        let mut waiters = self.waiters.lock().unwrap();
        let mut i = 0;
        while i < waiters.len() {
            if answers(&waiters[i]) {
                let _ = waiters.swap_remove(i).reply.send(reply.clone());
            } else {
                i += 1;
            }
        }
    }
}

impl Transport for FetchFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Internal
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        self.deliver(wire);
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        std::future::pending().await
    }
}
