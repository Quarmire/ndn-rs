use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use ndn_packet::Interest;
use ndn_security::SecurityManager;
use ndn_store::{LruCs, Pit, PitToken, StrategyTable};
use ndn_strategy::MeasurementsTable;
use ndn_transport::{Face, FaceId, FaceTable};

use crate::stages::ErasedStrategy;

use crate::dispatcher::InboundPacket;
use crate::Fib;

/// Shared tables owned by the engine, accessible to all tasks via `Arc`.
pub struct EngineInner {
    pub fib:            Arc<Fib>,
    pub pit:            Arc<Pit>,
    pub cs:             Arc<LruCs>,
    pub face_table:     Arc<FaceTable>,
    pub measurements:   Arc<MeasurementsTable>,
    pub strategy_table: Arc<StrategyTable<dyn ErasedStrategy>>,
    /// Security manager for signing/verification (optional — `None` disables
    /// security policy enforcement).
    pub security:       Option<Arc<SecurityManager>>,
    /// Pipeline inbound channel — used to spawn readers for dynamically-added
    /// faces (those registered after `build()` completes).
    pub(crate) pipeline_tx: mpsc::Sender<InboundPacket>,
}

/// Handle to a running forwarding engine.
///
/// Cloning the handle gives another reference to the same running engine.
#[derive(Clone)]
pub struct ForwarderEngine {
    pub(crate) inner: Arc<EngineInner>,
}

impl ForwarderEngine {
    pub fn fib(&self) -> Arc<Fib> {
        Arc::clone(&self.inner.fib)
    }

    pub fn faces(&self) -> Arc<FaceTable> {
        Arc::clone(&self.inner.face_table)
    }

    pub fn pit(&self) -> Arc<Pit> {
        Arc::clone(&self.inner.pit)
    }

    pub fn cs(&self) -> Arc<LruCs> {
        Arc::clone(&self.inner.cs)
    }

    pub fn security(&self) -> Option<Arc<SecurityManager>> {
        self.inner.security.as_ref().map(Arc::clone)
    }

    pub fn strategy_table(&self) -> Arc<StrategyTable<dyn ErasedStrategy>> {
        Arc::clone(&self.inner.strategy_table)
    }

    /// Look up the source face that originally sent an Interest.
    ///
    /// Computes the PIT token from the Interest's name, selectors, and
    /// forwarding hint, then reads the first in-record to find the source
    /// face ID.  Returns `None` if no PIT entry exists (e.g. the Interest
    /// was already satisfied or expired).
    ///
    /// This is used by the management handler to implement NFD's "FaceId
    /// defaults to the requesting face" behavior.
    pub fn source_face_id(&self, interest: &Interest) -> Option<FaceId> {
        let token = PitToken::from_interest_full(
            &interest.name,
            Some(interest.selectors()),
            interest.forwarding_hint(),
        );
        self.inner.pit.get(&token)
            .and_then(|entry| entry.in_records.first().map(|r| FaceId(r.face_id)))
    }

    /// Register a face and immediately start its packet-reader task.
    ///
    /// Use this for faces accepted from a listener after `build()` returns —
    /// for example, a `UnixFace` connection accepted by the NDN face listener.
    /// The face participates in forwarding exactly like faces registered at
    /// build time.
    pub fn add_face<F: Face + 'static>(&self, face: F, cancel: CancellationToken) {
        let face_id    = face.id();
        self.inner.face_table.insert(face);
        let erased     = self.inner.face_table.get(face_id)
            .expect("face was just inserted");
        let tx         = self.inner.pipeline_tx.clone();
        let face_table = Arc::clone(&self.inner.face_table);
        tokio::spawn(crate::dispatcher::run_face_reader(face_id, erased, tx, cancel, face_table));
    }
}

/// Handle to gracefully shut down the engine.
pub struct ShutdownHandle {
    pub(crate) cancel: CancellationToken,
    pub(crate) tasks:  JoinSet<()>,
}

impl ShutdownHandle {
    /// Cancel all engine tasks and wait for them to finish.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        while let Some(result) = self.tasks.join_next().await {
            if let Err(e) = result {
                tracing::warn!("engine task panicked during shutdown: {e}");
            }
        }
    }
}
