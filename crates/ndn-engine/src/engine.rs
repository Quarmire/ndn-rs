use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use ndn_packet::Interest;
use ndn_security::SecurityManager;
use ndn_store::{LruCs, Pit, PitToken, StrategyTable};
use ndn_strategy::MeasurementsTable;
use ndn_transport::{Face, FaceId, FacePersistency, FaceTable};

use crate::stages::ErasedStrategy;

use crate::dispatcher::InboundPacket;
use crate::Fib;

/// Per-face lifecycle state stored alongside the cancellation token.
pub struct FaceState {
    pub cancel: CancellationToken,
    pub persistency: FacePersistency,
    /// Last packet activity (nanoseconds since Unix epoch).
    /// Updated on recv and send; used for idle-timeout of on-demand faces.
    pub last_activity: AtomicU64,
}

impl FaceState {
    pub fn new(cancel: CancellationToken, persistency: FacePersistency) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self {
            cancel,
            persistency,
            last_activity: AtomicU64::new(now),
        }
    }

    pub fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        self.last_activity.store(now, Ordering::Relaxed);
    }
}

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
    /// Per-face state: cancellation token, persistency level, and last activity.
    ///
    /// When a control face (e.g. UnixFace) creates child faces (e.g. SHM via
    /// `faces/create`), the child uses a child token of the control face's
    /// token.  When the control face disconnects, its token is cancelled,
    /// which propagates to all child faces.
    pub(crate) face_states: Arc<DashMap<FaceId, FaceState>>,
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
    /// Persistence defaults to `OnDemand`. Use `add_face_with_persistency` for
    /// management-created or permanent faces.
    pub fn add_face<F: Face + 'static>(&self, face: F, cancel: CancellationToken) {
        self.add_face_with_persistency(face, cancel, FacePersistency::OnDemand);
    }

    /// Register a face with an explicit persistence level.
    pub fn add_face_with_persistency<F: Face + 'static>(
        &self,
        face: F,
        cancel: CancellationToken,
        persistency: FacePersistency,
    ) {
        let face_id = face.id();
        self.inner.face_states.insert(face_id, FaceState::new(cancel.clone(), persistency));
        self.inner.face_table.insert(face);
        let erased     = self.inner.face_table.get(face_id)
            .expect("face was just inserted");
        let tx         = self.inner.pipeline_tx.clone();
        let face_table = Arc::clone(&self.inner.face_table);
        let fib        = Arc::clone(&self.inner.fib);
        let face_states = Arc::clone(&self.inner.face_states);
        tokio::spawn(crate::dispatcher::run_face_reader(
            face_id, erased, tx, cancel, face_table, fib, face_states,
        ));
    }

    /// Inject a raw packet into the pipeline as if it arrived from `face_id`.
    ///
    /// Returns `Err(())` if the pipeline channel is closed.
    pub async fn inject_packet(
        &self,
        raw: bytes::Bytes,
        face_id: FaceId,
        arrival: u64,
    ) -> Result<(), ()> {
        self.inner.pipeline_tx
            .send(InboundPacket { raw, face_id, arrival })
            .await
            .map_err(|_| ())
    }

    /// Get the cancellation token for a face, if one exists.
    pub fn face_token(&self, face_id: FaceId) -> Option<CancellationToken> {
        self.inner.face_states.get(&face_id).map(|r| r.cancel.clone())
    }

    /// Access the face states map (for idle timeout sweeps).
    pub fn face_states(&self) -> Arc<DashMap<FaceId, FaceState>> {
        Arc::clone(&self.inner.face_states)
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
