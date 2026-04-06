//! Engine-side implementation of `DiscoveryContext`.
//!
//! `EngineDiscoveryContext` is the bridge between discovery protocols and the
//! engine's internal tables.  It holds a `Weak<EngineInner>` to break the
//! reference cycle (EngineInner → Arc<EngineDiscoveryContext> → Weak<EngineInner>).

use std::sync::{Arc, Weak};
use std::time::Instant;

use bytes::Bytes;
use dashmap::DashMap;
use ndn_discovery::{
    DiscoveryContext, NeighborTable, NeighborTableView, NeighborUpdate, ProtocolId,
};
use ndn_packet::Name;
use ndn_transport::{ErasedFace, FaceId, FacePersistency};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::engine::{DEFAULT_SEND_QUEUE_CAP, EngineInner, FaceState};

/// Side-table tracking which FIB entries were installed by each discovery
/// protocol, so they can be bulk-removed via `remove_fib_entries_by_owner`.
type OwnedRoutes = DashMap<ProtocolId, Vec<(Name, FaceId)>>;

/// Engine implementation of `DiscoveryContext`.
///
/// Constructed once at engine build time and stored in `EngineInner`.  Every
/// task that may call `on_face_up` / `on_face_down` / `on_inbound` receives an
/// `Arc<EngineDiscoveryContext>`.
pub struct EngineDiscoveryContext {
    /// Weak reference to the engine's shared inner state.  We use `Weak` here
    /// so that `EngineInner → Arc<EngineDiscoveryContext> → Weak<EngineInner>`
    /// doesn't form a strong reference cycle.
    pub(crate) inner: Weak<EngineInner>,
    /// Direct strong reference to the neighbor table.  This is the same
    /// `Arc<NeighborTable>` stored in `EngineInner::neighbors`, duplicated here
    /// so `neighbors() -> &dyn NeighborTableView` can return a reference valid
    /// for the lifetime of `&self` without needing to upgrade the `Weak`.
    neighbors: Arc<NeighborTable>,
    /// Cancellation token for faces dynamically added by discovery protocols.
    pub(crate) cancel: CancellationToken,
    /// Tracks `(prefix, nexthop_face_id)` pairs for each owning protocol.
    owned_routes: Arc<OwnedRoutes>,
}

impl EngineDiscoveryContext {
    pub(crate) fn new(
        inner: Weak<EngineInner>,
        neighbors: Arc<NeighborTable>,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            neighbors,
            cancel,
            owned_routes: Arc::new(DashMap::new()),
        })
    }
}

impl DiscoveryContext for EngineDiscoveryContext {
    // ── Face management ──────────────────────────────────────────────────────

    fn alloc_face_id(&self) -> FaceId {
        let inner = match self.inner.upgrade() {
            Some(i) => i,
            None => {
                warn!("DiscoveryContext::alloc_face_id called after engine shutdown");
                return FaceId(0);
            }
        };
        inner.face_table.alloc_id()
    }

    fn add_face(&self, face: Arc<dyn ErasedFace>) -> FaceId {
        let inner = match self.inner.upgrade() {
            Some(i) => i,
            None => {
                warn!("DiscoveryContext::add_face called after engine shutdown");
                return FaceId(0);
            }
        };

        let face_id = face.id();
        let kind = face.kind();
        let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
        let cancel = self.cancel.child_token();

        let state = if kind == ndn_transport::FaceKind::Udp {
            FaceState::new_reliable(
                cancel.clone(),
                FacePersistency::OnDemand,
                send_tx,
                ndn_face_net::DEFAULT_UDP_MTU,
            )
        } else {
            FaceState::new(cancel.clone(), FacePersistency::OnDemand, send_tx)
        };
        inner.face_states.insert(face_id, state);
        inner.face_table.insert_arc(Arc::clone(&face));

        let discovery = Arc::clone(&inner.discovery);
        let discovery_ctx = inner
            .discovery_ctx
            .get()
            .expect("EngineDiscoveryContext not yet initialized")
            .clone();

        // Spawn outbound send task.
        {
            let d = Arc::clone(&discovery);
            let ctx = Arc::clone(&discovery_ctx);
            tokio::spawn(crate::engine::run_face_sender(
                Arc::clone(&face),
                send_rx,
                FacePersistency::OnDemand,
                crate::dispatcher::FaceRunnerCtx {
                    face_id,
                    cancel: cancel.clone(),
                    face_table: Arc::clone(&inner.face_table),
                    fib: Arc::clone(&inner.fib),
                    face_states: Arc::clone(&inner.face_states),
                    discovery: d,
                    discovery_ctx: ctx,
                },
            ));
        }

        // Spawn inbound recv task.
        let pipeline_tx = match inner.pipeline_tx.get() {
            Some(tx) => tx.clone(),
            None => {
                warn!("DiscoveryContext::add_face: pipeline_tx not yet initialized");
                return FaceId(0);
            }
        };
        tokio::spawn(crate::dispatcher::run_face_reader(
            face,
            pipeline_tx,
            Arc::clone(&inner.pit),
            crate::dispatcher::FaceRunnerCtx {
                face_id,
                cancel,
                face_table: Arc::clone(&inner.face_table),
                fib: Arc::clone(&inner.fib),
                face_states: Arc::clone(&inner.face_states),
                discovery,
                discovery_ctx,
            },
        ));

        face_id
    }

    fn remove_face(&self, face_id: FaceId) {
        let inner = match self.inner.upgrade() {
            Some(i) => i,
            None => return,
        };
        if let Some((_, state)) = inner.face_states.remove(&face_id) {
            state.cancel.cancel();
        }
        inner.fib.remove_face(face_id);
        inner.face_table.remove(face_id);
    }

    // ── FIB management ───────────────────────────────────────────────────────

    fn add_fib_entry(&self, prefix: &Name, nexthop: FaceId, cost: u32, owner: ProtocolId) {
        let inner = match self.inner.upgrade() {
            Some(i) => i,
            None => return,
        };
        inner.fib.add_nexthop(prefix, nexthop, cost);
        self.owned_routes
            .entry(owner)
            .or_default()
            .push((prefix.clone(), nexthop));
    }

    fn remove_fib_entry(&self, prefix: &Name, nexthop: FaceId, owner: ProtocolId) {
        let inner = match self.inner.upgrade() {
            Some(i) => i,
            None => return,
        };
        inner.fib.remove_nexthop(prefix, nexthop);
        if let Some(mut routes) = self.owned_routes.get_mut(&owner) {
            routes.retain(|(n, f)| !(n == prefix && *f == nexthop));
        }
    }

    fn remove_fib_entries_by_owner(&self, owner: ProtocolId) {
        let inner = match self.inner.upgrade() {
            Some(i) => i,
            None => return,
        };
        if let Some((_, routes)) = self.owned_routes.remove(&owner) {
            for (prefix, nexthop) in routes {
                inner.fib.remove_nexthop(&prefix, nexthop);
            }
        }
    }

    // ── Neighbor table ───────────────────────────────────────────────────────

    fn neighbors(&self) -> Arc<dyn NeighborTableView> {
        Arc::clone(&self.neighbors) as Arc<dyn NeighborTableView>
    }

    fn update_neighbor(&self, update: NeighborUpdate) {
        self.neighbors.apply(update);
    }

    // ── Packet I/O ───────────────────────────────────────────────────────────

    fn send_on(&self, face_id: FaceId, pkt: Bytes) {
        let inner = match self.inner.upgrade() {
            Some(i) => i,
            None => return,
        };
        if let Some(state) = inner.face_states.get(&face_id) {
            let _ = state.send_tx.try_send(pkt);
        }
    }

    // ── Time ─────────────────────────────────────────────────────────────────

    fn now(&self) -> Instant {
        Instant::now()
    }
}
