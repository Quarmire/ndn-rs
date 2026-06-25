//! `EngineDiscoveryContext` bridges discovery protocols to engine tables.
//! Holds `Weak<EngineInner>` to break the EngineInner → Arc<ctx> cycle.

use std::sync::{Arc, Weak};
// `DiscoveryProtocol` signs in std::time::Instant. `Instant::now()` panics
// on wasm; the wasm engine uses `NoDiscovery` and never spawns the tick
// task (see `wasm_builder.rs`).
use std::time::Instant;

use bytes::Bytes;
use dashmap::DashMap;
use ndn_discovery_core::{
    DiscoveryContext, FaceLifecycleContext, NeighborContext, NeighborTable, NeighborTableView,
    NeighborUpdate, ProtocolId, RoutingTableContext,
};
use ndn_packet::Name;
use ndn_transport::{CongestionPolicy, Face, FaceId, FacePersistency};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::engine::{DEFAULT_SEND_QUEUE_CAP, EngineInner, FaceState};

type OwnedRoutes = DashMap<ProtocolId, Vec<(Name, FaceId)>>;

pub struct EngineDiscoveryContext {
    pub(crate) inner: Weak<EngineInner>,
    /// Mirrored from `EngineInner::neighbors` so `neighbors()` can return a
    /// reference without upgrading the `Weak`.
    neighbors: Arc<NeighborTable>,
    pub(crate) cancel: CancellationToken,
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

impl FaceLifecycleContext for EngineDiscoveryContext {
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

    fn add_face(&self, face: Arc<Face>) -> FaceId {
        let inner = match self.inner.upgrade() {
            Some(i) => i,
            None => {
                warn!("DiscoveryContext::add_face called after engine shutdown");
                return FaceId(0);
            }
        };

        let face_id = face.id();
        let kind = face.kind();
        let congestion_policy = CongestionPolicy::default_for_scope(face.scope());
        let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
        let cancel = self.cancel.child_token();

        let state = FaceState::new(
            cancel.clone(),
            FacePersistency::OnDemand,
            send_tx,
            congestion_policy,
        );
        // Discovery UDP links use NDNLPv2 reliability. Enable the per-face
        // reliability feature (canonical TxSequence + Ack + retx, the same path
        // faces/update toggles) and mirror it in the FaceFlags bitmap so
        // faces/list reports it.
        #[cfg(feature = "face-net")]
        if kind == ndn_transport::FaceKind::Udp {
            let _ = face
                .link_service
                .apply(ndn_transport::FaceOption::LpReliability(true));
            state.apply_face_flags_mask(
                ndn_transport::BIT_LP_RELIABILITY,
                ndn_transport::BIT_LP_RELIABILITY,
            );
        }
        inner.face_states.insert(face_id, state);
        inner.face_table.insert_arc(Arc::clone(&face));

        let discovery = Arc::clone(&inner.discovery);
        let discovery_ctx = inner
            .discovery_ctx
            .get()
            .expect("EngineDiscoveryContext not yet initialized")
            .clone();

        {
            let d = Arc::clone(&discovery);
            let ctx = Arc::clone(&discovery_ctx);
            inner.runtime.spawn(Box::pin(crate::engine::run_face_sender(
                Arc::clone(&face),
                send_rx,
                FacePersistency::OnDemand,
                crate::dispatcher::FaceRunnerCtx {
                    face_id,
                    cancel: cancel.clone(),
                    face_table: Arc::clone(&inner.face_table),
                    fib: Arc::clone(&inner.fib),
                    rib: Arc::clone(&inner.rib),
                    face_states: Arc::clone(&inner.face_states),
                    discovery: d,
                    discovery_ctx: ctx,
                    runtime: Arc::clone(&inner.runtime),
                    face_lifecycle_sink: inner.face_lifecycle_sink.get().cloned(),
                },
            )));
        }

        let pipeline_tx = match inner.pipeline_tx.get() {
            Some(tx) => tx.clone(),
            None => {
                warn!("DiscoveryContext::add_face: pipeline_tx not yet initialized");
                return FaceId(0);
            }
        };
        inner
            .runtime
            .spawn(Box::pin(crate::dispatcher::run_face_reader(
                face,
                pipeline_tx,
                Arc::clone(&inner.pit),
                crate::dispatcher::FaceRunnerCtx {
                    face_id,
                    cancel,
                    face_table: Arc::clone(&inner.face_table),
                    fib: Arc::clone(&inner.fib),
                    rib: Arc::clone(&inner.rib),
                    face_states: Arc::clone(&inner.face_states),
                    discovery,
                    discovery_ctx,
                    runtime: Arc::clone(&inner.runtime),
                    face_lifecycle_sink: inner.face_lifecycle_sink.get().cloned(),
                },
            )));

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
        inner.rib.handle_face_down(face_id, &inner.fib);
        inner.fib.remove_face(face_id);
        inner.face_table.remove(face_id);
    }
}

impl RoutingTableContext for EngineDiscoveryContext {
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
}

impl NeighborContext for EngineDiscoveryContext {
    fn neighbors(&self) -> Arc<dyn NeighborTableView> {
        Arc::clone(&self.neighbors) as Arc<dyn NeighborTableView>
    }

    fn update_neighbor(&self, update: NeighborUpdate) {
        self.neighbors.apply(update);
    }
}

impl DiscoveryContext for EngineDiscoveryContext {
    fn send_on(&self, face_id: FaceId, pkt: Bytes) {
        let inner = match self.inner.upgrade() {
            Some(i) => i,
            None => return,
        };
        if let Some(state) = inner.face_states.get(&face_id) {
            // Discovery beacons are locally produced; `FaceId::INVALID`
            // marks them as having no upstream source.
            let _ = state.send_tx.try_send((
                pkt,
                FaceId::INVALID,
                crate::engine::EgressIntent::default(),
            ));
        }
    }

    fn now(&self) -> Instant {
        // Route discovery's clock through the engine runtime (deterministic under a virtual
        // runtime); fall back to wall-clock only if the engine is being torn down.
        // (ndn-lab slice 0c.)
        self.inner
            .upgrade()
            .map(|i| i.runtime.now())
            .unwrap_or_else(Instant::now)
    }
}
