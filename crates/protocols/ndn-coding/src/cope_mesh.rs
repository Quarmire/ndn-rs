//! F3 mesh auto-installation (feature `f3-link-mesh`).
//!
//! [`CopeMesh`] turns a neighbor set — as a routing/neighbor table supplies —
//! into a running COPE coding mesh on a live engine: one egress
//! [`CopeMemberFace`](crate::cope_face::CopeMemberFace) per neighbor (the
//! engine's FIB routes to it by `FaceId`, so the next-hop is the out-`FaceId`),
//! a single [`CopeIngressFace`](crate::cope_face::CopeIngressFace) draining
//! decoded natives, and a background ticker that broadcasts reception reports
//! (`announce`) and flushes coded frames.
//!
//! **Fed from a live routing protocol:** the neighbor set is *dynamic*. As the
//! routing layer (e.g. NLSR's `NeighborConfig`, or any `RoutingProtocol`)
//! gains or loses an adjacency, it calls [`CopeMesh::add_neighbor`] /
//! [`CopeMesh::remove_neighbor`], or [`CopeMesh::sync_neighbors`] with the
//! current neighbor list. Each member face has its own child cancellation
//! token, so removing one neighbor reaps only that face. A routing protocol
//! installs FIB next-hops toward each neighbor via [`CopeMesh::neighbor_face`].
//!
//! The neighbor-id IS the member `FaceId`, so neighbor ids **must be allocated
//! from the engine's face-id space** (`engine.faces().alloc_id()`) to avoid
//! colliding with the ingress face or other faces — the routing layer assigns
//! them.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use ndn_engine::ForwarderEngine;
use ndn_transport::{FaceId, FacePersistency, Transport};
use tokio_util::sync::CancellationToken;

use crate::cope::NeighborId;
use crate::cope_face::{CopeBroadcastLink, CopeIngressFace, CopeMemberFace};

/// A COPE coding mesh installed on a [`ForwarderEngine`], with a dynamic
/// neighbor set driven by routing.
pub struct CopeMesh<T: Transport> {
    engine: ForwarderEngine,
    link: Arc<CopeBroadcastLink<T>>,
    /// neighbor → (member face id, that face's cancel token).
    members: HashMap<NeighborId, (FaceId, CancellationToken)>,
    ingress_face_id: FaceId,
    /// Parent token; cancelling it (on drop) reaps every member + the ingress.
    cancel: CancellationToken,
}

impl<T: Transport> CopeMesh<T> {
    /// Install a mesh over the broadcast transport `inner` for the initial
    /// `neighbors` (the routing-table-derived set). `self_id` is this node's
    /// neighbor id (used in its reception reports). Registers one egress member
    /// face per neighbor (`FaceId(neighbor)`) plus one ingress face, all
    /// `Permanent`. Use [`add_neighbor`](Self::add_neighbor) /
    /// [`sync_neighbors`](Self::sync_neighbors) to track routing changes.
    pub fn install(
        engine: &ForwarderEngine,
        inner: T,
        self_id: NeighborId,
        neighbors: &[NeighborId],
    ) -> Self {
        let cancel = CancellationToken::new();
        let link = Arc::new(CopeBroadcastLink::new(self_id, inner));

        let ingress_face_id = engine.faces().alloc_id();
        let ingress = CopeIngressFace::new(ingress_face_id, Arc::clone(&link));
        engine.add_face_with_persistency(ingress, cancel.clone(), FacePersistency::Permanent);

        let mut mesh = Self {
            engine: engine.clone(),
            link,
            members: HashMap::new(),
            ingress_face_id,
            cancel,
        };
        for &n in neighbors {
            mesh.add_neighbor(n);
        }
        mesh
    }

    /// Add a neighbor (routing discovered an adjacency): install its egress
    /// member face. Idempotent — returns the existing `FaceId` if present.
    pub fn add_neighbor(&mut self, neighbor: NeighborId) -> FaceId {
        if let Some((fid, _)) = self.members.get(&neighbor) {
            return *fid;
        }
        let token = self.cancel.child_token();
        let face = CopeMemberFace::send_only(neighbor, Arc::clone(&self.link));
        let fid = face.id();
        self.engine
            .add_face_with_persistency(face, token.clone(), FacePersistency::Permanent);
        self.members.insert(neighbor, (fid, token));
        fid
    }

    /// Remove a neighbor (routing lost the adjacency): cancel just its member
    /// face and drop it from the engine. Returns `true` if it was present.
    pub fn remove_neighbor(&mut self, neighbor: NeighborId) -> bool {
        match self.members.remove(&neighbor) {
            Some((fid, token)) => {
                token.cancel(); // stop this member's I/O tasks
                self.engine.faces().remove(fid);
                true
            }
            None => false,
        }
    }

    /// Reconcile the installed members to exactly `desired` — the idiomatic
    /// call on a routing neighbor-table change: adds new neighbors, removes
    /// vanished ones.
    pub fn sync_neighbors(&mut self, desired: &[NeighborId]) {
        let want: HashSet<NeighborId> = desired.iter().copied().collect();
        let stale: Vec<NeighborId> = self
            .members
            .keys()
            .copied()
            .filter(|n| !want.contains(n))
            .collect();
        for n in stale {
            self.remove_neighbor(n);
        }
        for &n in desired {
            self.add_neighbor(n);
        }
    }

    /// Current member neighbors.
    pub fn neighbors(&self) -> Vec<NeighborId> {
        self.members.keys().copied().collect()
    }

    /// The `FaceId` to route toward `neighbor` (a routing protocol installs the
    /// FIB next-hop using this).
    pub fn neighbor_face(&self, neighbor: NeighborId) -> Option<FaceId> {
        self.members.get(&neighbor).map(|(fid, _)| *fid)
    }

    /// The ingress face decoded natives arrive on.
    pub fn ingress_face_id(&self) -> FaceId {
        self.ingress_face_id
    }

    /// The shared coding link (enqueue/report/flush/announce live here).
    pub fn link(&self) -> &Arc<CopeBroadcastLink<T>> {
        &self.link
    }

    /// The mesh's cancellation token (fires on drop) — pass it to
    /// [`spawn_neighbor_sync`](Self::spawn_neighbor_sync) so the driver stops
    /// with the mesh.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Drive the neighbor set from a routing protocol's neighbor-change stream:
    /// spawn a task that calls [`sync_neighbors`](Self::sync_neighbors) every
    /// time `rx` reports a new active-neighbor-id set. This is the decoupled
    /// hook — `ndn-coding` stays independent of any routing crate. The adapter
    /// that maps a concrete protocol's events to this `watch` is a few lines in
    /// the integration layer, e.g. for NLSR:
    ///
    /// ```ignore
    /// // hello: ndn_routing …::hello::HelloProtocol
    /// let mut adj = hello.adjacency_watch(); // watch<AdjacencySnapshot>
    /// let (tx, rx) = tokio::sync::watch::channel(Vec::new());
    /// CopeMesh::spawn_neighbor_sync(Arc::clone(&mesh), rx, mesh_lock.cancel_token());
    /// tokio::spawn(async move {
    ///     while adj.changed().await.is_ok() {
    ///         let ids = adj.borrow().neighbors.iter()
    ///             .filter(|(_, s)| matches!(s, NeighborState::Active))
    ///             .filter_map(|(n, _)| name_to_neighbor_id(n))
    ///             .collect();
    ///         let _ = tx.send(ids);
    ///     }
    /// });
    /// ```
    pub fn spawn_neighbor_sync(
        mesh: Arc<tokio::sync::Mutex<Self>>,
        mut rx: tokio::sync::watch::Receiver<Vec<NeighborId>>,
        cancel: CancellationToken,
    ) where
        T: 'static,
    {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    changed = rx.changed() => {
                        if changed.is_err() {
                            break; // routing stream closed
                        }
                        let desired = rx.borrow_and_update().clone();
                        mesh.lock().await.sync_neighbors(&desired);
                    }
                }
            }
        });
    }

    /// Start the background ticker: every `interval`, broadcast this node's
    /// reception report (`announce`) and flush coded frames. Stops on drop.
    pub fn start_ticker(&self, interval: Duration) {
        let link = Arc::clone(&self.link);
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {
                        let _ = link.announce().await;
                        let _ = link.flush().await;
                    }
                }
            }
        });
    }
}

impl<T: Transport> Drop for CopeMesh<T> {
    fn drop(&mut self) {
        self.cancel.cancel(); // stop the ticker + reap all mesh faces
    }
}
