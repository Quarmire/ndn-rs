//! F3 mesh auto-installation (feature `f3-link-mesh`).
//!
//! [`CopeMesh`] turns a neighbor set — as a routing/neighbor table would
//! supply — into a running COPE coding mesh on a live engine: one egress
//! [`CopeMemberFace`](crate::cope_face::CopeMemberFace) per neighbor (the
//! engine's FIB routes to it by `FaceId`, so the next-hop is the out-`FaceId`),
//! a single [`CopeIngressFace`](crate::cope_face::CopeIngressFace) draining
//! decoded natives, and a background ticker that broadcasts reception reports
//! (`announce`) and flushes coded frames over the shared broadcast medium.
//!
//! The neighbor-id IS the member `FaceId`; a routing protocol assigns neighbor
//! ids (= face ids) and installs FIB next-hops toward them via
//! [`CopeMesh::neighbor_face`]. Distributing the reception reports and feeding
//! the neighbor set from a live routing protocol are the remaining operational
//! hooks; the mechanism is here.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ndn_engine::ForwarderEngine;
use ndn_transport::{FaceId, FacePersistency, Transport};
use tokio_util::sync::CancellationToken;

use crate::cope::NeighborId;
use crate::cope_face::{CopeBroadcastLink, CopeIngressFace, CopeMemberFace};

/// A COPE coding mesh installed on a [`ForwarderEngine`].
pub struct CopeMesh<T: Transport> {
    link: Arc<CopeBroadcastLink<T>>,
    members: HashMap<NeighborId, FaceId>,
    ingress_face_id: FaceId,
    cancel: CancellationToken,
}

impl<T: Transport> CopeMesh<T> {
    /// Install a mesh over the broadcast transport `inner` for the given
    /// `neighbors` (the routing-table-derived neighbor set). `self_id` is this
    /// node's neighbor id (used in its reception reports). Registers one
    /// egress member face per neighbor (`FaceId(neighbor)`) plus one ingress
    /// face, all `Permanent`.
    pub fn install(
        engine: &ForwarderEngine,
        inner: T,
        self_id: NeighborId,
        neighbors: &[NeighborId],
    ) -> Self {
        let cancel = CancellationToken::new();
        let link = Arc::new(CopeBroadcastLink::new(self_id, inner));

        let mut members = HashMap::with_capacity(neighbors.len());
        for &n in neighbors {
            let face = CopeMemberFace::send_only(n, Arc::clone(&link));
            let fid = face.id();
            engine.add_face_with_persistency(face, cancel.clone(), FacePersistency::Permanent);
            members.insert(n, fid);
        }

        let ingress_face_id = engine.faces().alloc_id();
        let ingress = CopeIngressFace::new(ingress_face_id, Arc::clone(&link));
        engine.add_face_with_persistency(ingress, cancel.clone(), FacePersistency::Permanent);

        Self {
            link,
            members,
            ingress_face_id,
            cancel,
        }
    }

    /// The `FaceId` to route toward `neighbor` in the FIB (a routing protocol
    /// installs the next-hop using this).
    pub fn neighbor_face(&self, neighbor: NeighborId) -> Option<FaceId> {
        self.members.get(&neighbor).copied()
    }

    /// The ingress face decoded natives arrive on.
    pub fn ingress_face_id(&self) -> FaceId {
        self.ingress_face_id
    }

    /// The shared coding link (enqueue/report/flush/announce live here).
    pub fn link(&self) -> &Arc<CopeBroadcastLink<T>> {
        &self.link
    }

    /// Start the background ticker: every `interval`, broadcast this node's
    /// reception report (`announce`) and flush coded frames. Stops when the
    /// mesh is dropped (its `CancellationToken` fires).
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
        self.cancel.cancel(); // stop the ticker + reap the mesh faces
    }
}
