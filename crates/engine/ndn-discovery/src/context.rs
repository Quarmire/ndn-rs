//! `DiscoveryContext` — narrow engine interface exposed to discovery protocols.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{ErasedFace, FaceId};

use crate::{MacAddr, NeighborEntry, NeighborUpdate, ProtocolId};

/// Read-only view of the neighbor table, handed to protocols via the context.
pub trait NeighborTableView: Send + Sync {
    fn get(&self, name: &Name) -> Option<NeighborEntry>;
    fn all(&self) -> Vec<NeighborEntry>;
    fn face_for_peer(&self, mac: &MacAddr, iface: &str) -> Option<FaceId>;
}

/// Narrow interface through which discovery protocols mutate engine state.
pub trait DiscoveryContext: Send + Sync {
    fn alloc_face_id(&self) -> FaceId;

    fn add_face(&self, face: Arc<dyn ErasedFace>) -> FaceId;

    fn remove_face(&self, face_id: FaceId);

    /// Install a FIB route owned by `owner` (bulk-removable via
    /// [`remove_fib_entries_by_owner`]).
    fn add_fib_entry(&self, prefix: &Name, nexthop: FaceId, cost: u32, owner: ProtocolId);

    fn remove_fib_entry(&self, prefix: &Name, nexthop: FaceId, owner: ProtocolId);

    fn remove_fib_entries_by_owner(&self, owner: ProtocolId);

    fn neighbors(&self) -> Arc<dyn NeighborTableView>;

    fn update_neighbor(&self, update: NeighborUpdate);

    /// Send raw bytes directly on a face, bypassing the forwarding pipeline.
    fn send_on(&self, face_id: FaceId, pkt: Bytes);

    fn now(&self) -> Instant;
}
