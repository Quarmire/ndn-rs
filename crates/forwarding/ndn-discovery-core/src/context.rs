//! Engine interfaces exposed to discovery and routing protocols.
//!
//! [`DiscoveryContext`] is decomposed into [`NeighborContext`],
//! [`RoutingTableContext`], and [`FaceLifecycleContext`] supertraits so
//! callers can take only the narrower view they need.

use std::sync::Arc;
// web-time: identical to std::time::Instant on native, JS-clock-backed on wasm32
// (this crate is the wasm-safe trait surface — std::time::Instant panics there).
use web_time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{Face, FaceId};

use crate::{MacAddr, NeighborEntry, NeighborUpdate, ProtocolId};

pub trait NeighborTableView: Send + Sync {
    fn get(&self, name: &Name) -> Option<NeighborEntry>;
    fn all(&self) -> Vec<NeighborEntry>;
    fn face_for_peer(&self, mac: &MacAddr, iface: &str) -> Option<FaceId>;
}

pub trait NeighborContext: Send + Sync {
    fn neighbors(&self) -> Arc<dyn NeighborTableView>;
    fn update_neighbor(&self, update: NeighborUpdate);
}

/// FIB writes scoped by `owner`. `remove_fib_entries_by_owner` is used
/// when a protocol is unregistered.
pub trait RoutingTableContext: Send + Sync {
    fn add_fib_entry(&self, prefix: &Name, nexthop: FaceId, cost: u32, owner: ProtocolId);
    fn remove_fib_entry(&self, prefix: &Name, nexthop: FaceId, owner: ProtocolId);
    fn remove_fib_entries_by_owner(&self, owner: ProtocolId);
}

pub trait FaceLifecycleContext: Send + Sync {
    fn alloc_face_id(&self) -> FaceId;
    fn add_face(&self, face: Arc<Face>) -> FaceId;
    fn remove_face(&self, face_id: FaceId);
}

pub trait DiscoveryContext:
    NeighborContext + RoutingTableContext + FaceLifecycleContext + Send + Sync
{
    /// Send `pkt` on a specific face. The engine stamps `FaceId::INVALID`
    /// as the source so the egress worker knows the bytes are locally
    /// produced.
    fn send_on(&self, face_id: FaceId, pkt: Bytes);

    /// Engine clock — `std::time::Instant::now()` on native, runtime
    /// `now()` on wasm.
    fn now(&self) -> Instant;
}
