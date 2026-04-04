//! `DiscoveryContext` — narrow engine interface exposed to discovery protocols.
//!
//! Protocols call context methods to add/remove faces, install FIB routes, and
//! update the neighbor table.  They cannot access the engine directly, which
//! keeps the protocol implementations portable and testable in isolation.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{ErasedFace, FaceId};

use crate::{MacAddr, NeighborEntry, NeighborUpdate, ProtocolId};

/// Read-only view of the neighbor table, handed to protocols via the context.
pub trait NeighborTableView: Send + Sync {
    /// Look up an entry by node name.
    fn get(&self, name: &Name) -> Option<NeighborEntry>;
    /// Snapshot all entries.
    fn all(&self) -> Vec<NeighborEntry>;
    /// Find any existing face for this MAC + interface combination.
    fn face_for_peer(&self, mac: &MacAddr, iface: &str) -> Option<FaceId>;
}

/// Narrow interface through which discovery protocols mutate engine state.
///
/// The engine implements this trait on a context struct that holds `Arc`
/// references to the face table, FIB, and neighbor table.  Protocol
/// implementations only see this interface, making them easy to unit-test
/// with a stub context.
pub trait DiscoveryContext: Send + Sync {
    // ── Face management ──────────────────────────────────────────────────────

    /// Allocate a unique `FaceId` from the engine's face table.
    ///
    /// Discovery protocols call this before constructing a face object (e.g.
    /// [`NamedEtherFace::new`]) that requires an ID at construction time.
    fn alloc_face_id(&self) -> FaceId;

    /// Add a dynamically created face to the engine.
    ///
    /// Returns the `FaceId` assigned by the face table.  The engine spawns
    /// recv/send tasks and begins forwarding through the face immediately.
    fn add_face(&self, face: Arc<dyn ErasedFace>) -> FaceId;

    /// Remove a face from the engine, stopping its tasks.
    fn remove_face(&self, face_id: FaceId);

    // ── FIB management ───────────────────────────────────────────────────────

    /// Install a FIB route owned by `owner`.
    ///
    /// Routes tagged with a `ProtocolId` can be bulk-removed via
    /// [`remove_fib_entries_by_owner`] when the protocol shuts down or
    /// reconfigures.
    fn add_fib_entry(&self, prefix: &Name, nexthop: FaceId, cost: u32, owner: ProtocolId);

    /// Remove a single FIB nexthop.
    fn remove_fib_entry(&self, prefix: &Name, nexthop: FaceId, owner: ProtocolId);

    /// Remove every FIB route installed by `owner`.
    fn remove_fib_entries_by_owner(&self, owner: ProtocolId);

    // ── Neighbor table ───────────────────────────────────────────────────────

    /// Read access to the engine-owned neighbor table.
    fn neighbors(&self) -> &dyn NeighborTableView;

    /// Apply a mutation to the engine-owned neighbor table.
    fn update_neighbor(&self, update: NeighborUpdate);

    // ── Packet I/O ───────────────────────────────────────────────────────────

    /// Send raw bytes directly on a face, bypassing the pipeline.
    ///
    /// Used by discovery protocols to transmit hello packets and probes
    /// without entering the forwarding plane.
    fn send_on(&self, face_id: FaceId, pkt: Bytes);

    // ── Time ─────────────────────────────────────────────────────────────────

    /// Current monotonic time.
    fn now(&self) -> Instant;
}
