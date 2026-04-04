use crate::af_packet::MacAddr;
use ndn_packet::Name;
use ndn_transport::FaceId;
use std::collections::HashMap;

/// A discovered neighbor and its per-radio face bindings.
#[derive(Clone, Debug)]
pub struct NeighborEntry {
    /// NDN node name of the neighbor.
    pub node_name: Name,
    /// Per-radio face bindings: each entry is (FaceId, MAC, interface).
    pub radio_faces: Vec<(FaceId, MacAddr, String)>,
    /// Timestamp of last successful hello (ns since Unix epoch).
    pub last_seen: u64,
}

/// Neighbor discovery task.
///
/// Sends a broadcast hello Interest, captures the UDP/Ethernet source address
/// of each responding neighbor, creates a unicast `NamedEtherFace` per peer,
/// and maintains the neighbor table.
///
/// The broadcast rate is kept minimal — just enough for initial bootstrap and
/// re-discovery after mobility events. All subsequent traffic uses per-neighbor
/// unicast faces at full 802.11 rate adaptation.
pub struct NeighborDiscovery {
    neighbors: HashMap<Name, NeighborEntry>,
}

impl NeighborDiscovery {
    pub fn new() -> Self {
        Self {
            neighbors: HashMap::new(),
        }
    }

    pub fn neighbors(&self) -> impl Iterator<Item = &NeighborEntry> {
        self.neighbors.values()
    }

    pub fn get(&self, name: &Name) -> Option<&NeighborEntry> {
        self.neighbors.get(name)
    }

    pub fn upsert(&mut self, entry: NeighborEntry) {
        self.neighbors.insert(entry.node_name.clone(), entry);
    }

    pub fn remove(&mut self, name: &Name) {
        self.neighbors.remove(name);
    }
}

impl Default for NeighborDiscovery {
    fn default() -> Self {
        Self::new()
    }
}
