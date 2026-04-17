use super::af_packet::MacAddr;
use ndn_packet::Name;
use ndn_transport::FaceId;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct NeighborEntry {
    pub node_name: Name,
    pub radio_faces: Vec<(FaceId, MacAddr, String)>,
    pub last_seen: u64,
}

/// Neighbor discovery state: broadcasts hello Interests and creates
/// unicast `NamedEtherFace` per peer.
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
