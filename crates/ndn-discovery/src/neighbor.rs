//! Neighbor table — engine-owned state for all discovered peers.
//!
//! The table is owned by the engine (via [`DiscoveryContext`]) rather than by
//! any individual protocol implementation.  This means the table survives
//! protocol swaps at runtime and can be shared across multiple simultaneous
//! protocols (e.g. EtherND + SWIM running together).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ndn_packet::Name;
use ndn_transport::FaceId;
use tracing::{debug, info};

use crate::MacAddr;

/// Lifecycle state of a neighbor peer.
#[derive(Clone, Debug)]
pub enum NeighborState {
    /// Actively probing — waiting for a hello response.
    Probing {
        /// Number of consecutive unanswered probe attempts.
        attempts: u8,
        /// When the last probe was sent.
        last_probe: Instant,
    },
    /// Link confirmed reachable.
    Established {
        /// Timestamp of last successful exchange.
        last_seen: Instant,
    },
    /// Missed several hellos; link may be degrading.
    Stale {
        /// Number of consecutive missed hellos.
        miss_count: u8,
        /// Timestamp of last successful exchange before failures began.
        last_seen: Instant,
    },
    /// Peer is considered unreachable; entry pending removal.
    Absent,
}

/// A discovered neighbor and its per-link face bindings.
#[derive(Clone, Debug)]
pub struct NeighborEntry {
    /// NDN node name (e.g. `/ndn/site/host`).
    pub node_name: Name,
    /// Current reachability state.
    pub state: NeighborState,
    /// Per-link face bindings: `(face_id, source_mac, interface_name)`.
    ///
    /// A peer may be reachable over multiple interfaces simultaneously
    /// (e.g. Ethernet + Wi-Fi).  Each gets its own unicast face.
    pub faces: Vec<(FaceId, MacAddr, String)>,
    /// Estimated round-trip time in microseconds (EWMA, `None` until measured).
    pub rtt_us: Option<u32>,
    /// Nonce sent in the most recent outstanding hello Interest, used for
    /// replay detection and RTT measurement.
    pub pending_nonce: Option<u32>,
}

impl NeighborEntry {
    pub fn new(node_name: Name) -> Self {
        Self {
            node_name,
            state: NeighborState::Probing {
                attempts: 0,
                last_probe: Instant::now(),
            },
            faces: Vec::new(),
            rtt_us: None,
            pending_nonce: None,
        }
    }

    /// Return whether this neighbor has any live unicast faces.
    pub fn is_reachable(&self) -> bool {
        matches!(self.state, NeighborState::Established { .. }) && !self.faces.is_empty()
    }

    /// Find the face for the given MAC + interface, if one already exists.
    pub fn face_for(&self, mac: &MacAddr, iface: &str) -> Option<FaceId> {
        self.faces
            .iter()
            .find(|(_, m, i)| m == mac && i == iface)
            .map(|(id, _, _)| *id)
    }
}

/// Mutation applied to the neighbor table via [`DiscoveryContext::update_neighbor`].
pub enum NeighborUpdate {
    /// Insert or replace a full entry.
    Upsert(NeighborEntry),
    /// Transition an existing entry to a new state.
    SetState { name: Name, state: NeighborState },
    /// Add a face binding to an existing entry.
    AddFace {
        name: Name,
        face_id: FaceId,
        mac: MacAddr,
        iface: String,
    },
    /// Remove a face binding.
    RemoveFace { name: Name, face_id: FaceId },
    /// Record a measured RTT for an entry.
    UpdateRtt { name: Name, rtt_us: u32 },
    /// Remove the entry entirely.
    Remove(Name),
}

fn state_label(s: &NeighborState) -> &'static str {
    match s {
        NeighborState::Probing { .. } => "Probing",
        NeighborState::Established { .. } => "Established",
        NeighborState::Stale { .. } => "Stale",
        NeighborState::Absent => "Absent",
    }
}

/// Engine-owned, lock-protected neighbor table.
///
/// Wrapped in `Arc<NeighborTable>` so both the engine and the
/// `DiscoveryContext` implementation can hold a reference.
pub struct NeighborTable {
    inner: Mutex<HashMap<Name, NeighborEntry>>,
}

impl NeighborTable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
        })
    }

    /// Apply a [`NeighborUpdate`].
    pub fn apply(&self, update: NeighborUpdate) {
        let mut map = self.inner.lock().unwrap();
        match update {
            NeighborUpdate::Upsert(entry) => {
                let is_new = !map.contains_key(&entry.node_name);
                let label = state_label(&entry.state);
                let name = entry.node_name.clone();
                map.insert(name.clone(), entry);
                if is_new {
                    debug!(peer = %name, state = label, "neighbor added to table");
                }
            }
            NeighborUpdate::SetState { name, state } => {
                if let Some(entry) = map.get_mut(&name) {
                    let from = state_label(&entry.state);
                    let to = state_label(&state);
                    if from != to {
                        // State-variant transitions are meaningful lifecycle events;
                        // same-variant updates (e.g. refreshing last_seen) are silent.
                        if matches!(state, NeighborState::Established { .. }) {
                            info!(peer = %name, %from, %to, "neighbor established");
                        } else if matches!(state, NeighborState::Stale { .. }) {
                            info!(peer = %name, %from, %to, "neighbor went stale");
                        } else {
                            debug!(peer = %name, %from, %to, "neighbor state →");
                        }
                    }
                    entry.state = state;
                }
            }
            NeighborUpdate::AddFace {
                name,
                face_id,
                mac,
                iface,
            } => {
                if let Some(entry) = map.get_mut(&name) {
                    // Avoid duplicates.
                    if entry.face_for(&mac, &iface).is_none() {
                        entry.faces.push((face_id, mac, iface));
                    }
                }
            }
            NeighborUpdate::RemoveFace { name, face_id } => {
                if let Some(entry) = map.get_mut(&name) {
                    entry.faces.retain(|(id, _, _)| *id != face_id);
                }
            }
            NeighborUpdate::UpdateRtt { name, rtt_us } => {
                if let Some(entry) = map.get_mut(&name) {
                    // EWMA with α = 0.125 (same as TCP RTO estimation).
                    entry.rtt_us = Some(match entry.rtt_us {
                        None => rtt_us,
                        Some(prev) => (7 * prev + rtt_us) / 8,
                    });
                }
            }
            NeighborUpdate::Remove(name) => {
                if map.remove(&name).is_some() {
                    info!(peer = %name, "neighbor removed from table");
                }
            }
        }
    }

    /// Snapshot a single entry by name.
    pub fn get(&self, name: &Name) -> Option<NeighborEntry> {
        self.inner.lock().unwrap().get(name).cloned()
    }

    /// Snapshot all entries.
    pub fn all(&self) -> Vec<NeighborEntry> {
        self.inner.lock().unwrap().values().cloned().collect()
    }

    /// Find a face for the given MAC + interface across all entries.
    pub fn face_for_peer(&self, mac: &MacAddr, iface: &str) -> Option<FaceId> {
        let map = self.inner.lock().unwrap();
        for entry in map.values() {
            if let Some(id) = entry.face_for(mac, iface) {
                return Some(id);
            }
        }
        None
    }
}

impl Default for NeighborTable {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl crate::NeighborTableView for NeighborTable {
    fn get(&self, name: &Name) -> Option<NeighborEntry> {
        NeighborTable::get(self, name)
    }
    fn all(&self) -> Vec<NeighborEntry> {
        NeighborTable::all(self)
    }
    fn face_for_peer(&self, mac: &crate::MacAddr, iface: &str) -> Option<FaceId> {
        NeighborTable::face_for_peer(self, mac, iface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn upsert_and_get() {
        let table = NeighborTable::new();
        let n = name("/ndn/test/node");
        table.apply(NeighborUpdate::Upsert(NeighborEntry::new(n.clone())));
        assert!(table.get(&n).is_some());
    }

    #[test]
    fn remove_entry() {
        let table = NeighborTable::new();
        let n = name("/ndn/test/node");
        table.apply(NeighborUpdate::Upsert(NeighborEntry::new(n.clone())));
        table.apply(NeighborUpdate::Remove(n.clone()));
        assert!(table.get(&n).is_none());
    }

    #[test]
    fn rtt_ewma() {
        let table = NeighborTable::new();
        let n = name("/ndn/test/node");
        table.apply(NeighborUpdate::Upsert(NeighborEntry::new(n.clone())));
        table.apply(NeighborUpdate::UpdateRtt {
            name: n.clone(),
            rtt_us: 1000,
        });
        let e = table.get(&n).unwrap();
        assert_eq!(e.rtt_us, Some(1000)); // first sample stored as-is

        table.apply(NeighborUpdate::UpdateRtt {
            name: n.clone(),
            rtt_us: 2000,
        });
        let e = table.get(&n).unwrap();
        // EWMA: (7*1000 + 2000) / 8 = 1125
        assert_eq!(e.rtt_us, Some(1125));
    }

    #[test]
    fn add_face_deduplicates() {
        let table = NeighborTable::new();
        let n = name("/ndn/test/node");
        let mac = MacAddr::new([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);
        table.apply(NeighborUpdate::Upsert(NeighborEntry::new(n.clone())));
        table.apply(NeighborUpdate::AddFace {
            name: n.clone(),
            face_id: FaceId(1),
            mac,
            iface: "eth0".into(),
        });
        table.apply(NeighborUpdate::AddFace {
            name: n.clone(),
            face_id: FaceId(1),
            mac,
            iface: "eth0".into(),
        });
        let e = table.get(&n).unwrap();
        assert_eq!(e.faces.len(), 1);
    }

    #[test]
    fn face_for_peer_lookup() {
        let table = NeighborTable::new();
        let n = name("/ndn/test/node");
        let mac = MacAddr::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        table.apply(NeighborUpdate::Upsert(NeighborEntry::new(n.clone())));
        table.apply(NeighborUpdate::AddFace {
            name: n.clone(),
            face_id: FaceId(7),
            mac,
            iface: "eth0".into(),
        });
        assert_eq!(table.face_for_peer(&mac, "eth0"), Some(FaceId(7)));
        assert_eq!(table.face_for_peer(&mac, "eth1"), None);
    }
}
