use dashmap::DashMap;
use ndn_packet::Name;
use ndn_transport::FaceId;
use std::sync::Arc;

/// Per-prefix flow entry tracking observed throughput and preferred radio face.
#[derive(Clone, Debug)]
pub struct FlowEntry {
    pub prefix:         Arc<Name>,
    /// The radio face that has been giving the best performance.
    pub preferred_face: FaceId,
    /// EWMA bytes/sec observed on this prefix.
    pub observed_tput:  f32,
    /// EWMA RTT in milliseconds.
    pub observed_rtt_ms: f32,
    /// Timestamp of last update (ns since Unix epoch).
    pub last_updated:   u64,
}

/// Maps name prefixes to preferred radio faces based on observed flow performance.
///
/// Acts as a fast path for the `MultiRadioStrategy` — established flows skip the
/// FIB and go directly to the historically best face. Invalidated when radio
/// channel assignments change.
pub struct FlowTable {
    entries: DashMap<Arc<Name>, FlowEntry>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self { entries: DashMap::new() }
    }

    pub fn get(&self, name: &Arc<Name>) -> Option<FlowEntry> {
        self.entries.get(name).map(|r| r.clone())
    }

    pub fn update(&self, entry: FlowEntry) {
        self.entries.insert(Arc::clone(&entry.prefix), entry);
    }

    /// Clear all entries for faces on `iface` — called on channel switch.
    pub fn flush_interface(&self, face_id: FaceId) {
        self.entries.retain(|_, v| v.preferred_face != face_id);
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl Default for FlowTable {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;

    fn make_entry(comp: &'static str, face: u32, tput: f32) -> FlowEntry {
        let prefix = Arc::new(Name::from_components([
            NameComponent::generic(Bytes::from_static(comp.as_bytes()))
        ]));
        FlowEntry {
            prefix,
            preferred_face:   FaceId(face),
            observed_tput:    tput,
            observed_rtt_ms:  10.0,
            last_updated:     0,
        }
    }

    #[test]
    fn insert_and_get() {
        let table = FlowTable::new();
        let entry = make_entry("a", 1, 100.0);
        let key = Arc::clone(&entry.prefix);
        table.update(entry);
        let got = table.get(&key).unwrap();
        assert_eq!(got.preferred_face, FaceId(1));
    }

    #[test]
    fn get_unknown_returns_none() {
        let table = FlowTable::new();
        let name = Arc::new(Name::root());
        assert!(table.get(&name).is_none());
    }

    #[test]
    fn flush_interface_removes_matching_entries() {
        let table = FlowTable::new();
        let e1 = make_entry("prefix-a", 1, 50.0);
        let e2 = make_entry("prefix-b", 2, 80.0);
        let k1 = Arc::clone(&e1.prefix);
        table.update(e1);
        table.update(e2);
        assert_eq!(table.len(), 2);
        table.flush_interface(FaceId(1));
        assert_eq!(table.len(), 1);
        assert!(table.get(&k1).is_none());
    }

    #[test]
    fn flush_nonexistent_interface_is_noop() {
        let table = FlowTable::new();
        let entry = make_entry("c", 3, 20.0);
        table.update(entry);
        table.flush_interface(FaceId(99));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn is_empty_and_len() {
        let table = FlowTable::new();
        assert!(table.is_empty());
        table.update(make_entry("d", 1, 0.0));
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
    }
}
