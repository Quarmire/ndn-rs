#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;

use crate::FaceId;

/// Maps rx `FaceId` → tx `FaceId` for asymmetric link pairs (e.g., wfb-ng).
///
/// On symmetric faces (Udp, Tcp, Ethernet), Data is sent back on the same face
/// an Interest arrived on. On asymmetric wfb-ng links, there is a separate
/// transmit face — this table resolves which tx face to use.
///
/// The dispatch stage consults this table before sending Data:
///
/// ```ignore
/// let send_id = face_pairs.get_tx_for_rx(in_face_id).unwrap_or(in_face_id);
/// face_table.get(send_id)?.send(data).await;
/// ```
///
/// Normal faces have no entry in this table (`get_tx_for_rx` returns `None`),
/// so `unwrap_or(in_face_id)` falls through to the standard symmetric path.
pub struct FacePairTable {
    #[cfg(not(target_arch = "wasm32"))]
    pairs: DashMap<FaceId, FaceId>,
    #[cfg(target_arch = "wasm32")]
    pairs: std::sync::Mutex<std::collections::HashMap<FaceId, FaceId>>,
}

impl FacePairTable {
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            pairs: DashMap::new(),
            #[cfg(target_arch = "wasm32")]
            pairs: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Register an asymmetric link pair: Interests arrive on `rx`, Data is
    /// sent on `tx`.
    pub fn insert(&self, rx: FaceId, tx: FaceId) {
        #[cfg(not(target_arch = "wasm32"))]
        self.pairs.insert(rx, tx);
        #[cfg(target_arch = "wasm32")]
        self.pairs.lock().unwrap().insert(rx, tx);
    }

    /// Returns the tx face to use when Data should go back on `rx_face`.
    /// Returns `None` for symmetric faces.
    pub fn get_tx_for_rx(&self, rx: FaceId) -> Option<FaceId> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.pairs.get(&rx).map(|r| *r);
        #[cfg(target_arch = "wasm32")]
        return self.pairs.lock().unwrap().get(&rx).copied();
    }

    /// Remove the pair for `rx`.
    pub fn remove(&self, rx: FaceId) {
        #[cfg(not(target_arch = "wasm32"))]
        self.pairs.remove(&rx);
        #[cfg(target_arch = "wasm32")]
        self.pairs.lock().unwrap().remove(&rx);
    }

    pub fn len(&self) -> usize {
        #[cfg(not(target_arch = "wasm32"))]
        return self.pairs.len();
        #[cfg(target_arch = "wasm32")]
        return self.pairs.lock().unwrap().len();
    }

    pub fn is_empty(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        return self.pairs.is_empty();
        #[cfg(target_arch = "wasm32")]
        return self.pairs.lock().unwrap().is_empty();
    }
}

impl Default for FacePairTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u32) -> FaceId {
        FaceId(n)
    }

    #[test]
    fn get_tx_for_unknown_rx_returns_none() {
        let t = FacePairTable::new();
        assert!(t.get_tx_for_rx(id(1)).is_none());
    }

    #[test]
    fn insert_then_get_returns_tx() {
        let t = FacePairTable::new();
        t.insert(id(1), id(2));
        assert_eq!(t.get_tx_for_rx(id(1)), Some(id(2)));
    }

    #[test]
    fn remove_clears_pair() {
        let t = FacePairTable::new();
        t.insert(id(3), id(4));
        t.remove(id(3));
        assert!(t.get_tx_for_rx(id(3)).is_none());
    }

    #[test]
    fn symmetric_face_returns_none() {
        let t = FacePairTable::new();
        t.insert(id(10), id(11));
        // Face 99 is symmetric — not in the table.
        assert!(t.get_tx_for_rx(id(99)).is_none());
    }

    #[test]
    fn multiple_pairs_independent() {
        let t = FacePairTable::new();
        t.insert(id(1), id(2));
        t.insert(id(3), id(4));
        assert_eq!(t.get_tx_for_rx(id(1)), Some(id(2)));
        assert_eq!(t.get_tx_for_rx(id(3)), Some(id(4)));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn is_empty_and_len() {
        let t = FacePairTable::new();
        assert!(t.is_empty());
        t.insert(id(0), id(1));
        assert!(!t.is_empty());
        assert_eq!(t.len(), 1);
    }
}
