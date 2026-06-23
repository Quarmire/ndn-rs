//! Native/wasm signal store — the engine-owned adapter behind the
//! [`ndn_signals_core::SignalView`] / [`ndn_signals_core::SignalStore`] traits.
//!
//! Signal *sources* (radio metrics, GPS, …) push the latest reading via the
//! `set_*` methods; strategies read cached values via the `SignalView` slot on
//! [`crate::StrategyContext`]. Pushed-not-pulled, so the forwarding hot path
//! never blocks on a driver. `DashMap` on native, `Mutex<HashMap>` on wasm32,
//! mirroring [`crate::MeasurementsTable`].
//!
//! Signals are *external/environmental* inputs (RSSI, position); they are
//! distinct from measurements, which are derived from observed NDN traffic.

#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;
#[cfg(target_arch = "wasm32")]
use std::collections::HashMap;
#[cfg(target_arch = "wasm32")]
use std::sync::Mutex;

use ndn_signals_core::{LinkSignals, NodeSignals, SignalStore, SignalView};
use ndn_transport::FaceId;

/// Concurrent cross-layer signal store: per-face link signals, this node's
/// signals, and per-neighbor (face-keyed) learned signals.
pub struct SignalsTable {
    #[cfg(not(target_arch = "wasm32"))]
    link: DashMap<FaceId, LinkSignals>,
    #[cfg(not(target_arch = "wasm32"))]
    neighbor: DashMap<FaceId, NodeSignals>,
    #[cfg(not(target_arch = "wasm32"))]
    node: DashMap<(), NodeSignals>,

    #[cfg(target_arch = "wasm32")]
    link: Mutex<HashMap<FaceId, LinkSignals>>,
    #[cfg(target_arch = "wasm32")]
    neighbor: Mutex<HashMap<FaceId, NodeSignals>>,
    #[cfg(target_arch = "wasm32")]
    node: Mutex<Option<NodeSignals>>,
}

impl SignalsTable {
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            link: DashMap::new(),
            #[cfg(not(target_arch = "wasm32"))]
            neighbor: DashMap::new(),
            #[cfg(not(target_arch = "wasm32"))]
            node: DashMap::new(),
            #[cfg(target_arch = "wasm32")]
            link: Mutex::new(HashMap::new()),
            #[cfg(target_arch = "wasm32")]
            neighbor: Mutex::new(HashMap::new()),
            #[cfg(target_arch = "wasm32")]
            node: Mutex::new(None),
        }
    }

    /// Snapshot of every per-face link signal (for the mgmt/observability
    /// dataset). Order is unspecified.
    pub fn dump_links(&self) -> Vec<(FaceId, LinkSignals)> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.link.iter().map(|e| (*e.key(), *e.value())).collect();
        #[cfg(target_arch = "wasm32")]
        return self
            .link
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
    }
}

impl Default for SignalsTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalView<FaceId> for SignalsTable {
    fn link(&self, face: FaceId) -> Option<LinkSignals> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.link.get(&face).map(|r| *r);
        #[cfg(target_arch = "wasm32")]
        return self.link.lock().unwrap().get(&face).copied();
    }

    fn node(&self) -> NodeSignals {
        #[cfg(not(target_arch = "wasm32"))]
        return self.node.get(&()).map(|r| *r).unwrap_or_default();
        #[cfg(target_arch = "wasm32")]
        return self.node.lock().unwrap().unwrap_or_default();
    }

    fn neighbor(&self, face: FaceId) -> Option<NodeSignals> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.neighbor.get(&face).map(|r| *r);
        #[cfg(target_arch = "wasm32")]
        return self.neighbor.lock().unwrap().get(&face).copied();
    }
}

impl SignalStore<FaceId> for SignalsTable {
    fn set_link(&self, face: FaceId, signals: LinkSignals) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.link.insert(face, signals);
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.link.lock().unwrap().insert(face, signals);
        }
    }

    fn set_node(&self, signals: NodeSignals) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.node.insert((), signals);
        }
        #[cfg(target_arch = "wasm32")]
        {
            *self.node.lock().unwrap() = Some(signals);
        }
    }

    fn set_neighbor(&self, face: FaceId, signals: NodeSignals) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.neighbor.insert(face, signals);
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.neighbor.lock().unwrap().insert(face, signals);
        }
    }

    fn update_link(&self, face: FaceId, f: &mut dyn FnMut(&mut LinkSignals)) {
        // Atomic field-merge under the per-key lock — so the congestion bridge and a
        // RSSI source can update disjoint fields of the same face without clobbering.
        #[cfg(not(target_arch = "wasm32"))]
        {
            f(self.link.entry(face).or_default().value_mut());
        }
        #[cfg(target_arch = "wasm32")]
        {
            f(self.link.lock().unwrap().entry(face).or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_signals_core::GeoPos;

    #[test]
    fn round_trips_link_node_neighbor() {
        let t = SignalsTable::new();
        assert_eq!(t.link(FaceId(1)), None);

        t.set_link(
            FaceId(1),
            LinkSignals {
                rssi_dbm: Some(-55),
                ..Default::default()
            },
        );
        assert_eq!(t.link(FaceId(1)).and_then(|l| l.rssi_dbm), Some(-55));

        t.set_node(NodeSignals {
            position: Some(GeoPos {
                lat_e7: 1,
                lon_e7: 2,
                alt_cm: 3,
            }),
            ..Default::default()
        });
        assert_eq!(
            t.node().position,
            Some(GeoPos {
                lat_e7: 1,
                lon_e7: 2,
                alt_cm: 3
            })
        );

        assert_eq!(t.neighbor(FaceId(9)), None);
        t.set_neighbor(
            FaceId(9),
            NodeSignals {
                battery_pct: Some(42),
                ..Default::default()
            },
        );
        assert_eq!(t.neighbor(FaceId(9)).and_then(|n| n.battery_pct), Some(42));
    }
}
