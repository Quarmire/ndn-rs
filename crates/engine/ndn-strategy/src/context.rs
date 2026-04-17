use std::sync::Arc;

use ndn_packet::Name;
use ndn_store::PitToken;
use ndn_transport::{AnyMap, FaceId};

use crate::MeasurementsTable;

#[derive(Clone, Copy, Debug)]
pub struct FibNexthop {
    pub face_id: FaceId,
    pub cost: u32,
}

#[derive(Clone, Debug)]
pub struct FibEntry {
    pub nexthops: Vec<FibNexthop>,
}

impl FibEntry {
    /// Split-horizon: exclude a specific face.
    pub fn nexthops_excluding(&self, exclude: FaceId) -> Vec<FibNexthop> {
        self.nexthops
            .iter()
            .copied()
            .filter(|n| n.face_id != exclude)
            .collect()
    }
}

/// Immutable view of engine state provided to strategy methods.
pub struct StrategyContext<'a> {
    pub name: &'a Arc<Name>,
    pub in_face: FaceId,
    pub fib_entry: Option<&'a FibEntry>,
    pub pit_token: Option<PitToken>,
    pub measurements: &'a MeasurementsTable,
    /// Cross-layer data (radio metrics, flow stats) from `ContextEnricher`s.
    pub extensions: &'a AnyMap,
}
