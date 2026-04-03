use std::sync::Arc;

use ndn_packet::Name;
use ndn_store::PitToken;
use ndn_transport::{AnyMap, FaceId};

use crate::MeasurementsTable;

/// A single FIB nexthop.
#[derive(Clone, Copy, Debug)]
pub struct FibNexthop {
    pub face_id: FaceId,
    pub cost: u32,
}

/// FIB entry: one or more nexthops with associated costs.
#[derive(Clone, Debug)]
pub struct FibEntry {
    pub nexthops: Vec<FibNexthop>,
}

impl FibEntry {
    /// Return nexthops filtered to exclude a specific face (split-horizon).
    pub fn nexthops_excluding(&self, exclude: FaceId) -> Vec<FibNexthop> {
        self.nexthops
            .iter()
            .copied()
            .filter(|n| n.face_id != exclude)
            .collect()
    }
}

/// An immutable view of the engine state provided to strategy methods.
///
/// Strategies cannot mutate forwarding tables directly — they return
/// `ForwardingAction` values and the pipeline runner acts on them.
pub struct StrategyContext<'a> {
    /// The name being forwarded.
    pub name: &'a Arc<Name>,
    /// The face the Interest or Data arrived on.
    pub in_face: FaceId,
    /// FIB entry for the longest matching prefix of `name`.
    pub fib_entry: Option<&'a FibEntry>,
    /// PIT token for the current Interest, if applicable.
    pub pit_token: Option<PitToken>,
    /// Read-only access to EWMA measurements per (prefix, face).
    pub measurements: &'a MeasurementsTable,
    /// Cross-layer enrichment data (radio metrics, flow stats, etc.).
    ///
    /// Populated by [`ContextEnricher`](ndn_engine::ContextEnricher) instances
    /// before the strategy runs. Strategies access typed data via
    /// `ctx.extensions.get::<T>()`.
    pub extensions: &'a AnyMap,
}
