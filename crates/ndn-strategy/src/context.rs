use std::sync::Arc;

use ndn_packet::Name;
use ndn_runtime::Runtime;
use ndn_signals_core::{GeoPos, SignalView};
use ndn_store::PitToken;
use ndn_transport::{AnyMap, FaceId};

use crate::MeasurementsTable;

/// Previous-hop geographic position (NDNLPv2 A-LAL PL header), surfaced
/// per-Interest in [`StrategyContext::extensions`] for geographic strategies
/// (CCLF Location Score). The previous hop is whoever forwarded this Interest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrevHopLocation(pub GeoPos);

/// Destination/data geographic position (NDNLPv2 A-LAL DL header), surfaced
/// per-Interest in [`StrategyContext::extensions`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataLocation(pub GeoPos);

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
    /// External/environmental signals (RSSI, SNR, GPS, …) pushed by signal
    /// sources. The canonical cross-layer input surface — read via
    /// [`SignalView::link`] / [`SignalView::node`] / [`SignalView::neighbor`].
    /// `&NoSignals` when no source is installed.
    pub signals: &'a (dyn SignalView<FaceId> + Send + Sync),
    /// Open-ended cross-layer DTOs from `ContextEnricher`s. Prefer
    /// [`Self::signals`] for known metrics; this slot is for experimental data.
    pub extensions: &'a AnyMap,
    /// Platform-agnostic spawn/sleep handle used by
    /// [`crate::Strategy::schedule`].
    pub runtime: &'a Arc<dyn Runtime>,
}
