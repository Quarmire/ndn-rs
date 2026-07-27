//! Forwarding strategy framework: the [`Strategy`] trait, the
//! [`StrategyContext`] view of PIT/FIB/measurements state, built-in
//! [`BestRouteStrategy`] and [`MulticastStrategy`], and a
//! [`StrategyFilter`] composition seam for engine-builder use.

#![allow(missing_docs)]
// The built-in strategies register themselves through `register_strategy!`,
// which expands to a `linkme::distributed_slice` element — a `link_section`
// static that the `unsafe_code` lint flags. The macro itself carries NO
// `#[allow(unsafe_code)]`, because that would be *incompatible* with a
// downstream registrant crate that sets `#![forbid(unsafe_code)]`
// (e.g. ndn-ext's ndn-strategy-cclf). So the allow lives here, at the crate
// root of the crate that owns the built-ins, and does not leak into the macro
// expansion. There is no hand-written `unsafe` in this crate.
#![allow(unsafe_code)]

pub mod best_route;
pub mod congestion;
pub mod congestion_aware;
pub mod context;
pub mod erased;
pub mod filter;
pub mod filters;
pub mod broadcast;
pub mod measured;
pub mod measurements;
pub mod multicast;
pub mod registry;
pub mod self_learning;
pub mod signals;
pub mod strategy;

pub use best_route::BestRouteStrategy;
pub use broadcast::BroadcastStrategy;
pub use congestion::{CongestionConfig, CongestionFeedback, CongestionSource, congestion_feedback};
pub use congestion_aware::CongestionAwareStrategy;
pub use context::{DataLocation, FibEntry, FibNexthop, PrevHopLocation, StrategyContext};
pub use erased::ErasedStrategy;
pub use filter::StrategyFilter;
pub use filters::RssiFilter;
pub use measured::MeasuredStrategy;
pub use measurements::{MeasurementsEntry, MeasurementsTable};
pub use multicast::MulticastStrategy;
// Cross-layer signals: re-export the core taxonomy/traits + the native store.
pub use ndn_signals_core::{
    CongestionLevel, GeoPos, LinkSignals, NoSignals, NodeSignals, SignalStore, SignalView,
};
pub use signals::SignalsTable;
pub use strategy::{ScheduledEvent, Strategy};
