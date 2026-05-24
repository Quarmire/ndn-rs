//! Forwarding strategy framework: the [`Strategy`] trait, the
//! [`StrategyContext`] view of PIT/FIB/measurements state, built-in
//! [`BestRouteStrategy`] and [`MulticastStrategy`], and a
//! [`StrategyFilter`] composition seam for engine-builder use.

#![allow(missing_docs)]

pub mod best_route;
pub mod context;
pub mod erased;
pub mod filter;
pub mod filters;
pub mod measurements;
pub mod multicast;
pub mod registry;
pub mod self_learning;
pub mod signals;
pub mod strategy;

pub use best_route::BestRouteStrategy;
pub use context::{FibEntry, FibNexthop, StrategyContext};
pub use erased::ErasedStrategy;
pub use filter::StrategyFilter;
pub use filters::RssiFilter;
pub use measurements::{MeasurementsEntry, MeasurementsTable};
pub use multicast::MulticastStrategy;
// Cross-layer signals: re-export the core taxonomy/traits + the native store.
pub use ndn_signals_core::{
    CongestionLevel, GeoPos, LinkSignals, NoSignals, NodeSignals, SignalStore, SignalView,
};
pub use signals::SignalsTable;
pub use strategy::{ScheduledEvent, Strategy};
