//! # ndn-strategy — Forwarding strategy framework
//!
//! Defines the [`Strategy`] trait and the types strategies operate on.
//!
//! - [`StrategyContext`] gives strategies an immutable view of PIT, FIB, and
//!   measurements state, with cross-layer extension slots via [`AnyMap`].
//! - [`StrategyFilter`] enables composable pre/post processing around any
//!   strategy (e.g. [`RssiFilter`] for link-quality gating).
//! - Built-in strategies: [`BestRouteStrategy`] (lowest-cost nexthop) and
//!   [`MulticastStrategy`] (forward to all nexthops).
//! - Cross-layer DTOs ([`FaceLinkQuality`], [`LinkQualitySnapshot`]) allow
//!   transport-layer metrics to flow into strategy decisions.

pub mod best_route;
pub mod context;
pub mod cross_layer;
pub mod filter;
pub mod filters;
pub mod measurements;
pub mod multicast;
pub mod strategy;

pub use best_route::BestRouteStrategy;
pub use context::{FibEntry, FibNexthop, StrategyContext};
pub use cross_layer::{FaceLinkQuality, LinkQualitySnapshot};
pub use filter::StrategyFilter;
pub use filters::RssiFilter;
pub use measurements::{MeasurementsEntry, MeasurementsTable};
pub use multicast::MulticastStrategy;
pub use strategy::Strategy;
