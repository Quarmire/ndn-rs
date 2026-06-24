//! Data-plane name-activity observation (opt-in).
//!
//! Some soft state must follow *real* traffic, not just control messages: ndn-pipes'
//! relay PUI inactivity monitor, for instance, must renew a pipe while its namespace is
//! still being fetched, or it would tear an active pipe down after the Promised Use
//! Interval. The forwarder is the only place that sees every packet crossing a node, so
//! it exposes this thin observation seam — the thesis NPD reads NFD logs for the same
//! signal; here it's a direct in-engine callback.

use ndn_packet::Name;

/// Observes the names of packets crossing the forwarder. Registered via
/// [`EngineBuilder::with_name_activity_observer`](crate::EngineBuilder::with_name_activity_observer);
/// when set it is called on the interest hot path, so implementations must keep
/// [`on_activity`](Self::on_activity) cheap (a prefix check against a small watched set).
pub trait NameActivityObserver: Send + Sync {
    /// An Interest for `name` is being processed by the forwarder (after the PathControl
    /// bypass, before CS/PIT — so a cache hit still registers as demand). Match it
    /// against the watched prefixes and renew the corresponding soft state.
    fn on_activity(&self, name: &Name);
}
