use crate::context::StrategyContext;
use ndn_pipeline::ForwardingAction;
use smallvec::SmallVec;

/// Post-processes forwarding actions from an inner strategy.
///
/// Filters are applied in order by `ComposedStrategy`. Each filter can
/// reorder, remove, or augment faces in `Forward` actions — for example,
/// removing faces with RSSI below a threshold.
///
/// If a filter removes all faces from a `Forward` action, the composed
/// strategy falls through to the next action in the list (typically `Nack`
/// or `Suppress`).
pub trait StrategyFilter: Send + Sync + 'static {
    /// Human-readable filter name for logging and debug output.
    fn name(&self) -> &str;

    /// Transform or prune forwarding actions produced by the inner strategy.
    fn filter(
        &self,
        ctx: &StrategyContext,
        actions: SmallVec<[ForwardingAction; 2]>,
    ) -> SmallVec<[ForwardingAction; 2]>;
}
