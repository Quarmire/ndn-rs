use crate::context::StrategyContext;
use ndn_transport::ForwardingAction;
use smallvec::SmallVec;

/// Post-processes forwarding actions from an inner strategy. Applied in order
/// by `ComposedStrategy`; dropping all faces from a `Forward` causes fallthrough.
pub trait StrategyFilter: Send + Sync + 'static {
    fn name(&self) -> &str;

    fn filter(
        &self,
        ctx: &StrategyContext,
        actions: SmallVec<[ForwardingAction; 2]>,
    ) -> SmallVec<[ForwardingAction; 2]>;
}
