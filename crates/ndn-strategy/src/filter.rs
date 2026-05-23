//! `StrategyFilter` — ndn-rs extension for composing post-processing
//! filters around an inner strategy at `EngineBuilder::strategy()` time.
//! Engine-builder only: the NFD mgmt surface
//! (`/localhost/nfd/strategy-choice/set`) still installs one strategy
//! per prefix and never sees the filter chain.
//!
//! See `docs/wiki/src/design/strategy-composition.md`.

use crate::context::StrategyContext;
use ndn_transport::ForwardingAction;
use smallvec::SmallVec;

/// Post-processes forwarding actions from an inner strategy. Applied in
/// chain order; dropping every face from a `Forward` causes fallthrough
/// to the next filter (or to `Nack` if the chain exhausts).
pub trait StrategyFilter: Send + Sync + 'static {
    fn name(&self) -> &str;

    fn filter(
        &self,
        ctx: &StrategyContext,
        actions: SmallVec<[ForwardingAction; 2]>,
    ) -> SmallVec<[ForwardingAction; 2]>;
}
