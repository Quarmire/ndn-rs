//! Object-safe wrapper trait over [`Strategy`] so callers can hold
//! `Arc<dyn ErasedStrategy>`. Blanket impl `impl<S: Strategy> ErasedStrategy
//! for S` makes the erasure automatic. (The `Strategy` trait is now
//! synchronous, so this no longer boxes futures — it just forwards.)

use ndn_packet::Name;
use ndn_transport::{ForwardingAction, NackReason};
use smallvec::SmallVec;

use crate::Strategy;
use crate::context::StrategyContext;

pub trait ErasedStrategy: Send + Sync + 'static {
    fn name(&self) -> &Name;

    /// Fast path. `None` falls through to [`Self::after_receive_interest_erased`].
    fn decide_sync(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>>;

    fn after_receive_interest_erased(
        &self,
        ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]>;

    fn on_nack_erased(&self, ctx: &StrategyContext<'_>, reason: NackReason) -> ForwardingAction;
}

impl<S: Strategy> ErasedStrategy for S {
    fn name(&self) -> &Name {
        Strategy::name(self)
    }

    fn decide_sync(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        self.decide(ctx)
    }

    fn after_receive_interest_erased(
        &self,
        ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        self.after_receive_interest(ctx)
    }

    fn on_nack_erased(&self, ctx: &StrategyContext<'_>, reason: NackReason) -> ForwardingAction {
        self.on_nack(ctx, reason)
    }
}
