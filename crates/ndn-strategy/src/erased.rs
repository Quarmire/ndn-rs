//! Object-safe wrapper trait over [`Strategy`] that boxes the RPITIT
//! futures so callers can hold `Arc<dyn ErasedStrategy>`. Blanket impl
//! `impl<S: Strategy> ErasedStrategy for S` makes the erasure automatic.

use std::future::Future;
use std::pin::Pin;

use ndn_packet::Name;
use ndn_transport::{ForwardingAction, NackReason};
use smallvec::SmallVec;

use crate::Strategy;
use crate::context::StrategyContext;

pub trait ErasedStrategy: Send + Sync + 'static {
    fn name(&self) -> &Name;

    /// Synchronous fast path. `None` falls through to async.
    fn decide_sync(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>>;

    fn after_receive_interest_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
    ) -> Pin<Box<dyn Future<Output = SmallVec<[ForwardingAction; 2]>> + Send + 'a>>;

    fn on_nack_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
        reason: NackReason,
    ) -> Pin<Box<dyn Future<Output = ForwardingAction> + Send + 'a>>;
}

impl<S: Strategy> ErasedStrategy for S {
    fn name(&self) -> &Name {
        Strategy::name(self)
    }

    fn decide_sync(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        self.decide(ctx)
    }

    fn after_receive_interest_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
    ) -> Pin<Box<dyn Future<Output = SmallVec<[ForwardingAction; 2]>> + Send + 'a>> {
        Box::pin(self.after_receive_interest(ctx))
    }

    fn on_nack_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
        reason: NackReason,
    ) -> Pin<Box<dyn Future<Output = ForwardingAction> + Send + 'a>> {
        Box::pin(self.on_nack(ctx, reason))
    }
}
