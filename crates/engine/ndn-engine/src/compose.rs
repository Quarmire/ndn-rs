use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use smallvec::SmallVec;

use crate::pipeline::{ForwardingAction, NackReason};
use ndn_packet::Name;
use ndn_strategy::{StrategyContext, StrategyFilter};

use crate::stages::ErasedStrategy;

/// A strategy that delegates to an inner strategy and post-processes
/// its forwarding actions through a chain of filters.
///
/// This enables cross-layer filtering without modifying base strategies.
/// For example, composing `BestRouteStrategy` with an `RssiFilter` produces
/// "best-route but only on faces with acceptable signal strength."
pub struct ComposedStrategy {
    name: Name,
    inner: Arc<dyn ErasedStrategy>,
    filters: Vec<Arc<dyn StrategyFilter>>,
}

impl ComposedStrategy {
    pub fn new(
        name: Name,
        inner: Arc<dyn ErasedStrategy>,
        filters: Vec<Arc<dyn StrategyFilter>>,
    ) -> Self {
        Self {
            name,
            inner,
            filters,
        }
    }

    fn apply_filters(
        &self,
        ctx: &StrategyContext,
        mut actions: SmallVec<[ForwardingAction; 2]>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        for filter in &self.filters {
            actions = filter.filter(ctx, actions);
        }
        actions
    }
}

impl ErasedStrategy for ComposedStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide_sync(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        let actions = self.inner.decide_sync(ctx)?;
        Some(self.apply_filters(ctx, actions))
    }

    fn after_receive_interest_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
    ) -> Pin<Box<dyn Future<Output = SmallVec<[ForwardingAction; 2]>> + Send + 'a>> {
        Box::pin(async move {
            let actions = self.inner.after_receive_interest_erased(ctx).await;
            self.apply_filters(ctx, actions)
        })
    }

    fn on_nack_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
        reason: NackReason,
    ) -> Pin<Box<dyn Future<Output = ForwardingAction> + Send + 'a>> {
        Box::pin(async move {
            let action = self.inner.on_nack_erased(ctx, reason).await;
            let mut actions = SmallVec::new();
            actions.push(action);
            let filtered = self.apply_filters(ctx, actions);
            filtered
                .into_iter()
                .next()
                .unwrap_or(ForwardingAction::Suppress)
        })
    }
}
