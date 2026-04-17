use crate::context::StrategyContext;
use ndn_packet::Name;
use ndn_transport::ForwardingAction;

/// A pure decision function: reads state through `StrategyContext`, returns
/// `ForwardingAction` values for the pipeline to execute.
pub trait Strategy: Send + Sync + 'static {
    fn name(&self) -> &Name;

    /// Synchronous fast path. Return `Some` to skip the async `Box::pin` overhead.
    fn decide(&self, _ctx: &StrategyContext) -> Option<smallvec::SmallVec<[ForwardingAction; 2]>> {
        None
    }

    fn after_receive_interest(
        &self,
        ctx: &StrategyContext,
    ) -> impl std::future::Future<Output = smallvec::SmallVec<[ForwardingAction; 2]>> + Send;

    fn after_receive_data(
        &self,
        ctx: &StrategyContext,
    ) -> impl std::future::Future<Output = smallvec::SmallVec<[ForwardingAction; 2]>> + Send;

    fn on_interest_timeout(
        &self,
        _ctx: &StrategyContext,
    ) -> impl std::future::Future<Output = ForwardingAction> + Send {
        async { ForwardingAction::Suppress }
    }

    fn on_nack(
        &self,
        _ctx: &StrategyContext,
        _reason: ndn_transport::NackReason,
    ) -> impl std::future::Future<Output = ForwardingAction> + Send {
        async { ForwardingAction::Suppress }
    }
}
