use crate::context::StrategyContext;
use ndn_packet::Name;
use ndn_pipeline::ForwardingAction;

/// The forwarding strategy trait.
///
/// A strategy is a pure decision function — it reads state through
/// `StrategyContext` but cannot modify forwarding tables directly.
/// Autonomous behaviour (probing, discovery) is done via the `Probe` channel
/// on `StrategyContext`.
pub trait Strategy: Send + Sync + 'static {
    /// Canonical name identifying this strategy.
    fn name(&self) -> &Name;

    /// Synchronous fast path for forwarding decisions.
    ///
    /// Strategies whose `after_receive_interest` is fully synchronous should
    /// override this to return `Some(actions)`, avoiding the `Box::pin` heap
    /// allocation in the `ErasedStrategy` wrapper.
    ///
    /// Returns `None` (default) to fall through to the async path.
    fn decide(&self, _ctx: &StrategyContext) -> Option<smallvec::SmallVec<[ForwardingAction; 2]>> {
        None
    }

    /// Called when an Interest arrives and needs a forwarding decision.
    fn after_receive_interest(
        &self,
        ctx: &StrategyContext,
    ) -> impl std::future::Future<Output = smallvec::SmallVec<[ForwardingAction; 2]>> + Send;

    /// Called when Data arrives and needs to be forwarded to consumers.
    fn after_receive_data(
        &self,
        ctx: &StrategyContext,
    ) -> impl std::future::Future<Output = smallvec::SmallVec<[ForwardingAction; 2]>> + Send;

    /// Called when a PIT entry times out. Default: suppress (let the entry die).
    fn on_interest_timeout(
        &self,
        _ctx: &StrategyContext,
    ) -> impl std::future::Future<Output = ForwardingAction> + Send {
        async { ForwardingAction::Suppress }
    }

    /// Called when a Nack arrives on an out-record face.
    fn on_nack(
        &self,
        _ctx: &StrategyContext,
        _reason: ndn_pipeline::NackReason,
    ) -> impl std::future::Future<Output = ForwardingAction> + Send {
        async { ForwardingAction::Suppress }
    }
}
