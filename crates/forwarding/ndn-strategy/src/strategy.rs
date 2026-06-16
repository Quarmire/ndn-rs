use std::sync::Arc;
use std::time::Duration;

use ndn_packet::Name;
use ndn_runtime::Runtime;
use ndn_transport::ForwardingAction;
use tokio_util::sync::CancellationToken;

use crate::context::StrategyContext;

/// Handle to a callback scheduled via [`Strategy::schedule`].
///
/// Dropping the handle does **not** cancel the callback. Call
/// [`ScheduledEvent::cancel`] to suppress a pending firing; a callback
/// already executing runs to completion regardless.
#[derive(Clone, Debug)]
pub struct ScheduledEvent {
    cancel: CancellationToken,
}

impl ScheduledEvent {
    /// Cancel the scheduled callback. Idempotent.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

fn schedule_on(
    runtime: &Arc<dyn Runtime>,
    delay: Duration,
    callback: Box<dyn FnOnce() + Send + 'static>,
) -> ScheduledEvent {
    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();
    let sleep_fut = runtime.sleep(delay);
    runtime.spawn(Box::pin(async move {
        if cancel_task.run_until_cancelled(sleep_fut).await.is_some() {
            callback();
        }
    }));
    ScheduledEvent { cancel }
}

/// Per-FIB-entry forwarding decision function.
///
/// Invoked by the pipeline once per packet event (Interest in / Data in /
/// Interest timeout / Nack in) for a FIB entry the strategy is registered
/// against. Reads PIT/FIB/measurements state through [`StrategyContext`]
/// and returns one or more [`ForwardingAction`] values for the pipeline
/// to execute. Implementations must not block; defer long work via
/// [`Self::schedule`] or [`ForwardingAction::ForwardAfter`].
pub trait Strategy: Send + Sync + 'static {
    /// Wire name on `/localhost/nfd/strategy-choice`. `&Name` avoids
    /// allocation on the hot path.
    fn name(&self) -> &Name;

    /// Optional fast path mirroring [`Self::after_receive_interest`].
    /// `Some(actions)` short-circuits; `None` falls through to
    /// [`Self::after_receive_interest`]. (Both are synchronous now — see
    /// the module note; this remains as a distinct cheap-check entry point.)
    fn decide(&self, _ctx: &StrategyContext) -> Option<smallvec::SmallVec<[ForwardingAction; 2]>> {
        None
    }

    /// Sans-io: a synchronous decision returning [`ForwardingAction`]s for the
    /// pipeline to execute. Implementations must not block or do I/O — defer
    /// via [`Self::schedule`] or [`ForwardingAction::ForwardAfter`].
    fn after_receive_interest(
        &self,
        ctx: &StrategyContext,
    ) -> smallvec::SmallVec<[ForwardingAction; 2]>;

    /// Hook for strategy bookkeeping (RTT samples, link-quality updates)
    /// and strategy-driven egress decisions on satisfying Data. Default
    /// forwarding (Data downstream to PIT in-records) is the pipeline's
    /// job.
    fn after_receive_data(
        &self,
        ctx: &StrategyContext,
    ) -> smallvec::SmallVec<[ForwardingAction; 2]>;

    /// Default suppresses; override to retry on a different nexthop.
    fn on_interest_timeout(&self, _ctx: &StrategyContext) -> ForwardingAction {
        ForwardingAction::Suppress
    }

    /// Default suppresses; override to retry on a different nexthop or
    /// to forward the Nack downstream.
    fn on_nack(
        &self,
        _ctx: &StrategyContext,
        _reason: ndn_transport::NackReason,
    ) -> ForwardingAction {
        ForwardingAction::Suppress
    }

    /// Schedule `callback` to run after `delay` on the engine
    /// [`Runtime`]. Complements [`ForwardingAction::ForwardAfter`]:
    /// `ForwardAfter` is for deferred forwarding; `schedule` is for
    /// arbitrary strategy code (sampling, probing, neighbour
    /// bookkeeping). Override for test-only fake clocks.
    fn schedule(
        &self,
        ctx: &StrategyContext<'_>,
        delay: Duration,
        callback: Box<dyn FnOnce() + Send + 'static>,
    ) -> ScheduledEvent {
        schedule_on(ctx.runtime, delay, callback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn schedule_fires_callback_after_delay() {
        let runtime: Arc<dyn Runtime> = Arc::new(ndn_runtime::TokioRuntime);
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        let _ev = schedule_on(
            &runtime,
            Duration::from_millis(20),
            Box::new(move || fired_clone.store(true, Ordering::SeqCst)),
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(fired.load(Ordering::SeqCst), "callback never ran");
    }

    #[tokio::test]
    async fn schedule_cancel_suppresses_callback() {
        let runtime: Arc<dyn Runtime> = Arc::new(ndn_runtime::TokioRuntime);
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        let ev = schedule_on(
            &runtime,
            Duration::from_millis(100),
            Box::new(move || fired_clone.store(true, Ordering::SeqCst)),
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
        ev.cancel();
        assert!(ev.is_cancelled());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !fired.load(Ordering::SeqCst),
            "cancelled callback still ran"
        );
    }
}
