use super::action::Action;
use super::context::PacketContext;

/// A single stage in the forwarding pipeline. `process` takes the context
/// by value; `Action::Continue` returns it, every other variant consumes it.
pub trait PipelineStage: Send + Sync + 'static {
    fn process(
        &self,
        ctx: PacketContext,
    ) -> impl std::future::Future<Output = Result<Action, super::action::DropReason>> + Send;
}

/// Object-safe wrapper for plugin stages; the built-in pipeline is
/// monomorphised.
pub type BoxedStage = Box<
    dyn Fn(
            PacketContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Action, super::action::DropReason>> + Send>,
        > + Send
        + Sync,
>;
