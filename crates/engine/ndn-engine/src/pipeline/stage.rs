use super::action::Action;
use super::context::PacketContext;

/// A single stage in the NDN forwarding pipeline.
///
/// `process` takes `PacketContext` by value — `Action::Continue` returns it
/// to the runner; all other actions consume it, making use-after-hand-off
/// a compile error.
pub trait PipelineStage: Send + Sync + 'static {
    fn process(
        &self,
        ctx: PacketContext,
    ) -> impl std::future::Future<Output = Result<Action, super::action::DropReason>> + Send;
}

/// Object-safe wrapper for stages that need dynamic dispatch (e.g. plugins).
/// The built-in pipeline is monomorphised; this is only for plugin stages.
pub type BoxedStage = Box<
    dyn Fn(
            PacketContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Action, super::action::DropReason>> + Send>,
        > + Send
        + Sync,
>;
