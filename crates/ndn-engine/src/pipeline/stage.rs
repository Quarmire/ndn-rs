use super::action::Action;
use super::context::PacketContext;

/// A single stage in the NDN forwarding pipeline.
///
/// Stages are fixed at build time (not runtime-configurable) so the compiler
/// can inline and optimise the dispatch loop for the known concrete types.
///
/// `process` takes `PacketContext` by value. `Action::Continue` returns it
/// to the runner. All other actions consume it, making use-after-hand-off
/// a compile error.
pub trait PipelineStage: Send + Sync + 'static {
    fn process(
        &self,
        ctx: PacketContext,
    ) -> impl std::future::Future<Output = Result<Action, super::action::DropReason>> + Send;
}

/// Object-safe wrapper around `PipelineStage` for runtime dispatch.
///
/// Used for stages that genuinely need dynamic dispatch (e.g., plugin stages).
/// The built-in pipeline is monomorphised for zero-cost dispatch.
pub type BoxedStage = Box<
    dyn Fn(
            PacketContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Action, super::action::DropReason>> + Send>,
        > + Send
        + Sync,
>;
