use std::sync::Arc;
use ndn_packet::{Data, Interest, Name};
use ndn_store::NameTrie;

/// A handler function registered for a name prefix.
///
/// Called when an Interest arrives at `ComputeFace` matching the prefix.
/// The result is returned as a Data packet and cached in the engine CS.
pub trait ComputeHandler: Send + Sync + 'static {
    fn compute(
        &self,
        interest: &Interest,
    ) -> impl std::future::Future<Output = Result<Data, ComputeError>> + Send;
}

#[derive(Debug)]
pub enum ComputeError {
    NotFound,
    ComputeFailed(String),
}

impl std::fmt::Display for ComputeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComputeError::NotFound       => write!(f, "no compute handler for this name"),
            ComputeError::ComputeFailed(e) => write!(f, "compute failed: {e}"),
        }
    }
}

impl std::error::Error for ComputeError {}

/// Registry mapping name prefixes to `ComputeHandler` implementations.
pub struct ComputeRegistry {
    handlers: NameTrie<Arc<dyn ErasedHandler>>,
}

trait ErasedHandler: Send + Sync + 'static {
    fn compute_erased<'a>(
        &'a self,
        interest: &'a Interest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Data, ComputeError>> + Send + 'a>>;
}

impl<H: ComputeHandler> ErasedHandler for H {
    fn compute_erased<'a>(
        &'a self,
        interest: &'a Interest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Data, ComputeError>> + Send + 'a>> {
        Box::pin(self.compute(interest))
    }
}

impl ComputeRegistry {
    pub fn new() -> Self {
        Self { handlers: NameTrie::new() }
    }

    pub fn register<H: ComputeHandler>(&self, prefix: &Name, handler: H) {
        self.handlers.insert(prefix, Arc::new(handler));
    }

    pub async fn dispatch(&self, interest: &Interest) -> Option<Result<Data, ComputeError>> {
        let handler = self.handlers.lpm(&interest.name)?;
        Some(handler.compute_erased(interest).await)
    }
}

impl Default for ComputeRegistry {
    fn default() -> Self { Self::new() }
}
