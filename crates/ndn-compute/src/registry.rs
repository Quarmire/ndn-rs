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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;
    use ndn_tlv::TlvWriter;

    fn minimal_data() -> Data {
        // DATA > NAME > NAMECOMP("test")
        let nc   = { let mut w = TlvWriter::new(); w.write_tlv(0x08, b"test"); w.finish() };
        let name = { let mut w = TlvWriter::new(); w.write_tlv(0x07, &nc);    w.finish() };
        let pkt  = { let mut w = TlvWriter::new(); w.write_tlv(0x06, &name); w.finish() };
        Data::decode(pkt).unwrap()
    }

    struct EchoHandler;

    impl ComputeHandler for EchoHandler {
        async fn compute(&self, _interest: &Interest) -> Result<Data, ComputeError> {
            Ok(minimal_data())
        }
    }

    struct FailHandler;

    impl ComputeHandler for FailHandler {
        async fn compute(&self, _interest: &Interest) -> Result<Data, ComputeError> {
            Err(ComputeError::ComputeFailed("intentional failure".into()))
        }
    }

    fn make_interest(comp: &'static str) -> Interest {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(comp.as_bytes()))
        ]);
        Interest::new(name)
    }

    #[tokio::test]
    async fn dispatch_to_registered_handler() {
        let registry = ComputeRegistry::new();
        let prefix = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"compute"))
        ]);
        registry.register(&prefix, EchoHandler);
        let interest = make_interest("compute");
        let result = registry.dispatch(&interest).await;
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn dispatch_no_match_returns_none() {
        let registry = ComputeRegistry::new();
        let interest = make_interest("unknown");
        assert!(registry.dispatch(&interest).await.is_none());
    }

    #[tokio::test]
    async fn dispatch_handler_error_propagates() {
        let registry = ComputeRegistry::new();
        let prefix = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"fail"))
        ]);
        registry.register(&prefix, FailHandler);
        let interest = make_interest("fail");
        let result = registry.dispatch(&interest).await.unwrap();
        assert!(matches!(result, Err(ComputeError::ComputeFailed(_))));
    }

    #[test]
    fn compute_error_display() {
        assert!(!ComputeError::NotFound.to_string().is_empty());
        assert!(!ComputeError::ComputeFailed("x".into()).to_string().is_empty());
    }
}
