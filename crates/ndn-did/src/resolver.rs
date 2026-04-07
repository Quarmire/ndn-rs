//! [`DidResolver`] trait and built-in resolver implementations.

pub mod key;
pub mod ndn;

pub use key::KeyDidResolver;
pub use ndn::NdnDidResolver;

use std::{collections::HashMap, future::Future, pin::Pin};

use crate::document::DidDocument;

/// Error type for DID resolution.
#[derive(Debug, thiserror::Error)]
pub enum DidError {
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    #[error("unsupported DID method: {0}")]
    UnsupportedMethod(String),
    #[error("DID document not found: {0}")]
    NotFound(String),
    #[error("resolution failed: {0}")]
    Resolution(String),
    #[error("invalid DID document: {0}")]
    InvalidDocument(String),
}

/// A resolver that can dereference a DID string to a [`DidDocument`].
pub trait DidResolver: Send + Sync {
    /// The DID method this resolver handles (e.g., `"ndn"`, `"key"`).
    fn method(&self) -> &str;

    /// Resolve the DID, returning its document.
    fn resolve<'a>(
        &'a self,
        did: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<DidDocument, DidError>> + Send + 'a>>;
}

/// A resolver that dispatches to method-specific resolvers.
///
/// Ships with [`KeyDidResolver`] and [`NdnDidResolver`] pre-registered.
/// Additional resolvers (e.g., `WebDidResolver` behind the `did-web` feature)
/// can be added with [`UniversalResolver::with`].
pub struct UniversalResolver {
    resolvers: HashMap<String, Box<dyn DidResolver>>,
}

impl UniversalResolver {
    /// Create a resolver with [`KeyDidResolver`] and [`NdnDidResolver`] registered.
    pub fn new() -> Self {
        let mut r = Self {
            resolvers: HashMap::new(),
        };
        r.register(KeyDidResolver);
        r.register(NdnDidResolver::default());
        r
    }

    /// Register an additional resolver. Replaces any existing resolver for the same method.
    pub fn with(mut self, resolver: impl DidResolver + 'static) -> Self {
        self.register(resolver);
        self
    }

    /// Register an additional resolver by mutable reference.
    pub fn register(&mut self, resolver: impl DidResolver + 'static) {
        self.resolvers
            .insert(resolver.method().to_string(), Box::new(resolver));
    }

    /// Resolve any supported DID.
    pub async fn resolve(&self, did: &str) -> Result<DidDocument, DidError> {
        let method = parse_method(did)?;
        let resolver = self
            .resolvers
            .get(method)
            .ok_or_else(|| DidError::UnsupportedMethod(method.to_string()))?;
        resolver.resolve(did).await
    }
}

impl Default for UniversalResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the method name from a DID string (`did:<method>:...`).
pub(crate) fn parse_method(did: &str) -> Result<&str, DidError> {
    let without_did = did
        .strip_prefix("did:")
        .ok_or_else(|| DidError::InvalidDid(did.to_string()))?;
    let colon = without_did
        .find(':')
        .ok_or_else(|| DidError::InvalidDid(did.to_string()))?;
    Ok(&without_did[..colon])
}
