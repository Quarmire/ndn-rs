//! [`DidResolver`] trait and built-in resolver implementations.
//!
//! Per W3C DID Core §7.1, `resolve(did, options)` returns a
//! [`DidResolutionResult`] containing three components: the document, document
//! metadata, and resolution metadata. Every resolver in this module returns the
//! full result; [`UniversalResolver::resolve_document`] provides a convenience
//! shortcut when only the document is needed.

pub mod key;
pub mod ndn;

pub use key::KeyDidResolver;
pub use ndn::NdnDidResolver;

use std::{collections::HashMap, future::Future, pin::Pin};

use crate::did::{
    document::DidDocument,
    metadata::{DidResolutionError, DidResolutionResult},
};

/// High-level DID error for use in application code.
///
/// Resolvers return [`DidResolutionResult`] per the W3C spec; `DidError` is
/// produced by [`DidResolutionResult::into_document()`] for callers that only
/// need the document and want a simple `Result<DidDocument, DidError>`.
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

/// A resolver that can dereference a DID string to a [`DidResolutionResult`].
///
/// Per W3C DID Core §7.1, `resolve` must return the complete resolution result
/// including document metadata and resolution metadata — even on failure (the
/// error is encoded in `did_resolution_metadata.error`).
pub trait DidResolver: Send + Sync {
    /// The DID method this resolver handles (e.g., `"ndn"`, `"key"`).
    fn method(&self) -> &str;

    /// Resolve the DID, returning the full W3C resolution result.
    fn resolve<'a>(
        &'a self,
        did: &'a str,
    ) -> Pin<Box<dyn Future<Output = DidResolutionResult> + Send + 'a>>;
}

/// A resolver that dispatches to method-specific resolvers.
///
/// Ships with [`KeyDidResolver`] and [`NdnDidResolver`] pre-registered.
/// Additional resolvers can be added with [`UniversalResolver::with`].
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

    fn register(&mut self, resolver: impl DidResolver + 'static) {
        self.resolvers
            .insert(resolver.method().to_string(), Box::new(resolver));
    }

    /// Resolve a DID, returning the full W3C [`DidResolutionResult`].
    pub async fn resolve(&self, did: &str) -> DidResolutionResult {
        let method = match parse_method(did) {
            Some(m) => m,
            None => {
                return DidResolutionResult::err(
                    DidResolutionError::InvalidDid,
                    format!("cannot parse DID method from: {did}"),
                );
            }
        };

        match self.resolvers.get(method) {
            Some(resolver) => resolver.resolve(did).await,
            None => DidResolutionResult::err(
                DidResolutionError::MethodNotSupported,
                format!("no resolver registered for did:{method}"),
            ),
        }
    }

    /// Convenience: resolve and return just the [`DidDocument`].
    ///
    /// Maps W3C resolution errors to [`DidError`] for simpler call sites.
    pub async fn resolve_document(&self, did: &str) -> Result<DidDocument, DidError> {
        self.resolve(did).await.into_document()
    }
}

impl Default for UniversalResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the method name from a DID string (`did:<method>:...` → `<method>`).
pub(crate) fn parse_method(did: &str) -> Option<&str> {
    let rest = did.strip_prefix("did:")?;
    let colon = rest.find(':')?;
    Some(&rest[..colon])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_method_valid() {
        assert_eq!(parse_method("did:ndn:com:acme:alice"), Some("ndn"));
        assert_eq!(parse_method("did:key:z6Mk..."), Some("key"));
        assert_eq!(parse_method("did:web:example.com"), Some("web"));
    }

    #[test]
    fn parse_method_invalid() {
        assert_eq!(parse_method("not-a-did"), None);
        assert_eq!(parse_method("did:"), None);
        assert_eq!(parse_method("did:no-colon"), None);
    }

    #[tokio::test]
    async fn unsupported_method_returns_error_result() {
        let resolver = UniversalResolver::new();
        let result = resolver.resolve("did:web:example.com").await;
        assert!(result.did_resolution_metadata.error.is_some());
    }
}
