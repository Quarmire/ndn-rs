//! `did:ndn` resolver — resolves via NDN Interest/Data exchange.
//!
//! Sends an Interest for `<identity-name>/KEY` and interprets the returned
//! NDN certificate as a DID Document. This is the native NDN resolution path.
//!
//! The resolver is initialized in stub mode by default (no-op, returns
//! `DidError::Resolution`). To enable live NDN resolution, supply a
//! [`FetchFn`] via [`NdnDidResolver::with_fetcher`].

use std::{future::Future, pin::Pin, sync::Arc};

use ndn_packet::Name;
use ndn_security::Certificate;

use crate::{
    convert::cert_to_did_document,
    document::DidDocument,
    encoding::did_to_name,
    resolver::{DidError, DidResolver},
};

/// Async function that fetches an NDN Data packet by name, returning the
/// decoded certificate if found.
pub type NdnFetchFn =
    Arc<dyn Fn(Name) -> Pin<Box<dyn Future<Output = Option<Certificate>> + Send>> + Send + Sync>;

/// Resolves `did:ndn` DIDs by sending NDN Interests.
///
/// By default (no fetcher configured), resolution always fails with
/// [`DidError::Resolution`]. Use [`NdnDidResolver::with_fetcher`] to provide
/// a live NDN fetch function.
#[derive(Default, Clone)]
pub struct NdnDidResolver {
    fetcher: Option<NdnFetchFn>,
}

impl NdnDidResolver {
    /// Attach a live NDN fetch function.
    ///
    /// The function receives the identity name and should fetch the certificate
    /// at `<name>/KEY` (latest version). It is called with the *identity* name,
    /// not the full KEY name — the resolver appends `/KEY` internally.
    pub fn with_fetcher(mut self, f: NdnFetchFn) -> Self {
        self.fetcher = Some(f);
        self
    }
}

impl DidResolver for NdnDidResolver {
    fn method(&self) -> &str {
        "ndn"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<DidDocument, DidError>> + Send + 'a>> {
        let fetcher = self.fetcher.clone();
        let did = did.to_string();
        Box::pin(async move {
            let name = did_to_name(&did)?;
            let key_name = name.append("KEY");

            let fetch = fetcher
                .ok_or_else(|| DidError::Resolution("no NDN fetcher configured".to_string()))?;

            let cert = fetch(key_name)
                .await
                .ok_or_else(|| DidError::NotFound(did.clone()))?;

            Ok(cert_to_did_document(&cert))
        })
    }
}
