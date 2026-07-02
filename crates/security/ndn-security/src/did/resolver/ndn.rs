//! `did:ndn` resolver — resolves via NDN Interest/Data exchange.
//!
//! Fetches the certificate at `<identity-name>/KEY` and converts it
//! to a DID Document via [`cert_to_did_document`].
//!
//! ## Wiring
//!
//! The resolver delegates the actual cert lookup to a shared
//! `CertFetcher`, the same machinery the [`Validator`] uses to
//! chase certificate chains. This buys two things the previous
//! `NdnFetchFn` parallel did not provide:
//!
//! - **In-flight de-duplication** — concurrent resolves for the
//!   same DID coalesce into one network Interest.
//! - **Cert-cache integration** — once a cert lands, every other
//!   consumer of the same `Arc<CertFetcher>` (Validator chain
//!   walks, future versioned-resolution lookups) sees it
//!   immediately.
//!
//! [`Validator`]: crate::validator::Validator
//!
//! Construct via [`NdnDidResolver::with_cert_fetcher`] or, more
//! commonly, [`UniversalResolver::with_cert_fetcher`]. A resolver
//! created via [`Default`] is in **stub mode**: it returns
//! `DidResolutionError::InternalError` for every `did:ndn:*` to
//! make the misconfiguration loud rather than silently degrading
//! `did:key`-only deployments.
//!
//! [`UniversalResolver::with_cert_fetcher`]:
//!     crate::did::UniversalResolver::with_cert_fetcher

use std::{future::Future, pin::Pin, sync::Arc};

use ndn_packet::Name;

use crate::{
    cert_fetcher::CertFetcher,
    did::{
        convert::cert_to_did_document,
        encoding::did_to_name,
        metadata::{DidResolutionError, DidResolutionResult},
        resolver::DidResolver,
    },
    error::TrustError,
};

/// Resolves `did:ndn` DIDs by sending NDN Interests through a
/// shared `CertFetcher`.
#[derive(Default, Clone)]
pub struct NdnDidResolver {
    cert_fetcher: Option<Arc<CertFetcher>>,
}

impl NdnDidResolver {
    /// Attach a `CertFetcher` for `did:ndn` resolution.
    ///
    /// The same `Arc<CertFetcher>` should be shared with the
    /// `Validator` so chain walks and DID resolutions de-duplicate
    /// against each other and warm the same cache.
    pub fn with_cert_fetcher(mut self, fetcher: Arc<CertFetcher>) -> Self {
        self.cert_fetcher = Some(fetcher);
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
    ) -> Pin<Box<dyn Future<Output = DidResolutionResult> + Send + 'a>> {
        let cert_fetcher = self.cert_fetcher.clone();
        let did = did.to_string();

        Box::pin(async move {
            let name = match did_to_name(&did) {
                Ok(n) => n,
                Err(e) => {
                    return DidResolutionResult::err(
                        DidResolutionError::InvalidDid,
                        format!("cannot decode did:ndn name: {e}"),
                    );
                }
            };

            resolve_ca_did(&did, name, cert_fetcher).await
        })
    }
}

async fn resolve_ca_did(
    did: &str,
    identity_name: Name,
    fetcher: Option<Arc<CertFetcher>>,
) -> DidResolutionResult {
    let Some(fetcher) = fetcher else {
        return DidResolutionResult::err(
            DidResolutionError::InternalError,
            "NdnDidResolver has no CertFetcher wired; use \
             UniversalResolver::with_cert_fetcher to attach one",
        );
    };

    let key_name = Arc::new(identity_name.append("KEY"));
    match fetcher.fetch(&key_name).await {
        Ok(cert) => DidResolutionResult::ok(cert_to_did_document(&cert, None)),
        Err(TrustError::CertNotFound { .. }) => DidResolutionResult::err(
            DidResolutionError::NotFound,
            format!("certificate not found for DID: {did}"),
        ),
        Err(e) => DidResolutionResult::err(
            DidResolutionError::InternalError,
            format!("cert fetch error for DID {did}: {e}"),
        ),
    }
}
