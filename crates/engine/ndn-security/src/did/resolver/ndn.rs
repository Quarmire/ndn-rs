//! `did:ndn` resolver — resolves via NDN Interest/Data exchange.
//!
//! Two resolution strategies, chosen by decoding the binary DID back to the
//! underlying NDN name and inspecting the first component type:
//!
//! **CA-anchored** (name components are all GenericNameComponents):
//! Fetches the certificate at `<identity-name>/KEY` and converts it to a
//! DID Document via [`cert_to_did_document`].
//!
//! **Zone** (first component is BLAKE3_DIGEST type):
//! The zone root name IS the DID. The resolver fetches a published DID
//! Document Data packet at `<zone-root-name>`. Zone owners must publish
//! their DID Document as a signed Data packet for resolvers to find it.
//! The resolver verifies that `blake3(ed25519_pubkey)` in the fetched
//! document matches the zone root name component.
//!
//! **Stub mode** (no fetcher configured): returns `DidError::Resolution`.
//! Wire up a live fetcher via [`NdnDidResolver::with_fetcher`] /
//! [`NdnDidResolver::with_did_doc_fetcher`].

use std::{future::Future, pin::Pin, sync::Arc};

use ndn_packet::Name;

use crate::{
    Certificate,
    did::{
        convert::cert_to_did_document,
        document::DidDocument,
        encoding::did_to_name,
        metadata::{DidResolutionError, DidResolutionResult},
        resolver::DidResolver,
    },
};

/// Fetch an NDN certificate by name (used for CA-anchored DIDs).
pub type NdnFetchFn =
    Arc<dyn Fn(Name) -> Pin<Box<dyn Future<Output = Option<Certificate>> + Send>> + Send + Sync>;

/// Fetch an NDN DID Document Data packet by name (used for zone DIDs).
///
/// The returned bytes should be the JSON-LD `application/did+ld+json` content
/// of a signed NDN Data packet at the zone root name.
pub type NdnDidDocFetchFn =
    Arc<dyn Fn(Name) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>> + Send + Sync>;

/// Resolves `did:ndn` DIDs by sending NDN Interests.
///
/// Configure via the builder methods:
/// - [`with_fetcher`](Self::with_fetcher) — for CA-anchored DIDs (cert fetch)
/// - [`with_did_doc_fetcher`](Self::with_did_doc_fetcher) — for zone DIDs
///   (raw DID Document fetch)
///
/// Both can be configured on the same instance.
#[derive(Default, Clone)]
pub struct NdnDidResolver {
    cert_fetcher: Option<NdnFetchFn>,
    did_doc_fetcher: Option<NdnDidDocFetchFn>,
}

impl NdnDidResolver {
    /// Attach a certificate fetch function for CA-anchored `did:ndn` DIDs.
    ///
    /// The function receives the identity name (e.g. `/com/acme/alice`) and
    /// should return the certificate at `<name>/KEY` if found.
    pub fn with_fetcher(mut self, f: NdnFetchFn) -> Self {
        self.cert_fetcher = Some(f);
        self
    }

    /// Attach a DID Document fetch function for zone `did:ndn:v1:…` DIDs.
    ///
    /// The function receives the zone root name and should return the raw
    /// JSON-LD DID Document bytes from the Data packet at that name.
    pub fn with_did_doc_fetcher(mut self, f: NdnDidDocFetchFn) -> Self {
        self.did_doc_fetcher = Some(f);
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
        let did_doc_fetcher = self.did_doc_fetcher.clone();
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

            if name.is_zone_root() {
                resolve_zone_did(&did, name, did_doc_fetcher).await
            } else {
                resolve_ca_did(&did, name, cert_fetcher).await
            }
        })
    }
}

async fn resolve_ca_did(
    did: &str,
    identity_name: Name,
    fetcher: Option<NdnFetchFn>,
) -> DidResolutionResult {
    let fetch = match fetcher {
        Some(f) => f,
        None => {
            return DidResolutionResult::err(
                DidResolutionError::InternalError,
                "no NDN certificate fetcher configured for CA-anchored DID resolution",
            );
        }
    };

    let key_name = identity_name.append("KEY");
    match fetch(key_name).await {
        Some(cert) => DidResolutionResult::ok(cert_to_did_document(&cert, None)),
        None => DidResolutionResult::err(
            DidResolutionError::NotFound,
            format!("certificate not found for DID: {did}"),
        ),
    }
}

async fn resolve_zone_did(
    did: &str,
    zone_root: Name,
    fetcher: Option<NdnDidDocFetchFn>,
) -> DidResolutionResult {
    let fetch = match fetcher {
        Some(f) => f,
        None => {
            return DidResolutionResult::err(
                DidResolutionError::InternalError,
                "no NDN DID document fetcher configured for zone DID resolution",
            );
        }
    };

    let raw = match fetch(zone_root.clone()).await {
        Some(b) => b,
        None => {
            return DidResolutionResult::err(
                DidResolutionError::NotFound,
                format!("DID document not found for zone DID: {did}"),
            );
        }
    };

    let doc: DidDocument = match serde_json::from_slice(&raw) {
        Ok(d) => d,
        Err(e) => {
            return DidResolutionResult::err(
                DidResolutionError::InvalidDidDocument,
                format!("failed to parse DID document: {e}"),
            );
        }
    };

    // Verify the DID document id matches the requested DID.
    if doc.id != did {
        return DidResolutionResult::err(
            DidResolutionError::InvalidDidDocument,
            format!(
                "DID document id '{}' does not match requested DID '{did}'",
                doc.id
            ),
        );
    }

    // Verify that blake3(pubkey) matches the zone root name component.
    if let Some(pubkey_bytes) = doc.ed25519_public_key() {
        let expected_zone = crate::zone::zone_root_from_pubkey(&pubkey_bytes);
        if expected_zone != zone_root {
            return DidResolutionResult::err(
                DidResolutionError::InvalidDidDocument,
                "zone root name does not match blake3(pubkey) from DID document".to_string(),
            );
        }
    }

    DidResolutionResult::ok(doc)
}
