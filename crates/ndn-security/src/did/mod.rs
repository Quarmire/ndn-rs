//! NDN DID method — encode NDN names as W3C Decentralized Identifiers and
//! resolve DID Documents over the NDN network or via bridged methods.
//!
//! # did:ndn encoding
//!
//! A `did:ndn` DID is the base64url (no padding) encoding of the complete NDN
//! Name TLV wire format, including the outer `07 <length>` bytes:
//!
//! ```text
//! did:ndn:<base64url(Name TLV)>
//! ```
//!
//! This single form handles all NDN names unambiguously — GenericNameComponents,
//! ImplicitSha256Digest, ParametersSha256Digest, versioned components, etc. —
//! without type-specific special cases. See [`encoding`] for backward-compat
//! parsing of older forms.
//!
//! # Resolution
//!
//! Use [`UniversalResolver`] to resolve any supported DID method:
//!
//! ```rust,no_run
//! use ndn_security::did::{UniversalResolver, KeyDidResolver};
//!
//! # async fn example() -> Result<(), ndn_security::did::DidError> {
//! let resolver = UniversalResolver::new();
//! let doc = resolver.resolve_document("did:key:z6Mkfriq3r5SBo8EdoHpBVQBjEPdmBLWGcWHMU3KCi4bXD3m").await?;
//! println!("{}", doc.id);
//! # Ok(())
//! # }
//! ```
//!
//! # DID URL dereferencing
//!
//! ```rust,no_run
//! use ndn_security::did::{DidUrl, deref_did_url};
//! use ndn_security::did::document::DidDocument;
//!
//! # fn example(doc: &DidDocument) {
//! let url = DidUrl::parse("did:ndn:com:acme:alice#key-0").unwrap();
//! if let Some(resource) = deref_did_url(&url, doc) {
//!     println!("found resource for fragment");
//! }
//! # }
//! ```

pub mod convert;
pub mod document;
pub mod encoding;
pub mod metadata;
pub mod resolver;
pub mod url;

pub use convert::{
    TRUSTED_APPROVERS_DESCRIPTION_KEY, cert_to_did_document, did_document_to_trust_anchor,
    encode_trusted_approvers_description, trusted_approvers_from_cert,
};
pub use document::{
    DidController, DidDocument, Service, ServiceEndpoint, TRUSTED_APPROVER_SERVICE_TYPE,
    VerificationMethod, VerificationRef,
};
pub use encoding::{did_to_name, name_to_did};
pub use metadata::{
    DidDocumentMetadata, DidResolutionError, DidResolutionMetadata, DidResolutionOptions,
    DidResolutionResult,
};
pub use resolver::{DidError, DidResolver, KeyDidResolver, NdnDidResolver, UniversalResolver};
pub use url::{DereferencedResource, DidUrl, deref_did_url, deref_did_url_or_document};
