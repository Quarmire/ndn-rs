//! NDN DID method — encode NDN names as W3C Decentralized Identifiers and
//! resolve DID Documents over the NDN network or via bridged methods.
//!
//! # did:ndn encoding
//!
//! An NDN name maps to a `did:ndn` DID in two ways:
//!
//! - **Simple** (all GenericNameComponents, ASCII alphanumeric/hyphen/underscore/dot):
//!   colon-encoded following the `did:web` convention.
//!   `/com/acme/alice` → `did:ndn:com:acme:alice`
//!
//! - **Complex** (non-generic components or non-ASCII bytes): TLV base64url
//!   with a `v1:` prefix.
//!   → `did:ndn:v1:<base64url(TLV Name)>`
//!
//! # Resolving
//!
//! Use [`UniversalResolver`] to resolve any supported DID method:
//!
//! ```rust,no_run
//! use ndn_did::{UniversalResolver, KeyDidResolver};
//!
//! # async fn example() -> Result<(), ndn_did::DidError> {
//! let resolver = UniversalResolver::new();
//! let doc = resolver.resolve("did:key:z6Mkfriq3r5SBo8EdoHpBVQBjEPdmBLWGcWHMU3KCi4bXD3m").await?;
//! println!("{}", doc.id);
//! # Ok(())
//! # }
//! ```

pub mod convert;
pub mod document;
pub mod encoding;
pub mod resolver;

pub use convert::{cert_to_did_document, did_document_to_trust_anchor};
pub use document::{DidDocument, Service, ServiceEndpoint, VerificationMethod, VerificationRef};
pub use encoding::{did_to_name, name_to_did};
pub use resolver::{DidError, DidResolver, KeyDidResolver, NdnDidResolver, UniversalResolver};
