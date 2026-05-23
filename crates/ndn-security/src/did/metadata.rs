//! W3C DID Core resolution metadata types.
//!
//! Per the W3C DID Core specification §7.1, resolving a DID returns three
//! components: the DID Document itself, document metadata, and resolution
//! metadata. This module defines the latter two and the wrapper type that
//! combines all three.
//!
//! References:
//! - <https://www.w3.org/TR/did-core/#did-resolution>
//! - <https://www.w3.org/TR/did-core/#did-document-metadata>
//! - <https://www.w3.org/TR/did-core/#did-resolution-metadata>

use serde::{Deserialize, Serialize};

use super::document::DidDocument;

/// Input options for DID resolution, per W3C DID Core §7.1.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DidResolutionOptions {
    /// Desired media type for the DID Document representation.
    /// Default: `application/did+ld+json`.
    #[serde(rename = "accept", skip_serializing_if = "Option::is_none")]
    pub accept: Option<String>,
}

/// Metadata about the DID Document itself (not the DID or resolution process).
///
/// Per W3C DID Core §7.1.3, this is returned alongside every resolved document.
/// Values here reflect the *current state* of the document as of resolution.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentMetadata {
    /// When the DID was first created (RFC 3339 / ISO 8601 datetime string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// When the DID Document was last updated (RFC 3339 datetime).
    /// Absent if the document has never been updated since creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,

    /// `true` if the DID has been deactivated (revoked / succeeded).
    /// Resolvers MUST include this field when the DID is deactivated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,

    /// When the next version of the document is expected (RFC 3339 datetime).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,

    /// Version identifier of this specific document revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,

    /// DIDs that are equivalent to this DID per the resolution method.
    /// Used to express zone succession: the old DID's metadata lists the
    /// new zone's DID here.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub equivalent_id: Vec<String>,

    /// The canonical DID for this subject if different from the requested DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_id: Option<String>,
}

impl DidDocumentMetadata {
    /// Construct metadata indicating a deactivated DID.
    ///
    /// Used for zone succession: the old zone is deactivated; `successor_did`
    /// is listed in `equivalent_id` so resolvers can follow the chain.
    pub fn deactivated_with_successor(successor_did: impl Into<String>) -> Self {
        Self {
            deactivated: Some(true),
            equivalent_id: vec![successor_did.into()],
            ..Default::default()
        }
    }
}

/// Standardized DID resolution error codes per W3C DID Core §7.1.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DidResolutionError {
    /// The DID string is not a valid DID.
    InvalidDid,
    /// The DID was not found by the resolver.
    NotFound,
    /// The requested representation (content type) is not supported.
    RepresentationNotSupported,
    /// The resolver does not support the requested DID method.
    MethodNotSupported,
    /// The resolved DID Document is not valid.
    InvalidDidDocument,
    /// An unexpected error occurred during resolution.
    InternalError,
}

impl std::fmt::Display for DidResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::InvalidDid => "invalidDid",
            Self::NotFound => "notFound",
            Self::RepresentationNotSupported => "representationNotSupported",
            Self::MethodNotSupported => "methodNotSupported",
            Self::InvalidDidDocument => "invalidDidDocument",
            Self::InternalError => "internalError",
        };
        f.write_str(s)
    }
}

/// Metadata about the DID resolution process itself.
///
/// Per W3C DID Core §7.1.2, this is returned alongside every resolution
/// attempt — including failed ones (where `error` is set).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidResolutionMetadata {
    /// Media type of the returned representation (`application/did+ld+json`).
    /// MUST be present when resolution succeeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Error code if resolution failed. `None` when resolution succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DidResolutionError>,

    /// Human-readable error message (non-normative, for debugging).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl DidResolutionMetadata {
    /// Build metadata for a successful resolution.
    pub fn success() -> Self {
        Self {
            content_type: Some("application/did+ld+json".to_string()),
            error: None,
            error_message: None,
        }
    }

    /// Build metadata for a failed resolution.
    pub fn error(code: DidResolutionError, message: impl Into<String>) -> Self {
        Self {
            content_type: None,
            error: Some(code),
            error_message: Some(message.into()),
        }
    }
}

/// The complete output of a DID resolution operation.
///
/// Per W3C DID Core §7.1, `resolve(did, options)` returns a tuple of:
/// 1. `didResolutionMetadata` — how the resolution went
/// 2. `didDocument` — the resolved document (absent on error)
/// 3. `didDocumentMetadata` — metadata about the document's current state
///
/// Use [`DidResolutionResult::into_document()`] to extract the document and
/// convert resolution errors into a single `Result`.
#[derive(Debug, Clone)]
pub struct DidResolutionResult {
    pub did_document: Option<DidDocument>,
    pub did_document_metadata: DidDocumentMetadata,
    pub did_resolution_metadata: DidResolutionMetadata,
}

impl DidResolutionResult {
    pub fn ok(document: DidDocument) -> Self {
        Self {
            did_document: Some(document),
            did_document_metadata: DidDocumentMetadata::default(),
            did_resolution_metadata: DidResolutionMetadata::success(),
        }
    }

    pub fn ok_with_metadata(document: DidDocument, doc_meta: DidDocumentMetadata) -> Self {
        Self {
            did_document: Some(document),
            did_document_metadata: doc_meta,
            did_resolution_metadata: DidResolutionMetadata::success(),
        }
    }

    pub fn err(code: DidResolutionError, message: impl Into<String>) -> Self {
        Self {
            did_document: None,
            did_document_metadata: DidDocumentMetadata::default(),
            did_resolution_metadata: DidResolutionMetadata::error(code, message),
        }
    }

    /// Extract the DID Document, mapping resolution errors to a [`DidError`].
    pub fn into_document(self) -> Result<DidDocument, super::resolver::DidError> {
        if let Some(doc) = self.did_document {
            return Ok(doc);
        }
        match self.did_resolution_metadata.error {
            Some(DidResolutionError::NotFound) => Err(super::resolver::DidError::NotFound(
                self.did_resolution_metadata
                    .error_message
                    .unwrap_or_default(),
            )),
            Some(DidResolutionError::InvalidDid) => Err(super::resolver::DidError::InvalidDid(
                self.did_resolution_metadata
                    .error_message
                    .unwrap_or_default(),
            )),
            Some(DidResolutionError::MethodNotSupported) => {
                Err(super::resolver::DidError::UnsupportedMethod(
                    self.did_resolution_metadata
                        .error_message
                        .unwrap_or_default(),
                ))
            }
            _ => Err(super::resolver::DidError::Resolution(
                self.did_resolution_metadata
                    .error_message
                    .unwrap_or_else(|| "resolution failed".to_string()),
            )),
        }
    }

    pub fn is_deactivated(&self) -> bool {
        self.did_document_metadata.deactivated.unwrap_or(false)
    }
}
