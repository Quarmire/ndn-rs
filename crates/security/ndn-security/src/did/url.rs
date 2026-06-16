//! DID URL parsing and dereferencing.
//!
//! A DID URL is a DID plus optional path, query, and/or fragment components,
//! per W3C DID Core §3.2:
//!
//! ```text
//! did-url     = did path-abempty [ "?" query ] [ "#" fragment ]
//! path-abempty = *( "/" segment )
//! ```
//!
//! Examples:
//! - `did:ndn:BwkI...#key-0` — fragment reference to a verification method
//! - `did:ndn:BwMg...#key-agreement-1` — zone DID key agreement VM
//! - `did:ndn:BwkI.../service?type=ndn#endpoint` — service lookup
//!
//! (The method-specific identifier is base64url — no colons.)
//!
//! # Dereferencing
//!
//! [`deref_did_url`] takes a parsed DID URL and a resolved [`DidDocument`]
//! and returns the specific resource the URL identifies — a verification
//! method, a service, or the full document (when no fragment).

use super::{
    document::{DidDocument, Service, VerificationMethod},
    resolver::DidError,
};

/// A parsed DID URL (DID + optional path, query, fragment).
///
/// Per W3C DID Core §3.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidUrl {
    /// The DID part (`did:<method>:<method-specific-id>`).
    pub did: String,
    /// Path segments after the method-specific identifier (may be empty).
    pub path: Option<String>,
    /// Query string (without the leading `?`).
    pub query: Option<String>,
    /// Fragment (without the leading `#`). Used to reference VMs and services.
    pub fragment: Option<String>,
}

impl DidUrl {
    /// Parse a DID URL string.
    ///
    /// # Errors
    ///
    /// Returns `DidError::InvalidDid` if `url` is not a valid DID URL.
    pub fn parse(url: &str) -> Result<Self, DidError> {
        if !url.starts_with("did:") {
            return Err(DidError::InvalidDid(format!("not a DID URL: {url}")));
        }

        // Split off fragment first (fragment can contain '#' in theory but in
        // practice we split on the first '#').
        let (before_frag, fragment) = match url.find('#') {
            Some(pos) => (&url[..pos], Some(url[pos + 1..].to_string())),
            None => (url, None),
        };

        // Split query string.
        let (before_query, query) = match before_frag.find('?') {
            Some(pos) => (
                &before_frag[..pos],
                Some(before_frag[pos + 1..].to_string()),
            ),
            None => (before_frag, None),
        };

        // `did:` + method + `:` + method-specific-id [path]
        // The method-specific-id ends at the first `/` that is NOT part of
        // the method-specific-id itself. Per DID Core, `did:ndn:com:acme:alice`
        // has no path; `did:ndn:com:acme:alice/some/path` has path `/some/path`.
        //
        // Strategy: find the 3rd `:` (after `did:method:`), then look for `/`.
        let colon2 = before_query
            .find(':')
            .and_then(|i| before_query[i + 1..].find(':').map(|j| i + 1 + j));

        let (did, path) = match colon2 {
            None => {
                return Err(DidError::InvalidDid(format!(
                    "DID URL missing method-specific-id: {url}"
                )));
            }
            Some(method_colon) => {
                // method_colon is the position of the second ':' in the string
                let rest = &before_query[method_colon + 1..];
                match rest.find('/') {
                    None => (before_query.to_string(), None),
                    Some(slash) => {
                        let split_pos = method_colon + 1 + slash;
                        (
                            before_query[..split_pos].to_string(),
                            Some(before_query[split_pos..].to_string()),
                        )
                    }
                }
            }
        };

        Ok(Self {
            did,
            path,
            query,
            fragment,
        })
    }

    pub fn is_bare_did(&self) -> bool {
        self.path.is_none() && self.query.is_none() && self.fragment.is_none()
    }
}

impl std::fmt::Display for DidUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.did)?;
        if let Some(ref path) = self.path {
            f.write_str(path)?;
        }
        if let Some(ref query) = self.query {
            write!(f, "?{query}")?;
        }
        if let Some(ref fragment) = self.fragment {
            write!(f, "#{fragment}")?;
        }
        Ok(())
    }
}

/// The resource identified by a dereferenced DID URL.
///
/// Per W3C DID Core §7.2, a DID URL deferences to one of these.
#[derive(Debug, Clone)]
pub enum DereferencedResource<'a> {
    /// The full DID Document (when the URL has no fragment).
    Document(&'a DidDocument),
    /// A specific verification method (fragment matched a VM `id`).
    VerificationMethod(&'a VerificationMethod),
    /// A specific service (fragment matched a service `id`).
    Service(&'a Service),
}

/// Dereference a DID URL against an already-resolved DID Document.
///
/// This is the "secondary" dereference step from W3C DID Core §7.2 —
/// the document has already been resolved; this function extracts the
/// specific resource identified by the URL's fragment.
///
/// # Rules
///
/// - No fragment → returns the full document.
/// - Fragment matches a `verificationMethod[].id` → returns that VM.
/// - Fragment matches a `service[].id` → returns that service.
/// - Fragment matches nothing → returns `None`.
///
/// Fragment comparison strips any leading `#` and is exact-string.
/// Per DID Core, fragment comparison is case-sensitive.
///
/// # Example
///
/// ```rust,no_run
/// # use ndn_security::did::{DidUrl, deref_did_url};
/// # use ndn_security::did::document::DidDocument;
/// # fn example(doc: &DidDocument) {
/// let url = DidUrl::parse("did:ndn:com:acme:alice#key-0").unwrap();
/// match deref_did_url(&url, doc) {
///     Some(ndn_security::did::url::DereferencedResource::VerificationMethod(vm)) => {
///         println!("Found key: {}", vm.id);
///     }
///     _ => {}
/// }
/// # }
/// ```
pub fn deref_did_url<'a>(url: &DidUrl, doc: &'a DidDocument) -> Option<DereferencedResource<'a>> {
    let fragment = url.fragment.as_deref()?;

    // Try verification methods first: match by full `id` or by `#fragment`.
    // The VM `id` is typically `<did>#<fragment>`, so we match both ways.
    for vm in &doc.verification_methods {
        if vm.id == fragment
            || vm
                .id
                .split_once('#')
                .map(|(_, f)| f == fragment)
                .unwrap_or(false)
            || vm.id == format!("{}#{fragment}", url.did)
        {
            return Some(DereferencedResource::VerificationMethod(vm));
        }
    }

    // Try services.
    for svc in &doc.service {
        if svc.id == fragment
            || svc
                .id
                .split_once('#')
                .map(|(_, f)| f == fragment)
                .unwrap_or(false)
            || svc.id == format!("{}#{fragment}", url.did)
        {
            return Some(DereferencedResource::Service(svc));
        }
    }

    None
}

/// Convenience: dereference without a fragment, returning the document.
///
/// If `url` has no fragment, returns a reference to the document itself.
/// If it has a fragment, delegates to [`deref_did_url`].
pub fn deref_did_url_or_document<'a>(
    url: &DidUrl,
    doc: &'a DidDocument,
) -> Option<DereferencedResource<'a>> {
    if url.fragment.is_none() {
        Some(DereferencedResource::Document(doc))
    } else {
        deref_did_url(url, doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_did() {
        let url = DidUrl::parse("did:ndn:com:acme:alice").unwrap();
        assert_eq!(url.did, "did:ndn:com:acme:alice");
        assert!(url.path.is_none());
        assert!(url.query.is_none());
        assert!(url.fragment.is_none());
        assert!(url.is_bare_did());
    }

    #[test]
    fn parse_did_with_fragment() {
        let url = DidUrl::parse("did:ndn:com:acme:alice#key-0").unwrap();
        assert_eq!(url.did, "did:ndn:com:acme:alice");
        assert_eq!(url.fragment.as_deref(), Some("key-0"));
    }

    #[test]
    fn parse_did_with_path() {
        let url = DidUrl::parse("did:ndn:com:acme:alice/some/path").unwrap();
        assert_eq!(url.did, "did:ndn:com:acme:alice");
        assert_eq!(url.path.as_deref(), Some("/some/path"));
    }

    #[test]
    fn parse_did_with_query_and_fragment() {
        let url = DidUrl::parse("did:ndn:com:acme:alice?service=files#key-0").unwrap();
        assert_eq!(url.did, "did:ndn:com:acme:alice");
        assert_eq!(url.query.as_deref(), Some("service=files"));
        assert_eq!(url.fragment.as_deref(), Some("key-0"));
    }

    #[test]
    fn parse_zone_did_with_fragment() {
        // Current binary form: base64url with no colons.
        let url = DidUrl::parse("did:ndn:BwMgabc123abc123abc#key-agreement-1").unwrap();
        assert_eq!(url.did, "did:ndn:BwMgabc123abc123abc");
        assert_eq!(url.fragment.as_deref(), Some("key-agreement-1"));
    }

    #[test]
    fn roundtrip_display() {
        let original = "did:ndn:com:acme:alice#key-0";
        let url = DidUrl::parse(original).unwrap();
        assert_eq!(url.to_string(), original);
    }

    #[test]
    fn not_a_did_url_returns_error() {
        assert!(DidUrl::parse("https://example.com").is_err());
        assert!(DidUrl::parse("did:ndn").is_err());
    }
}
