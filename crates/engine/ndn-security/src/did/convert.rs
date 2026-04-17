//! Conversion between NDN [`Certificate`]s and [`DidDocument`]s.
//!
//! An NDN certificate is structurally equivalent to a DID Document:
//! the namespace IS the identifier, and the certificate's public key
//! is the verification method. This module makes that equivalence explicit
//! and provides a builder for zone-based DID Documents.

use std::sync::Arc;

use ndn_packet::Name;

use crate::Certificate;
use crate::did::{
    document::{DidDocument, VerificationMethod, VerificationRef},
    encoding::name_to_did,
};

const GENERIC_NAME_COMPONENT: u64 = 8;
const KEY_COMPONENT: &[u8] = b"KEY";

/// Convert an NDN certificate to a W3C [`DidDocument`].
///
/// The certificate's `name` is expected to be a KEY name like
/// `/com/acme/alice/KEY/v=123/self`. The identity DID is derived from
/// the prefix before `/KEY/`.
///
/// # Key agreement key
///
/// Pass `x25519_key` to include a `keyAgreement` entry. This is an X25519
/// public key separate from the Ed25519 signing key — critical for NDA's
/// encrypted content tier. The X25519 key is typically derived from the
/// Ed25519 seed (e.g., via RFC 7748 conversion) or generated independently.
pub fn cert_to_did_document(cert: &Certificate, x25519_key: Option<&[u8]>) -> DidDocument {
    let identity_name = strip_key_suffix(cert.name.as_ref());
    let did = name_to_did(&identity_name);
    let key_id = format!("{did}#key-0");

    let vm = VerificationMethod::ed25519_jwk(&key_id, &did, &cert.public_key);

    let mut doc = DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/jws-2020/v1".to_string(),
        ],
        id: did.clone(),
        controller: None,
        verification_methods: vec![vm],
        authentication: vec![VerificationRef::Reference(key_id.clone())],
        assertion_method: vec![VerificationRef::Reference(key_id.clone())],
        key_agreement: vec![],
        capability_invocation: vec![VerificationRef::Reference(key_id.clone())],
        capability_delegation: vec![VerificationRef::Reference(key_id)],
        service: vec![],
        also_known_as: vec![],
    };

    if let Some(x25519_bytes) = x25519_key {
        let ka_id = format!("{did}#key-agreement-0");
        let ka_vm = VerificationMethod::x25519_jwk(&ka_id, &did, x25519_bytes);
        doc.verification_methods.push(ka_vm);
        doc.key_agreement.push(VerificationRef::Reference(ka_id));
    }

    if let Some(issuer) = &cert.issuer {
        let issuer_identity = strip_key_suffix(issuer.as_ref());
        let issuer_did = name_to_did(&issuer_identity);
        if issuer_did != did {
            doc.also_known_as.push(issuer_did);
        }
    }

    doc
}

/// Build a W3C DID Document for a self-certifying [`ZoneKey`].
///
/// The resulting document:
/// - Has `id` = `did:ndn:<base64url(zone-root-name-TLV)>` (binary-only encoding)
/// - Lists the Ed25519 signing key as `authentication`, `assertionMethod`,
///   `capabilityInvocation`, and `capabilityDelegation`
/// - Optionally lists an X25519 key as `keyAgreement`
/// - Has no `controller` (the zone controls itself)
///
/// Publish this document as a signed Data packet at the zone root name so
/// that `NdnDidResolver` can fetch and verify it.
pub fn build_zone_did_document(
    zone_key: &crate::zone::ZoneKey,
    x25519_key: Option<&[u8]>,
    services: Vec<crate::did::document::Service>,
) -> DidDocument {
    let did = zone_key.zone_root_did();
    let key_id = format!("{did}#key-0");

    let vm = VerificationMethod::ed25519_jwk(&key_id, &did, zone_key.public_key_bytes());

    let mut doc = DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/jws-2020/v1".to_string(),
        ],
        id: did.clone(),
        controller: None,
        verification_methods: vec![vm],
        authentication: vec![VerificationRef::Reference(key_id.clone())],
        assertion_method: vec![VerificationRef::Reference(key_id.clone())],
        key_agreement: vec![],
        capability_invocation: vec![VerificationRef::Reference(key_id.clone())],
        capability_delegation: vec![VerificationRef::Reference(key_id)],
        service: services,
        also_known_as: vec![],
    };

    if let Some(x25519_bytes) = x25519_key {
        let ka_id = format!("{did}#key-agreement-0");
        let ka_vm = VerificationMethod::x25519_jwk(&ka_id, &did, x25519_bytes);
        doc.verification_methods.push(ka_vm);
        doc.key_agreement.push(VerificationRef::Reference(ka_id));
    }

    doc
}

/// Build a deactivated zone DID Document expressing zone succession.
///
/// When a zone owner rotates to a new zone, they publish this document at the
/// old zone root name. The `successor_did` is listed in `alsoKnownAs`.
/// Resolvers that check [`DidResolutionResult::is_deactivated`] will follow
/// the succession chain.
pub fn build_zone_succession_document(
    old_zone_key: &crate::zone::ZoneKey,
    successor_did: impl Into<String>,
) -> DidDocument {
    let did = old_zone_key.zone_root_did();
    let key_id = format!("{did}#key-0");
    let vm = VerificationMethod::ed25519_jwk(&key_id, &did, old_zone_key.public_key_bytes());

    DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: did.clone(),
        controller: None,
        verification_methods: vec![vm],
        authentication: vec![VerificationRef::Reference(key_id.clone())],
        assertion_method: vec![],
        key_agreement: vec![],
        capability_invocation: vec![],
        capability_delegation: vec![],
        service: vec![],
        also_known_as: vec![successor_did.into()],
    }
}

/// Attempt to reconstruct a trust anchor [`Certificate`] from a [`DidDocument`].
///
/// Returns `None` if the document does not contain a recognised Ed25519 key.
pub fn did_document_to_trust_anchor(doc: &DidDocument, name: Arc<Name>) -> Option<Certificate> {
    let key_bytes = doc.ed25519_public_key()?;
    Some(Certificate {
        name,
        public_key: bytes::Bytes::copy_from_slice(&key_bytes),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
    })
}

pub(crate) fn strip_key_suffix(name: &Name) -> Name {
    let comps = name.components();
    let key_pos = comps
        .iter()
        .rposition(|c| c.typ == GENERIC_NAME_COMPONENT && c.value.as_ref() == KEY_COMPONENT);
    match key_pos {
        Some(pos) if pos > 0 => Name::from_components(comps[..pos].iter().cloned()),
        _ => name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_key_suffix_basic() {
        let name: Name = "/com/acme/alice/KEY/v=123/self".parse().unwrap();
        let stripped = strip_key_suffix(&name);
        let expected: Name = "/com/acme/alice".parse().unwrap();
        assert_eq!(stripped, expected);
    }

    #[test]
    fn strip_key_suffix_no_key() {
        let name: Name = "/com/acme/alice".parse().unwrap();
        let stripped = strip_key_suffix(&name);
        assert_eq!(stripped, name);
    }

    #[test]
    fn cert_to_did_doc_has_required_relationships() {
        use bytes::Bytes;
        let name: Name = "/com/acme/alice/KEY/v=1/self".parse().unwrap();
        let cert = Certificate {
            name: Arc::new(name),
            public_key: Bytes::from(vec![0u8; 32]),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
        };
        let doc = cert_to_did_document(&cert, None);
        let identity_name: Name = "/com/acme/alice".parse().unwrap();
        let expected_did = crate::did::encoding::name_to_did(&identity_name);
        assert_eq!(doc.id, expected_did);
        assert!(!doc.authentication.is_empty());
        assert!(!doc.assertion_method.is_empty());
        assert!(!doc.capability_invocation.is_empty());
        assert!(!doc.capability_delegation.is_empty());
        assert!(doc.key_agreement.is_empty()); // no X25519 supplied
    }

    #[test]
    fn cert_to_did_doc_with_x25519() {
        use bytes::Bytes;
        let name: Name = "/com/acme/alice/KEY/v=1/self".parse().unwrap();
        let cert = Certificate {
            name: Arc::new(name),
            public_key: Bytes::from(vec![0u8; 32]),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
        };
        let x25519 = [0xABu8; 32];
        let doc = cert_to_did_document(&cert, Some(&x25519));
        assert!(!doc.key_agreement.is_empty());
        assert_eq!(doc.verification_methods.len(), 2);
        let ka_vm = &doc.verification_methods[1];
        let crv = ka_vm
            .public_key_jwk
            .as_ref()
            .and_then(|jwk| jwk.get("crv"))
            .and_then(|v| v.as_str());
        assert_eq!(crv, Some("X25519"));
    }
}
