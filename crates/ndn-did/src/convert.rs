//! Conversion between NDN [`Certificate`]s and [`DidDocument`]s.
//!
//! An NDN certificate is structurally equivalent to a DID Document:
//! the namespace IS the identifier, and the certificate's public key
//! is the verification method. This module makes that equivalence explicit.

use std::sync::Arc;

use base64::Engine;
use ndn_packet::Name;
use ndn_security::Certificate;

use crate::{
    document::{DidDocument, VerificationMethod, VerificationRef},
    encoding::name_to_did,
};

/// TLV type for GenericNameComponent.
const GENERIC_NAME_COMPONENT: u64 = 8;
const KEY_COMPONENT: &[u8] = b"KEY";

/// Convert an NDN certificate to a W3C [`DidDocument`].
///
/// The certificate's `name` is expected to be a KEY name like
/// `/com/acme/alice/KEY/v=123/self`. The identity DID is derived from
/// the prefix before `/KEY/`.
pub fn cert_to_did_document(cert: &Certificate) -> DidDocument {
    let identity_name = strip_key_suffix(cert.name.as_ref());
    let did = name_to_did(&identity_name);
    let key_id = format!("{did}#key-0");

    let jwk = build_jwk(&cert.public_key);

    let vm = VerificationMethod {
        id: key_id.clone(),
        typ: "JsonWebKey2020".to_string(),
        controller: did.clone(),
        public_key_jwk: Some(jwk),
    };

    let mut doc = DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/jws-2020/v1".to_string(),
        ],
        id: did.clone(),
        verification_methods: vec![vm],
        authentication: vec![VerificationRef::Reference(key_id.clone())],
        assertion_method: vec![VerificationRef::Reference(key_id)],
        service: vec![],
        also_known_as: vec![],
    };

    // If the certificate has an issuer different from itself, record the
    // issuer as a `did:ndn` alsoKnownAs cross-reference.
    if let Some(issuer) = &cert.issuer {
        let issuer_identity = strip_key_suffix(issuer.as_ref());
        let issuer_did = name_to_did(&issuer_identity);
        if issuer_did != did {
            doc.also_known_as.push(issuer_did);
        }
    }

    doc
}

/// Attempt to reconstruct a trust anchor [`Certificate`] from a [`DidDocument`].
///
/// Returns `None` if the document does not contain a recognised Ed25519 key.
pub fn did_document_to_trust_anchor(
    doc: &DidDocument,
    name: Arc<Name>,
) -> Option<Certificate> {
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

// --- internals ---

/// Strip the `/KEY/<version>/<issuer>` suffix from a certificate name to get
/// the identity name.
///
/// `/com/acme/alice/KEY/v=123/self` → `/com/acme/alice`
pub(crate) fn strip_key_suffix(name: &Name) -> Name {
    let comps = name.components();
    // Find the last occurrence of a GenericNameComponent with value "KEY"
    let key_pos = comps.iter().rposition(|c| {
        c.typ == GENERIC_NAME_COMPONENT && c.value.as_ref() == KEY_COMPONENT
    });
    match key_pos {
        Some(pos) if pos > 0 => Name::from_components(comps[..pos].iter().cloned()),
        _ => name.clone(),
    }
}

fn build_jwk(public_key: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);
    let mut map = serde_json::Map::new();
    map.insert("kty".to_string(), "OKP".into());
    map.insert("crv".to_string(), "Ed25519".into());
    map.insert("x".to_string(), x.into());
    map
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
}
