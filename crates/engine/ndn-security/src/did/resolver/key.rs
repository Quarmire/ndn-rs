//! `did:key` resolver — fully local, no network required.
//!
//! Only Ed25519 keys (`z6Mk...` — multicodec 0xed01 + base58btc multibase) are
//! supported. Per the `did:key` specification, the DID Document is derived
//! directly from the public key bytes without any network fetch.
//!
//! Reference: <https://w3c-ccg.github.io/did-method-key/>

use std::{future::Future, pin::Pin};

use crate::did::{
    document::{DidDocument, VerificationMethod, VerificationRef},
    metadata::{DidResolutionError, DidResolutionResult},
    resolver::DidResolver,
};

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Resolves `did:key` DIDs locally without any network access.
pub struct KeyDidResolver;

impl DidResolver for KeyDidResolver {
    fn method(&self) -> &str {
        "key"
    }

    fn resolve<'a>(
        &'a self,
        did: &'a str,
    ) -> Pin<Box<dyn Future<Output = DidResolutionResult> + Send + 'a>> {
        let did = did.to_string();
        Box::pin(async move {
            match resolve_key_did(&did) {
                Ok(doc) => DidResolutionResult::ok(doc),
                Err(e) => DidResolutionResult::err(
                    match &e {
                        s if s.contains("invalid") || s.contains("unsupported") => {
                            DidResolutionError::InvalidDid
                        }
                        _ => DidResolutionError::InternalError,
                    },
                    e,
                ),
            }
        })
    }
}

fn resolve_key_did(did: &str) -> Result<DidDocument, String> {
    let key_str = did
        .strip_prefix("did:key:")
        .ok_or_else(|| format!("not a did:key DID: {did}"))?;

    let public_key = decode_multibase_key(key_str)?;
    let key_id = format!("{did}#{key_str}");

    let vm = VerificationMethod::ed25519_jwk(&key_id, did, &public_key);

    Ok(DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/jws-2020/v1".to_string(),
        ],
        id: did.to_string(),
        controller: None,
        verification_methods: vec![vm],
        authentication: vec![VerificationRef::Reference(key_id.clone())],
        assertion_method: vec![VerificationRef::Reference(key_id.clone())],
        key_agreement: vec![],
        capability_invocation: vec![VerificationRef::Reference(key_id.clone())],
        capability_delegation: vec![VerificationRef::Reference(key_id)],
        service: vec![],
        also_known_as: vec![],
    })
}

fn decode_multibase_key(encoded: &str) -> Result<Vec<u8>, String> {
    let b58 = encoded
        .strip_prefix('z')
        .ok_or_else(|| format!("unsupported multibase prefix in {encoded}"))?;

    let bytes = bs58_decode(b58).map_err(|_| format!("invalid base58 in {encoded}"))?;

    if bytes.len() < 2 {
        return Err("key too short".to_string());
    }

    if bytes[0] == ED25519_MULTICODEC[0] && bytes[1] == ED25519_MULTICODEC[1] {
        Ok(bytes[2..].to_vec())
    } else {
        Err(format!(
            "unsupported key type (multicodec prefix {:02x}{:02x})",
            bytes[0], bytes[1]
        ))
    }
}

fn bs58_decode(s: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result: Vec<u8> = vec![0];
    for c in s.bytes() {
        let digit = ALPHABET.iter().position(|&b| b == c).ok_or(())? as u64;
        let mut carry = digit;
        for byte in result.iter_mut().rev() {
            carry += (*byte as u64) * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            result.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    let leading_zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut out = vec![0u8; leading_zeros];
    let trimmed: Vec<u8> = result.into_iter().skip_while(|&b| b == 0).collect();
    out.extend(trimmed);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_known_key_did() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let resolver = KeyDidResolver;
        let result = resolver.resolve(did).await;
        assert!(result.did_resolution_metadata.error.is_none(), "{result:?}");
        let doc = result.did_document.unwrap();
        assert_eq!(doc.id, did);
        assert!(!doc.verification_methods.is_empty());
        assert!(!doc.authentication.is_empty());
        assert!(!doc.capability_invocation.is_empty());
    }

    #[tokio::test]
    async fn invalid_did_returns_error_result() {
        let resolver = KeyDidResolver;
        let result = resolver.resolve("did:key:invalid").await;
        assert!(result.did_resolution_metadata.error.is_some());
        assert!(result.did_document.is_none());
    }
}
