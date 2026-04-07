//! `did:key` resolver — fully local, no network required.
//!
//! `did:key` encodes a public key directly in the DID string using multibase +
//! multicodec encoding. Resolution is pure computation.
//!
//! Only Ed25519 keys (`z6Mk...`) are supported in this implementation.

use std::{future::Future, pin::Pin};

use base64::Engine;

use crate::{
    document::{DidDocument, VerificationMethod, VerificationRef},
    resolver::{DidError, DidResolver},
};

/// Multicodec prefix for Ed25519 public keys.
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
    ) -> Pin<Box<dyn Future<Output = Result<DidDocument, DidError>> + Send + 'a>> {
        let did = did.to_string();
        Box::pin(async move { resolve_key_did(&did) })
    }
}

fn resolve_key_did(did: &str) -> Result<DidDocument, DidError> {
    let key_str = did
        .strip_prefix("did:key:")
        .ok_or_else(|| DidError::InvalidDid(did.to_string()))?;

    let public_key = decode_multibase_key(key_str)?;
    let key_id = format!("{did}#{key_str}");

    let mut jwk = serde_json::Map::new();
    jwk.insert("kty".to_string(), "OKP".into());
    jwk.insert("crv".to_string(), "Ed25519".into());
    jwk.insert(
        "x".to_string(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&public_key)
            .into(),
    );

    let vm = VerificationMethod {
        id: key_id.clone(),
        typ: "JsonWebKey2020".to_string(),
        controller: did.to_string(),
        public_key_jwk: Some(jwk),
    };

    Ok(DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/jws-2020/v1".to_string(),
        ],
        id: did.to_string(),
        verification_methods: vec![vm],
        authentication: vec![VerificationRef::Reference(key_id.clone())],
        assertion_method: vec![VerificationRef::Reference(key_id)],
        service: vec![],
        also_known_as: vec![],
    })
}

/// Decode a multibase + multicodec encoded public key.
///
/// Currently only base58btc (`z` prefix) with Ed25519 multicodec is supported.
fn decode_multibase_key(encoded: &str) -> Result<Vec<u8>, DidError> {
    // Multibase prefix 'z' = base58btc
    let b58 = encoded
        .strip_prefix('z')
        .ok_or_else(|| DidError::InvalidDid(format!("unsupported multibase prefix in {encoded}")))?;

    let bytes = bs58_decode(b58)
        .map_err(|_| DidError::InvalidDid(format!("invalid base58 in {encoded}")))?;

    if bytes.len() < 2 {
        return Err(DidError::InvalidDid("key too short".to_string()));
    }

    if bytes[0] == ED25519_MULTICODEC[0] && bytes[1] == ED25519_MULTICODEC[1] {
        Ok(bytes[2..].to_vec())
    } else {
        Err(DidError::InvalidDid(format!(
            "unsupported key type (multicodec prefix {:02x}{:02x})",
            bytes[0], bytes[1]
        )))
    }
}

/// Minimal base58 decoder (Bitcoin alphabet).
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
    // Leading '1's map to leading zero bytes
    let leading_zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut out = vec![0u8; leading_zeros];
    // Remove the leading zero we inserted and append result
    let trimmed: Vec<u8> = result.into_iter().skip_while(|&b| b == 0).collect();
    out.extend(trimmed);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_known_key_did() {
        // A well-known did:key test vector (Ed25519)
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let resolver = KeyDidResolver;
        let doc = resolver.resolve(did).await;
        // Should resolve (key is valid base58btc Ed25519)
        assert!(doc.is_ok(), "should resolve: {doc:?}");
        let doc = doc.unwrap();
        assert_eq!(doc.id, did);
        assert!(!doc.verification_methods.is_empty());
    }
}
