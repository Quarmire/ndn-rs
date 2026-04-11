//! W3C DID Core document types.

use serde::{Deserialize, Serialize};

/// A W3C DID Document.
///
/// <https://www.w3.org/TR/did-core/#did-documents>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(
        rename = "verificationMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verification_methods: Vec<VerificationMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<VerificationRef>,
    #[serde(
        rename = "assertionMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub assertion_method: Vec<VerificationRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,
    #[serde(
        rename = "alsoKnownAs",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub also_known_as: Vec<String>,
}

impl DidDocument {
    /// Return the first Ed25519 public key bytes, if present.
    pub fn ed25519_public_key(&self) -> Option<[u8; 32]> {
        use base64::Engine;
        for vm in &self.verification_methods {
            if vm.typ == "JsonWebKey2020"
                && let Some(jwk) = &vm.public_key_jwk
                && jwk.get("crv").and_then(|v| v.as_str()) == Some("Ed25519")
                && let Some(x) = jwk.get("x").and_then(|v| v.as_str())
                && let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x)
                && bytes.len() == 32
            {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Some(arr);
            }
        }
        None
    }
}

/// A verification method entry in a DID Document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub typ: String,
    pub controller: String,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Map<String, serde_json::Value>>,
}

/// A reference to a verification method — either an inline embedding or a URI reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerificationRef {
    Reference(String),
    Embedded(VerificationMethod),
}

/// A service endpoint in a DID Document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub typ: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: ServiceEndpoint,
}

/// A service endpoint value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceEndpoint {
    Uri(String),
    Map(serde_json::Map<String, serde_json::Value>),
}
