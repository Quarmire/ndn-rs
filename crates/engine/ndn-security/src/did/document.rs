//! W3C DID Core document types.
//!
//! Implements the full DID Document data model per W3C DID Core §5.
//!
//! References:
//! - <https://www.w3.org/TR/did-core/#did-documents>
//! - <https://www.w3.org/TR/did-core/#verification-methods>
//! - <https://www.w3.org/TR/did-core/#verification-relationships>
//! - <https://www.w3.org/TR/did-core/#services>

use serde::{Deserialize, Serialize};

/// The `controller` property — either a single DID string or a set of DIDs.
///
/// Per W3C DID Core §5.1.2, the controller can be one or more DID strings.
/// When multiple DIDs are listed, each controller independently has the
/// authority to update or deactivate the subject DID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DidController {
    One(String),
    Many(Vec<String>),
}

impl DidController {
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        match self {
            Self::One(s) => std::slice::from_ref(s).iter().map(String::as_str),
            Self::Many(v) => v.iter().map(String::as_str),
        }
    }

    pub fn contains(&self, did: &str) -> bool {
        self.iter().any(|d| d == did)
    }
}

impl From<String> for DidController {
    fn from(s: String) -> Self {
        Self::One(s)
    }
}

impl From<Vec<String>> for DidController {
    fn from(v: Vec<String>) -> Self {
        if v.len() == 1 {
            Self::One(v.into_iter().next().unwrap())
        } else {
            Self::Many(v)
        }
    }
}

/// A verification method entry in a DID Document.
///
/// Per W3C DID Core §5.2, a verification method has an `id`, `type`,
/// `controller`, and one public key representation. The most common types are:
/// - `JsonWebKey2020` + `publicKeyJwk`
/// - `Ed25519VerificationKey2020` + `publicKeyMultibase`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// DID URL identifying this verification method (e.g. `did:ndn:…#key-0`).
    pub id: String,

    /// Verification method type.
    ///
    /// Common values:
    /// - `"JsonWebKey2020"` — public key as JWK
    /// - `"Ed25519VerificationKey2020"` — Ed25519 as multibase
    /// - `"X25519KeyAgreementKey2020"` — X25519 for ECDH key agreement
    #[serde(rename = "type")]
    pub typ: String,

    /// DID of the entity that controls this key.
    pub controller: String,

    /// Public key as a JSON Web Key (for `JsonWebKey2020` type).
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Map<String, serde_json::Value>>,

    /// Public key as a multibase-encoded string (for `Ed25519VerificationKey2020`
    /// and `X25519KeyAgreementKey2020` types). The leading character encodes the
    /// base: `z` = base58btc.
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

impl VerificationMethod {
    /// Build a `JsonWebKey2020` verification method from raw Ed25519 public key bytes.
    pub fn ed25519_jwk(
        id: impl Into<String>,
        controller: impl Into<String>,
        key_bytes: &[u8],
    ) -> Self {
        use base64::Engine;
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes);
        let mut jwk = serde_json::Map::new();
        jwk.insert("kty".to_string(), "OKP".into());
        jwk.insert("crv".to_string(), "Ed25519".into());
        jwk.insert("x".to_string(), x.into());
        Self {
            id: id.into(),
            typ: "JsonWebKey2020".to_string(),
            controller: controller.into(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        }
    }

    /// Build a `X25519KeyAgreementKey2020` verification method from raw X25519 key bytes.
    pub fn x25519_jwk(
        id: impl Into<String>,
        controller: impl Into<String>,
        key_bytes: &[u8],
    ) -> Self {
        use base64::Engine;
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes);
        let mut jwk = serde_json::Map::new();
        jwk.insert("kty".to_string(), "OKP".into());
        jwk.insert("crv".to_string(), "X25519".into());
        jwk.insert("x".to_string(), x.into());
        Self {
            id: id.into(),
            typ: "JsonWebKey2020".to_string(),
            controller: controller.into(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        }
    }

    /// Extract the raw Ed25519 public key bytes from a `JsonWebKey2020` VM.
    pub fn ed25519_key_bytes(&self) -> Option<[u8; 32]> {
        use base64::Engine;
        let jwk = self.public_key_jwk.as_ref()?;
        if jwk.get("crv").and_then(|v| v.as_str()) != Some("Ed25519") {
            return None;
        }
        let x = jwk.get("x")?.as_str()?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    }

    /// Extract the raw X25519 public key bytes from a `JsonWebKey2020` VM.
    pub fn x25519_key_bytes(&self) -> Option<[u8; 32]> {
        use base64::Engine;
        let jwk = self.public_key_jwk.as_ref()?;
        if jwk.get("crv").and_then(|v| v.as_str()) != Some("X25519") {
            return None;
        }
        let x = jwk.get("x")?.as_str()?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    }
}

/// A reference to a verification method — either embedded or a URI reference.
///
/// Per W3C DID Core §5.3, verification relationships contain either:
/// - A full embedded `VerificationMethod` object
/// - A string DID URL (reference to a VM defined in `verificationMethod`)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerificationRef {
    Reference(String),
    Embedded(VerificationMethod),
}

impl VerificationRef {
    /// Extract the ID of the referenced or embedded VM.
    pub fn id(&self) -> &str {
        match self {
            Self::Reference(s) => s.as_str(),
            Self::Embedded(vm) => vm.id.as_str(),
        }
    }
}

/// A service endpoint in a DID Document.
///
/// Per W3C DID Core §5.4, services allow discovery of related resources
/// (e.g., an NDN prefix where this DID's Data packets are published).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Service {
    /// DID URL identifying this service (e.g. `did:ndn:…#ndn-prefix`).
    pub id: String,

    /// Service type string (e.g. `"NdnNamespace"`, `"LinkedDomains"`).
    #[serde(rename = "type")]
    pub typ: String,

    /// The service endpoint location.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: ServiceEndpoint,
}

/// A service endpoint value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceEndpoint {
    /// A URI string (NDN name URI, HTTPS URL, DID URL, etc.).
    Uri(String),
    /// A structured JSON object for complex endpoint descriptions.
    Map(serde_json::Map<String, serde_json::Value>),
    /// An array of endpoint URIs or objects.
    Set(Vec<ServiceEndpoint>),
}

/// A W3C DID Document.
///
/// Implements the complete DID Document data model per W3C DID Core §5.
/// All optional fields serialize with `skip_serializing_if` to produce
/// compliant JSON-LD output.
///
/// <https://www.w3.org/TR/did-core/#did-documents>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD context array. Always includes `"https://www.w3.org/ns/did/v1"`.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID subject — this document's own DID.
    pub id: String,

    /// The entity (or entities) authorized to make changes to this DID Document.
    /// When absent the subject is its own controller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<DidController>,

    /// All verification methods defined by this DID Document.
    /// Verification relationships reference VMs by their `id`.
    #[serde(
        rename = "verificationMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verification_methods: Vec<VerificationMethod>,

    /// Keys authorized to authenticate as the DID subject (W3C DID Core §5.3.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<VerificationRef>,

    /// Keys authorized to issue verifiable credentials on behalf of the subject
    /// (W3C DID Core §5.3.2).
    #[serde(
        rename = "assertionMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub assertion_method: Vec<VerificationRef>,

    /// Keys used for key agreement / ECDH encryption (W3C DID Core §5.3.3).
    ///
    /// Typically X25519 keys (separate from the Ed25519 signing key).
    /// Critical for NDA's encrypted content tier.
    #[serde(
        rename = "keyAgreement",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub key_agreement: Vec<VerificationRef>,

    /// Keys authorized to invoke cryptographic capabilities (W3C DID Core §5.3.4).
    ///
    /// Used in NDA's access-control model — capability tokens reference VMs
    /// listed here.
    #[serde(
        rename = "capabilityInvocation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_invocation: Vec<VerificationRef>,

    /// Keys authorized to delegate capabilities to others (W3C DID Core §5.3.5).
    #[serde(
        rename = "capabilityDelegation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_delegation: Vec<VerificationRef>,

    /// Service endpoints (W3C DID Core §5.4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,

    /// Alternative identifiers for the same subject (URIs or DID strings).
    /// Used for zone succession: old zone DID lists new zone DID here.
    #[serde(rename = "alsoKnownAs", default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,
}

impl DidDocument {
    /// Build a minimal DID Document with a single Ed25519 verification method.
    pub fn new_simple(
        did: impl Into<String>,
        key_id: impl Into<String>,
        public_key: &[u8],
    ) -> Self {
        let did = did.into();
        let key_id = key_id.into();
        let vm = VerificationMethod::ed25519_jwk(&key_id, &did, public_key);
        Self {
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
        }
    }

    pub fn ed25519_public_key(&self) -> Option<[u8; 32]> {
        for vm in &self.verification_methods {
            if let Some(bytes) = vm.ed25519_key_bytes() {
                return Some(bytes);
            }
        }
        // Also check embedded VMs in authentication.
        for vr in &self.authentication {
            if let VerificationRef::Embedded(vm) = vr
                && let Some(bytes) = vm.ed25519_key_bytes()
            {
                return Some(bytes);
            }
        }
        None
    }

    pub fn x25519_key_agreement_key(&self) -> Option<[u8; 32]> {
        for vr in &self.key_agreement {
            match vr {
                VerificationRef::Embedded(vm) => {
                    if let Some(bytes) = vm.x25519_key_bytes() {
                        return Some(bytes);
                    }
                }
                VerificationRef::Reference(id) => {
                    // Look up in verificationMethods.
                    if let Some(vm) = self.find_vm(id)
                        && let Some(bytes) = vm.x25519_key_bytes()
                    {
                        return Some(bytes);
                    }
                }
            }
        }
        None
    }

    pub fn find_vm(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_methods
            .iter()
            .find(|vm| vm.id == id)
            .or_else(|| {
                // Also check fragment-only match.
                let fragment = id.split_once('#').map(|(_, f)| f).unwrap_or(id);
                self.verification_methods.iter().find(|vm| {
                    vm.id == id
                        || vm
                            .id
                            .split_once('#')
                            .map(|(_, f)| f == fragment)
                            .unwrap_or(false)
                })
            })
    }

    /// Whether this DID document lists the given DID as a controller.
    ///
    /// If `controller` is absent, the subject is its own controller.
    pub fn is_controlled_by(&self, did: &str) -> bool {
        match &self.controller {
            None => self.id == did,
            Some(ctrl) => ctrl.contains(did),
        }
    }
}
