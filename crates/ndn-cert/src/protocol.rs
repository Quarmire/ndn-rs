//! NDNCERT wire protocol types.
//!
//! All messages are JSON-serialized and carried in NDN packet fields:
//! - `CertRequest` / `ChallengeRequest` in ApplicationParameters
//! - `CaProfile` / `NewResponse` / `ChallengeResponse` in Content

use serde::{Deserialize, Serialize};

/// CA information returned by `/<ca>/CA/INFO`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaProfile {
    /// The CA's NDN prefix as a URI string (e.g. `/com/acme/fleet/CA`).
    pub ca_prefix: String,
    /// Human-readable description of this CA.
    pub ca_info: String,
    /// Base64url-encoded public key of the CA's signing key.
    pub public_key: String,
    /// Supported challenge types.
    pub challenges: Vec<String>,
    /// Default certificate validity in seconds.
    pub default_validity_secs: u64,
    /// Maximum certificate validity in seconds.
    pub max_validity_secs: u64,
}

/// Certificate signing request submitted to `/<ca-prefix>/CA/NEW`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRequest {
    /// Requested certificate name (full KEY name, e.g. `/com/acme/alice/KEY/v=0/self`).
    pub name: String,
    /// Base64url-encoded Ed25519 public key.
    pub public_key: String,
    /// Requested validity start (Unix ms).
    pub not_before: u64,
    /// Requested validity end (Unix ms).
    pub not_after: u64,
}

/// Response to a NEW request — returns a request ID and available challenges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewResponse {
    /// Opaque request identifier (32 hex chars).
    pub request_id: String,
    /// Challenge types the client may use.
    pub challenges: Vec<String>,
}

/// Challenge request submitted to `/<ca-prefix>/CA/CHALLENGE/<request-id>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// Must match the `request_id` from [`NewResponse`].
    pub request_id: String,
    /// Which challenge type the client is responding to.
    pub challenge_type: String,
    /// Challenge-specific parameters.
    pub parameters: serde_json::Map<String, serde_json::Value>,
}

/// Response to a CHALLENGE request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub status: ChallengeStatus,
    /// Base64url-encoded issued certificate bytes (present when `status == Approved`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// Human-readable error (present when `status == Denied`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeStatus {
    Approved,
    Denied,
}
