//! NDNCERT wire protocol types.
//!
//! All messages are JSON-serialized and carried in NDN packet fields:
//! - `CertRequest` / `ChallengeRequest` in ApplicationParameters
//! - `CaProfile` / `NewResponse` / `ChallengeResponse` in Content
//!
//! # NDNCERT 0.3 TLV type assignments
//!
//! These constants are reserved for the Phase 1C TLV wire-format migration:
//! ```text
//! ca-prefix         0x81   ca-info           0x83   parameter-key     0x85
//! parameter-value   0x87   ca-certificate    0x89   max-validity      0x8B
//! probe-response    0x8D   max-suffix-length 0x8F   ecdh-pub          0x91
//! cert-request      0x93   salt              0x95   request-id        0x97
//! challenge         0x99   status            0x9B   iv                0x9D
//! encrypted-payload 0x9F   selected-challenge 0xA1  challenge-status  0xA3
//! remaining-tries   0xA5   remaining-time    0xA7   issued-cert-name  0xA9
//! error-code        0xAB   error-info        0xAD   auth-tag          0xAF
//! ```

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
    /// Numeric error code per NDNCERT 0.3 (present when `status == Denied`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCode>,
    /// Status message for in-progress challenges (present when `status == Processing`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// Remaining challenge attempts (present when `status == Processing`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_tries: Option<u8>,
    /// Seconds remaining before this challenge expires (present when `status == Processing`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_time_secs: Option<u32>,
}

/// Challenge/request status per NDNCERT 0.3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeStatus {
    /// Certificate has been issued successfully.
    Approved,
    /// Challenge is in progress; client must submit another CHALLENGE request.
    Processing,
    /// Challenge failed or request was rejected.
    Denied,
}

/// Numeric error codes per NDNCERT 0.3 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum ErrorCode {
    BadInterest = 1,
    BadApplicationParameters = 2,
    InvalidSignature = 3,
    InvalidParameters = 4,
    NameNotAllowed = 5,
    BadValidityPeriod = 6,
    OutOfTries = 7,
    OutOfTime = 8,
    NoAvailableNames = 9,
}

impl From<ErrorCode> for u8 {
    fn from(e: ErrorCode) -> u8 {
        e as u8
    }
}

impl TryFrom<u8> for ErrorCode {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::BadInterest),
            2 => Ok(Self::BadApplicationParameters),
            3 => Ok(Self::InvalidSignature),
            4 => Ok(Self::InvalidParameters),
            5 => Ok(Self::NameNotAllowed),
            6 => Ok(Self::BadValidityPeriod),
            7 => Ok(Self::OutOfTries),
            8 => Ok(Self::OutOfTime),
            9 => Ok(Self::NoAvailableNames),
            _ => Err(format!("unknown NDNCERT error code: {v}")),
        }
    }
}

/// Response to a PROBE request (`/<ca-prefix>/CA/PROBE`).
///
/// Allows a client to check whether the CA will serve a given name before
/// committing to a full enrollment. Does not create any state on the CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResponse {
    /// Whether the CA's namespace policy permits issuing for the requested name.
    pub allowed: bool,
    /// Reason for denial (present when `allowed == false`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Maximum number of name components the CA permits after its own prefix.
    /// `None` means no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_suffix_length: Option<u8>,
}

/// Request body for `/<ca-prefix>/CA/REVOKE`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    /// Name of the certificate to revoke.
    pub cert_name: String,
    /// Base64url-encoded Ed25519 signature of `cert_name` bytes, proving possession.
    pub signature: String,
}

/// Response to a REVOKE request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResponse {
    pub status: RevokeStatus,
}

/// Revocation outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevokeStatus {
    /// Certificate was revoked successfully.
    Revoked,
    /// Certificate not found in CA records.
    NotFound,
    /// Possession proof failed — requester does not own this certificate.
    Unauthorized,
}
