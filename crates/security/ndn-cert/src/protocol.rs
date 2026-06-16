//! NDNCERT v0.3 wire protocol types. TLV codec lives in [`crate::tlv`].

use serde::{Deserialize, Serialize};

/// CA information returned by `/<ca>/CA/INFO`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaProfile {
    pub ca_prefix: String,
    pub ca_info: String,
    /// Base64url-encoded CA signing public key.
    pub public_key: String,
    pub challenges: Vec<String>,
    pub default_validity_secs: u64,
    pub max_validity_secs: u64,
}

/// Certificate signing request submitted to `/<ca-prefix>/CA/NEW`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRequest {
    /// Full KEY name, e.g. `/com/acme/alice/KEY/v=0/self`.
    pub name: String,
    /// Base64url-encoded Ed25519 public key.
    pub public_key: String,
    /// Unix milliseconds.
    pub not_before: u64,
    /// Unix milliseconds.
    pub not_after: u64,
}

/// Response to a NEW request — returns a request ID and available challenges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewResponse {
    /// Opaque request identifier (32 hex chars).
    pub request_id: String,
    pub challenges: Vec<String>,
}

/// Challenge request submitted to `/<ca-prefix>/CA/CHALLENGE/<request-id>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub request_id: String,
    pub challenge_type: String,
    pub parameters: serde_json::Map<String, serde_json::Value>,
}

/// Response to a CHALLENGE request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub status: ChallengeStatus,
    /// Base64url-encoded issued certificate (when `status == Approved`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_tries: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_time_secs: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeStatus {
    Approved,
    Processing,
    Denied,
}

/// Numeric error codes per NDNCERT v0.3 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum ErrorCode {
    BadInterestFormat = 1,
    BadParameterFormat = 2,
    BadSignature = 3,
    InvalidParameters = 4,
    NameNotAllowed = 5,
    BadValidityPeriod = 6,
    RunOutOfTries = 7,
    RunOutOfTime = 8,
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
            1 => Ok(Self::BadInterestFormat),
            2 => Ok(Self::BadParameterFormat),
            3 => Ok(Self::BadSignature),
            4 => Ok(Self::InvalidParameters),
            5 => Ok(Self::NameNotAllowed),
            6 => Ok(Self::BadValidityPeriod),
            7 => Ok(Self::RunOutOfTries),
            8 => Ok(Self::RunOutOfTime),
            9 => Ok(Self::NoAvailableNames),
            _ => Err(format!("unknown NDNCERT error code: {v}")),
        }
    }
}

/// Response to a PROBE request — non-committal name-policy check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Max name components the CA permits after its own prefix; `None` = unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_suffix_length: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub cert_name: String,
    /// Base64url-encoded Ed25519 signature of `cert_name` bytes (possession proof).
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResponse {
    pub status: RevokeStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevokeStatus {
    Revoked,
    NotFound,
    /// Possession proof failed.
    Unauthorized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_canonical_names_and_numbers() {
        let pairs: &[(ErrorCode, u8, &str)] = &[
            (ErrorCode::BadInterestFormat, 1, "BadInterestFormat"),
            (ErrorCode::BadParameterFormat, 2, "BadParameterFormat"),
            (ErrorCode::BadSignature, 3, "BadSignature"),
            (ErrorCode::InvalidParameters, 4, "InvalidParameters"),
            (ErrorCode::NameNotAllowed, 5, "NameNotAllowed"),
            (ErrorCode::BadValidityPeriod, 6, "BadValidityPeriod"),
            (ErrorCode::RunOutOfTries, 7, "RunOutOfTries"),
            (ErrorCode::RunOutOfTime, 8, "RunOutOfTime"),
            (ErrorCode::NoAvailableNames, 9, "NoAvailableNames"),
        ];
        for (variant, code, name) in pairs {
            assert_eq!(u8::from(*variant), *code, "code mismatch for {name}");
            assert_eq!(
                ErrorCode::try_from(*code).expect("try_from must accept canonical code"),
                *variant,
                "try_from({code}) must round-trip to {name}"
            );
            assert_eq!(format!("{variant:?}"), *name, "Debug name for code {code}");
        }
    }
}
