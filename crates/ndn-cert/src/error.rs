use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertError {
    #[error("request not found: {0}")]
    RequestNotFound(String),
    #[error("challenge failed: {0}")]
    ChallengeFailed(String),
    #[error("challenge pending: {0}")]
    ChallengePending(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("security error: {0}")]
    Security(#[from] ndn_security::TrustError),
    #[error("name error: {0}")]
    Name(String),
}
