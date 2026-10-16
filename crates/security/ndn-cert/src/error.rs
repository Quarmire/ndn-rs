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
    /// The [`CaExchange`](crate::client::CaExchange) transport failed to
    /// deliver an Interest or return its Data.
    #[error("transport error: {0}")]
    Transport(String),
    /// The CA's durable state ([`CaStore`](crate::store::CaStore)) could not be
    /// read or written.
    #[error("CA storage error: {0}")]
    Storage(String),
}
