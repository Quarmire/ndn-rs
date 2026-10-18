use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertError {
    #[error("request not found: {0}")]
    RequestNotFound(String),
    #[error("challenge failed: {0}")]
    ChallengeFailed(String),
    #[error("challenge pending: {0}")]
    ChallengePending(String),
    /// The challenge can no longer pass — it expired, or the CA no longer
    /// holds what it was about — so the requester must start over
    /// (NDNCERT error code `RunOutOfTime`).
    #[error("challenge expired: {0}")]
    ChallengeExpired(String),
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
    /// This node's forwarder refused the Data that answered the Interest for
    /// `name`, told at once rather than as a timeout. A final verdict unless
    /// [`Refusal::is_final`](ndn_packet::Refusal::is_final) says otherwise
    /// (`unverifiable`: refused for now, ask again later).
    #[error(
        "this node's forwarder refused the Data answering {name} ({reason}): {}",
        reason.next_step()
    )]
    Refused {
        name: String,
        reason: ndn_packet::Refusal,
    },
    /// The CA's durable state ([`CaStore`](crate::store::CaStore)) could not be
    /// read or written.
    #[error("CA storage error: {0}")]
    Storage(String),
}
