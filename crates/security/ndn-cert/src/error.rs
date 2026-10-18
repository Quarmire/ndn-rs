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
    /// An NDNCERT failure with an explicit ErrorCode that no other variant
    /// states: on the CA, a refusal answered with `code`; on the requester,
    /// a CA failure answer other than NameNotAllowed, RunOutOfTries or
    /// RunOutOfTime.
    #[error("{info} (NDNCERT ErrorCode {code})")]
    CaFailure { code: u8, info: String },
}

impl CertError {
    /// The NDNCERT v0.3 ErrorCode a CA answers when a NEW or CHALLENGE
    /// fails with this error.
    pub fn ndncert_error_code(&self) -> u8 {
        use crate::protocol::ErrorCode;
        let code = match self {
            Self::CaFailure { code, .. } => return *code,
            Self::PolicyDenied(_) => ErrorCode::NameNotAllowed,
            Self::ChallengeExpired(_) => ErrorCode::RunOutOfTime,
            Self::ChallengeFailed(_) => ErrorCode::RunOutOfTries,
            Self::InvalidRequest(_) | Self::Name(_) | Self::Serialization(_) => {
                ErrorCode::BadParameterFormat
            }
            // An unknown or expired session, as v0.3 answers it; and errors
            // of the CA itself, for which v0.3 has no code.
            Self::RequestNotFound(_)
            | Self::Security(_)
            | Self::ChallengePending(_)
            | Self::Transport(_)
            | Self::Refused { .. }
            | Self::Storage(_) => ErrorCode::InvalidParameters,
        };
        code.into()
    }

    /// The ErrorInfo text a CA answers with [`Self::ndncert_error_code`]:
    /// the reason as stated, and no detail of the CA's own failures (its
    /// storage paths, its transport), which it logs instead.
    pub fn ndncert_error_info(&self) -> String {
        match self {
            Self::PolicyDenied(reason)
            | Self::ChallengeFailed(reason)
            | Self::ChallengeExpired(reason)
            | Self::CaFailure { info: reason, .. } => reason.clone(),
            Self::RequestNotFound(_) => {
                "no such request: it expired or was never opened; send NEW again".to_string()
            }
            Self::InvalidRequest(_) | Self::Name(_) | Self::Serialization(_) => self.to_string(),
            Self::Security(_)
            | Self::ChallengePending(_)
            | Self::Transport(_)
            | Self::Refused { .. }
            | Self::Storage(_) => {
                "the CA could not process this request; ask again later".to_string()
            }
        }
    }

    /// The requester's reading of a CA failure answer (`code`, `info`):
    /// NameNotAllowed refuses the name ([`Self::PolicyDenied`]),
    /// RunOutOfTime asks to start over ([`Self::ChallengeExpired`]), the
    /// other request-format codes keep their code ([`Self::CaFailure`]),
    /// and anything else is a denial ([`Self::ChallengeFailed`]).
    pub fn from_ca_failure(code: Option<u8>, info: String) -> Self {
        use crate::protocol::ErrorCode;
        match code.map(ErrorCode::try_from) {
            Some(Ok(ErrorCode::NameNotAllowed)) => Self::PolicyDenied(info),
            Some(Ok(ErrorCode::RunOutOfTime)) => Self::ChallengeExpired(info),
            Some(Ok(
                ErrorCode::BadInterestFormat
                | ErrorCode::BadParameterFormat
                | ErrorCode::BadSignature
                | ErrorCode::InvalidParameters
                | ErrorCode::BadValidityPeriod
                | ErrorCode::NoAvailableNames,
            )) => Self::CaFailure {
                code: code.unwrap_or_default(),
                info,
            },
            _ => Self::ChallengeFailed(info),
        }
    }
}
