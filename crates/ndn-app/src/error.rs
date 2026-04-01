use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("no data received for interest: timeout")]
    Timeout,
    #[error("interest was nacked: {reason:?}")]
    Nacked { reason: ndn_packet::NackReason },
    #[error("engine error: {0}")]
    Engine(#[from] anyhow::Error),
}
