use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// No Data arrived before the Interest timeout.
    #[error("no data received for interest: timeout")]
    Timeout,
    /// The forwarder returned a Nack.
    #[error("interest was nacked: {reason:?}")]
    Nacked { reason: ndn_packet::NackReason },
    /// An external [`ndn_ipc::ForwarderClient`] operation failed.
    #[error("forwarder connection error: {0}")]
    Connection(#[from] ndn_ipc::ForwarderError),
    /// The in-process channel or external connection was closed.
    #[error("connection closed")]
    Closed,
    /// A packet could not be decoded or a validation step failed.
    #[error("protocol error: {0}")]
    Protocol(String),
}
