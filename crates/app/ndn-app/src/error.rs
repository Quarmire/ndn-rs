use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// No Data arrived before the Interest timeout.
    #[error("no data received for interest: timeout")]
    Timeout,
    /// The forwarder returned a Nack.
    #[error("interest was nacked: {reason:?}")]
    Nacked {
        reason: Option<ndn_packet::NackReason>,
    },
    /// An external [`ndn_ipc::ForwarderClient`] operation failed. Only the
    /// Unix-socket `connect()` paths produce this, so it's native-only.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("forwarder connection error: {0}")]
    Connection(#[from] ndn_ipc::ForwarderError),
    /// The in-process channel or external connection was closed.
    #[error("connection closed")]
    Closed,
    /// A packet could not be decoded or a validation step failed.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Fetched Data did **not** authenticate: it decoded fine but failed
    /// signature or trust validation against the supplied validator.
    ///
    /// Kept distinct from [`Protocol`](Self::Protocol) (malformed bytes) and
    /// the network errors so applications can branch on retry policy — a
    /// verification failure is a trust event (alarm / drop / re-anchor), not
    /// a transient condition to retry. The string is the underlying
    /// `VerifyError` rendered for logging.
    #[error("data failed verification: {0}")]
    Unverified(String),
}
