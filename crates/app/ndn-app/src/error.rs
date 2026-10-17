use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// No Data arrived before the Interest timeout.
    #[error("no data received for interest: timeout")]
    Timeout,
    /// The forwarder returned a Nack (other than a refusal).
    #[error("interest was nacked: {reason:?}")]
    Nacked {
        reason: Option<ndn_packet::NackReason>,
    },
    /// This host's forwarder refused the Data that answered the Interest
    /// (revoked key, untrusted chain, schema refusal, bad signature, …): a
    /// final verdict, told at once instead of a timeout. Asking again gets
    /// the same answer; like [`Unverified`](Self::Unverified) it is a trust
    /// event, not a transient condition. Only a local face carries it.
    #[error("the forwarder refused the Data: {reason}")]
    Refused { reason: ndn_packet::Refusal },
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
    /// The operation needs a capability this handle doesn't have — e.g. a
    /// [`Node`](crate::Node) built from a single pre-made connection can't open
    /// the *dedicated* connection that sync (`publish`/`subscribe`) and the query
    /// responder require. Use [`Node::connect`](crate::Node::connect) (which can
    /// re-dial) or build the pattern type directly from `Node::connection`.
    #[error("unsupported on this handle: {0}")]
    Unsupported(String),
}

impl AppError {
    /// The error a Nack with `reason` is: [`Refused`](Self::Refused) for a
    /// refusal, [`Nacked`](Self::Nacked) otherwise.
    pub fn from_nack(reason: Option<ndn_packet::NackReason>) -> Self {
        match reason.and_then(|r| r.refusal()) {
            Some(reason) => AppError::Refused { reason },
            None => AppError::Nacked { reason },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::{NackReason, Refusal};

    /// A refusal Nack is `Refused` (a verdict, not retried); every other
    /// reason, and none, stays `Nacked`.
    #[test]
    fn from_nack_separates_refusals_from_other_nacks() {
        for r in Refusal::ALL {
            assert!(matches!(
                AppError::from_nack(Some(NackReason::Refused(r))),
                AppError::Refused { reason } if reason == r
            ));
        }
        for reason in [None, Some(NackReason::NoRoute), Some(NackReason::Other(999))] {
            assert!(matches!(
                AppError::from_nack(reason),
                AppError::Nacked { reason: got } if got == reason
            ));
        }
    }
}
