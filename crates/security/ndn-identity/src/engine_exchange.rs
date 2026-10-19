//! A [`CaExchange`] over an engine's in-process app consumer: the transport
//! the engine-bound onboarding calls ([`crate::adopt`], [`crate::invite`])
//! use, so their Interests are forwarded by the engine's FIB like any app's.

use bytes::Bytes;
use ndn_app::{AppError, Consumer, EngineAppExt, ForwarderEngine};
use ndn_cert::{CaExchange, CertError};
use ndn_packet::{Data, Interest, NackReason};
use tokio_util::sync::{CancellationToken, DropGuard};

/// The consumer face lives as long as this value (its face is torn down on
/// drop).
pub(crate) struct EngineExchange {
    consumer: Consumer,
    _face: DropGuard,
}

impl EngineExchange {
    pub(crate) fn new(engine: &ForwarderEngine) -> Self {
        let cancel = CancellationToken::new();
        Self {
            consumer: engine.app_consumer(cancel.clone()),
            _face: cancel.drop_guard(),
        }
    }
}

impl CaExchange for EngineExchange {
    /// Waits as long as the Interest lives (its InterestLifetime, at least
    /// the consumer's default timeout): a held Interest (a request's status)
    /// is answered late on purpose.
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let decoded = Interest::decode(interest.clone()).ok();
        let name = decoded
            .as_ref()
            .map(|i| i.name.to_string())
            .unwrap_or_default();
        let timeout = decoded
            .and_then(|i| i.lifetime())
            .map_or(ndn_app::DEFAULT_TIMEOUT, |l| {
                l.max(ndn_app::DEFAULT_TIMEOUT)
            });
        self.consumer
            .fetch_wire(interest, timeout)
            .await
            .map_err(|e| match e {
                AppError::Refused { reason } => CertError::Refused { name, reason },
                AppError::Nacked {
                    reason: Some(NackReason::NoRoute),
                } => CertError::Transport(format!("this forwarder has no route for {name}")),
                AppError::Nacked {
                    reason: Some(NackReason::Congestion),
                } => CertError::Transport(format!(
                    "{name} was Nacked (Congestion): the CA, or a forwarder on the way, takes no \
                     more such Interests now; ask again later"
                )),
                AppError::Timeout => CertError::Transport(format!(
                    "no answer to {name} within {:.1} s",
                    timeout.as_secs_f32()
                )),
                e => CertError::Transport(format!("{name}: {e}")),
            })
    }
}
