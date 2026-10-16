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
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let name = Interest::decode(interest.clone())
            .map(|i| i.name.to_string())
            .unwrap_or_default();
        self.consumer
            .fetch_wire(interest, ndn_app::DEFAULT_TIMEOUT)
            .await
            .map_err(|e| {
                CertError::Transport(match e {
                    AppError::Nacked {
                        reason: Some(NackReason::NoRoute),
                    } => format!("this forwarder has no route for {name}"),
                    AppError::Timeout => format!(
                        "no answer to {name} within {:.1} s",
                        ndn_app::DEFAULT_TIMEOUT.as_secs_f32()
                    ),
                    e => format!("{name}: {e}"),
                })
            })
    }
}
