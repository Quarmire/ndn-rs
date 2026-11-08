//! A [`CaExchange`] over an engine's in-process app consumer: the transport
//! the engine-bound onboarding calls ([`crate::adopt`], [`crate::invite`])
//! use, so their Interests are forwarded by the engine's FIB like any app's.

use bytes::Bytes;
use ndn_app::{AppError, Consumer, EngineAppExt, ForwarderEngine};
use ndn_cert::{CaExchange, CertError};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Interest, NackReason, Refusal};
use tokio_util::sync::{CancellationToken, DropGuard};

/// How many times [`EngineExchange::fetching`] asks for one signed packet
/// before it says nothing answered. A lossy path (20% of packets lost each
/// way, 5% altered in transit: the faulty network of the data-layer spec
/// §18.1) answers a single ask about three times in five; eight asks leave
/// well under one fetch in a thousand unanswered.
const FETCH_TRIES: u32 = 8;

/// The consumer face lives as long as this value (its face is torn down on
/// drop).
pub(crate) struct EngineExchange {
    consumer: Consumer,
    _face: DropGuard,
    /// How many times a plain fetch is asked ([`Self::fetching`]); 1 for an
    /// exchange that may carry commands.
    tries: u32,
}

impl EngineExchange {
    /// An exchange that asks each Interest once: a request to a CA is a
    /// command, never repeated behind its caller's back.
    pub(crate) fn new(engine: &ForwarderEngine) -> Self {
        let cancel = CancellationToken::new();
        Self {
            consumer: engine.app_consumer(cancel.clone()),
            _face: cancel.drop_guard(),
            tries: 1,
        }
    }

    /// An exchange for fetching signed packets by name (a trust context's
    /// versions and its metadata): a plain Interest — no parameters, no
    /// signature — that times out, or whose answer this engine refused as
    /// [`Refusal::BadSignature`] (a copy forged or altered on the way: it
    /// says nothing of the name), is asked again with a fresh nonce, up to
    /// [`FETCH_TRIES`] times. Asking again for a signed packet is
    /// idempotent; a copy that does not verify is never taken.
    pub(crate) fn fetching(engine: &ForwarderEngine) -> Self {
        Self {
            tries: FETCH_TRIES,
            ..Self::new(engine)
        }
    }
}

/// Whether `interest` may be asked again behind its caller's back: a plain
/// fetch by name, carrying no parameters and no signature.
fn plain(interest: &Interest) -> bool {
    interest.app_parameters().is_none() && interest.sig_info().is_none()
}

/// The plain `interest` asked again: the same Interest with a fresh nonce, so
/// no forwarder takes it for the one that looped.
fn asked_again(interest: &Interest) -> Bytes {
    let mut b = InterestBuilder::new((*interest.name).clone());
    let selectors = interest.selectors();
    if selectors.can_be_prefix {
        b = b.can_be_prefix();
    }
    if selectors.must_be_fresh {
        b = b.must_be_fresh();
    }
    if let Some(l) = interest.lifetime() {
        b = b.lifetime(l);
    }
    if let Some(h) = interest.hop_limit() {
        b = b.hop_limit(h);
    }
    if let Some(hints) = interest.forwarding_hint() {
        b = b.forwarding_hint(hints.iter().map(|h| (**h).clone()).collect());
    }
    b.build()
}

impl CaExchange for EngineExchange {
    /// Waits as long as the Interest lives (its InterestLifetime, at least
    /// the consumer's default timeout): a held Interest (a request's status)
    /// is answered late on purpose. A [`fetching`](EngineExchange::fetching)
    /// exchange asks a plain Interest again while nothing answers or what
    /// answers is a copy that does not verify.
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let decoded = Interest::decode(interest.clone()).ok();
        let name = decoded
            .as_ref()
            .map(|i| i.name.to_string())
            .unwrap_or_default();
        let timeout = decoded
            .as_ref()
            .and_then(|i| i.lifetime())
            .map_or(ndn_app::DEFAULT_TIMEOUT, |l| {
                l.max(ndn_app::DEFAULT_TIMEOUT)
            });
        // Only a plain Interest is asked again, each time with a new nonce.
        let again = decoded.as_ref().filter(|i| plain(i));
        let mut wire = interest;
        let mut tried = 1;
        loop {
            match self.consumer.fetch_wire(wire.clone(), timeout).await {
                Ok(data) => return Ok(data),
                Err(
                    AppError::Timeout
                    | AppError::Refused {
                        reason: Refusal::BadSignature,
                    },
                ) if tried < self.tries
                    && let Some(fresh) = again.map(asked_again) =>
                {
                    tried += 1;
                    wire = fresh;
                }
                Err(e) => {
                    return Err(match e {
                        AppError::Refused { reason } => CertError::Refused { name, reason },
                        AppError::Nacked {
                            reason: Some(NackReason::NoRoute),
                        } => {
                            CertError::Transport(format!("this forwarder has no route for {name}"))
                        }
                        AppError::Nacked {
                            reason: Some(NackReason::Congestion),
                        } => CertError::Transport(format!(
                            "{name} was Nacked (Congestion): the CA, or a forwarder on the way, \
                             takes no more such Interests now; ask again later"
                        )),
                        AppError::Timeout => CertError::Transport(format!(
                            "no answer to {name} within {:.1} s{}",
                            timeout.as_secs_f32(),
                            if tried > 1 {
                                format!(", asked {tried} times")
                            } else {
                                String::new()
                            }
                        )),
                        e => CertError::Transport(format!("{name}: {e}")),
                    });
                }
            }
        }
    }
}
